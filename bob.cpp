#include "common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

int main() {
    cout.setf(ios::unitbuf);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Bob socket creation failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BOB_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Bob bind failed\n";
        return 1;
    }

    listen(server_fd, 5);
    cout << "Bob listening on port " << BOB_PORT << "\n";

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;

        cout << "[Bob][Step 5] Accepted Alice connection\n";
        string ticket_msg = recv_string(client);
        cout << "[Bob][Step 5] Received ticket message = " << ticket_msg << "\n";
        auto ticket_parts = unpack_fields(ticket_msg);

        if (ticket_parts.size() != 2 || ticket_parts[0] != "TICKET") {
            cerr << "[Bob] Invalid ticket message\n";
            close(client);
            continue;
        }

        auto ticket_enc = hex_decode(ticket_parts[1]);
        auto ticket_plain = bytes_to_str(aes_decrypt(KB_KDC, ticket_enc));
        cout << "[Bob][Step 5] Decrypted ticket plaintext = " << ticket_plain << "\n";
        auto ticket_fields = unpack_fields(ticket_plain);

        if (ticket_fields.size() != 2) {
            cerr << "[Bob] Invalid decrypted ticket\n";
            close(client);
            continue;
        }

        auto ks = hex_decode(ticket_fields[0]);
        string ida = ticket_fields[1];

        // The ticket proves the KDC created Ks for Alice and Bob.
        cout << "[Bob][Step 5] Ticket decrypted successfully\n";
        cout << "[Bob][Step 5] Ks = " << hex_encode(ks) << "\n";
        cout << "[Bob][Step 5] IDA = " << ida << "\n";

        string data_msg = recv_string(client);
        cout << "[Bob][Step 6] Received data message = " << data_msg << "\n";
        auto data_parts = unpack_fields(data_msg);
        bool plaintext_mode = false;

        if (data_parts.size() != 2 || (data_parts[0] != "DATA" && data_parts[0] != "DATA_PLAIN")) {
            cerr << "[Bob] Invalid data message\n";
            close(client);
            continue;
        }

        string payload_plain;
        if (data_parts[0] == "DATA_PLAIN") {
            plaintext_mode = true;
            payload_plain = data_parts[1];
            cout << "[Bob][Step 6] Plaintext payload received directly\n";
        } else {
            auto enc_payload = hex_decode(data_parts[1]);
            cout << "[Bob][Step 6] Encrypted payload = " << data_parts[1] << "\n";
            payload_plain = bytes_to_str(aes_decrypt(ks, enc_payload));
            cout << "[Bob][Step 6] Decrypted payload = " << payload_plain << "\n";
        }
        auto payload_fields = unpack_fields(payload_plain);

        if (payload_fields.size() != 2) {
            cerr << "[Bob] Invalid payload structure\n";
            close(client);
            continue;
        }

        string M = payload_fields[0];
        string received_hash_hex = payload_fields[1];

        // Bob recomputes H(M) locally to check message integrity.
        auto calc_hash = sha256_bytes(M);
        string calc_hash_hex = hex_encode(calc_hash);

        if (plaintext_mode) {
            cout << "[Bob][Step 6] Plaintext baseline mode enabled\n";
        }
        cout << "[Bob][Step 7] Received M = " << M << "\n";
        cout << "[Bob][Step 7] Received H(M) = " << received_hash_hex << "\n";
        cout << "[Bob][Step 7] Calculated H(M) = " << calc_hash_hex << "\n";

        if (received_hash_hex == calc_hash_hex) {
            cout << "[Bob][Step 7] Verification Successful\n";
        } else {
            cout << "[Bob][Step 7] Verification Failed\n";
        }

        close(client);
    }

    close(server_fd);
    return 0;
}
