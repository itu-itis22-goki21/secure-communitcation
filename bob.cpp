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

        string ticket_msg = recv_string(client);
        auto ticket_parts = unpack_fields(ticket_msg);

        if (ticket_parts.size() != 2 || ticket_parts[0] != "TICKET") {
            cerr << "[Bob] Invalid ticket message\n";
            close(client);
            continue;
        }

        auto ticket_enc = hex_decode(ticket_parts[1]);
        auto ticket_plain = bytes_to_str(aes_decrypt(KB_KDC, ticket_enc));
        auto ticket_fields = unpack_fields(ticket_plain);

        if (ticket_fields.size() != 2) {
            cerr << "[Bob] Invalid decrypted ticket\n";
            close(client);
            continue;
        }

        auto ks = hex_decode(ticket_fields[0]);
        string ida = ticket_fields[1];

        cout << "[Bob] Ticket decrypted\n";
        cout << "[Bob] Ks = " << hex_encode(ks) << "\n";
        cout << "[Bob] IDA = " << ida << "\n";

        string data_msg = recv_string(client);
        auto data_parts = unpack_fields(data_msg);

        if (data_parts.size() != 2 || data_parts[0] != "DATA") {
            cerr << "[Bob] Invalid data message\n";
            close(client);
            continue;
        }

        auto enc_payload = hex_decode(data_parts[1]);
        auto payload_plain = bytes_to_str(aes_decrypt(ks, enc_payload));
        auto payload_fields = unpack_fields(payload_plain);

        if (payload_fields.size() != 2) {
            cerr << "[Bob] Invalid payload structure\n";
            close(client);
            continue;
        }

        string M = payload_fields[0];
        string received_hash_hex = payload_fields[1];

        auto calc_hash = sha256_bytes(M);
        string calc_hash_hex = hex_encode(calc_hash);

        cout << "[Bob] Received M = " << M << "\n";
        cout << "[Bob] Received H(M) = " << received_hash_hex << "\n";
        cout << "[Bob] Calculated H(M) = " << calc_hash_hex << "\n";

        if (received_hash_hex == calc_hash_hex) {
            cout << "[Bob] Verification Successful\n";
        } else {
            cout << "[Bob] Verification Failed\n";
        }

        close(client);
    }

    close(server_fd);
    return 0;
}
