#include "common.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>


namespace {
string env_or_default(const char* name, const char* fallback) {
    const char* value = getenv(name);
    return (value && *value) ? value : fallback;
}

bool env_flag(const char* name) {
    const char* value = getenv(name);
    return value && string(value) == "1";
}

int connect_to_host(const string& host, int port, int attempts = 20, int delay_ms = 500) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    string port_str = to_string(port);

    // Retry briefly so Alice can wait for KDC/Bob containers to finish starting up.
    for (int attempt = 0; attempt < attempts; ++attempt) {
        addrinfo* results = nullptr;
        if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results) == 0) {
            for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
                int sock = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
                if (sock < 0) continue;

                if (connect(sock, current->ai_addr, current->ai_addrlen) == 0) {
                    freeaddrinfo(results);
                    return sock;
                }

                close(sock);
            }

            freeaddrinfo(results);
        }

        this_thread::sleep_for(chrono::milliseconds(delay_ms));
    }

    return -1;
}
}

int main() {
    cout.setf(ios::unitbuf);

    string student_no = "150210093";
    string M = student_no + " Network Sec.";
    string kdc_host = env_or_default("KDC_HOST", "127.0.0.1");
    string bob_host = env_or_default("BOB_HOST", "127.0.0.1");
    bool plaintext_mode = env_flag("PLAINTEXT_MODE");
    bool tamper_hash = env_flag("TAMPER_HASH");

    int kdc_sock = connect_to_host(kdc_host, KDC_PORT);
    if (kdc_sock < 0) {
        cerr << "Alice could not connect to KDC at " << kdc_host << ":" << KDC_PORT << "\n";
        return 1;
    }

    string req = pack_fields({"REQ", ALICE_ID, BOB_ID});
    cout << "[Alice][Step 1] Connected to KDC at " << kdc_host << ":" << KDC_PORT << "\n";
    cout << "[Alice][Step 1] Sending request = " << req << "\n";
    send_string(kdc_sock, req);

    string kdc_resp = recv_string(kdc_sock);
    cout << "[Alice][Step 2] Received KDC response = " << kdc_resp << "\n";
    close(kdc_sock);

    auto resp_parts = unpack_fields(kdc_resp);
    if (resp_parts.size() != 3 || resp_parts[0] != "KDC_RESP") {
        cerr << "Invalid KDC response\n";
        return 1;
    }

    auto enc_ks = hex_decode(resp_parts[1]);
    auto ticket_for_bob = resp_parts[2];

    // Alice unwraps Ks with the long-term Alice-KDC master key.
    auto ks = aes_decrypt(KA_KDC, enc_ks);

    cout << "[Alice][Step 3] Encrypted Ks from KDC = " << resp_parts[1] << "\n";
    cout << "[Alice][Step 3] Decrypted Ks = " << hex_encode(ks) << "\n";
    cout << "[Alice][Step 3] Ticket for Bob = " << ticket_for_bob << "\n";

    auto hm = sha256_bytes(M);
    string original_hm_hex = hex_encode(hm);
    if (tamper_hash && !hm.empty()) {
        hm[0] ^= 0x01;
    }
    string hm_hex = hex_encode(hm);

    cout << "[Alice][Step 4] Plaintext M = " << M << "\n";
    cout << "[Alice][Step 4] Original H(M) = " << original_hm_hex << "\n";
    if (tamper_hash) {
        cout << "[Alice][Step 4] Tamper mode enabled: flipped 1 bit in H(M)\n";
    }
    cout << "[Alice][Step 4] Transmitted H(M) = " << hm_hex << "\n";

    string payload_plain = pack_fields({M, hm_hex});
    cout << "[Alice][Step 4] Payload before encryption = " << payload_plain << "\n";

    int bob_sock = connect_to_host(bob_host, BOB_PORT);
    if (bob_sock < 0) {
        cerr << "Alice could not connect to Bob at " << bob_host << ":" << BOB_PORT << "\n";
        return 1;
    }

    cout << "[Alice][Step 5] Connected to Bob at " << bob_host << ":" << BOB_PORT << "\n";
    cout << "[Alice][Step 5] Sending ticket message = "
         << pack_fields({"TICKET", ticket_for_bob}) << "\n";
    send_string(bob_sock, pack_fields({"TICKET", ticket_for_bob}));

    if (plaintext_mode) {
        // This mode exists only for the baseline Wireshark screenshot.
        cout << "[Alice][Step 6] Plaintext baseline mode enabled\n";
        cout << "[Alice][Step 6] Sending plaintext data message = "
             << pack_fields({"DATA_PLAIN", payload_plain}) << "\n";
        send_string(bob_sock, pack_fields({"DATA_PLAIN", payload_plain}));
    } else {
        // Bob receives both the ticket from the KDC and the message encrypted under Ks.
        auto enc_payload = aes_encrypt(ks, str_to_bytes(payload_plain));
        cout << "[Alice][Step 6] Encrypted payload = " << hex_encode(enc_payload) << "\n";
        cout << "[Alice][Step 6] Sending encrypted data message = "
             << pack_fields({"DATA", hex_encode(enc_payload)}) << "\n";
        send_string(bob_sock, pack_fields({"DATA", hex_encode(enc_payload)}));
    }

    cout << "[Alice][Done] Transmission completed\n";
    close(bob_sock);
    return 0;
}
