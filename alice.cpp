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

int connect_to_host(const string& host, int port, int attempts = 20, int delay_ms = 500) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    string port_str = to_string(port);

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

    string student_no = "11111111";
    string M = student_no + " Network Sec.";
    string kdc_host = env_or_default("KDC_HOST", "127.0.0.1");
    string bob_host = env_or_default("BOB_HOST", "127.0.0.1");

    int kdc_sock = connect_to_host(kdc_host, KDC_PORT);
    if (kdc_sock < 0) {
        cerr << "Alice could not connect to KDC at " << kdc_host << ":" << KDC_PORT << "\n";
        return 1;
    }

    string req = pack_fields({"REQ", ALICE_ID, BOB_ID});
    send_string(kdc_sock, req);

    string kdc_resp = recv_string(kdc_sock);
    close(kdc_sock);

    auto resp_parts = unpack_fields(kdc_resp);
    if (resp_parts.size() != 3 || resp_parts[0] != "KDC_RESP") {
        cerr << "Invalid KDC response\n";
        return 1;
    }

    auto enc_ks = hex_decode(resp_parts[1]);
    auto ticket_for_bob = resp_parts[2];

    auto ks = aes_decrypt(KA_KDC, enc_ks);

    cout << "[Alice] Ks = " << hex_encode(ks) << "\n";
    cout << "[Alice] Ticket for Bob = " << ticket_for_bob << "\n";

    auto hm = sha256_bytes(M);
    string hm_hex = hex_encode(hm);

    cout << "[Alice] M = " << M << "\n";
    cout << "[Alice] H(M) = " << hm_hex << "\n";

    string payload_plain = pack_fields({M, hm_hex});
    auto enc_payload = aes_encrypt(ks, str_to_bytes(payload_plain));

    int bob_sock = connect_to_host(bob_host, BOB_PORT);
    if (bob_sock < 0) {
        cerr << "Alice could not connect to Bob at " << bob_host << ":" << BOB_PORT << "\n";
        return 1;
    }

    send_string(bob_sock, pack_fields({"TICKET", ticket_for_bob}));
    send_string(bob_sock, pack_fields({"DATA", hex_encode(enc_payload)}));

    close(bob_sock);
    return 0;
}
