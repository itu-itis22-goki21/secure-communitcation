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
        cerr << "KDC socket creation failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(KDC_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "KDC bind failed\n";
        return 1;
    }

    listen(server_fd, 5);
    cout << "KDC listening on port " << KDC_PORT << "\n";

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;

        string req = recv_string(client);
        auto parts = unpack_fields(req);

        if (parts.size() == 3 && parts[0] == "REQ") {
            string ida = parts[1];
            string idb = parts[2];

            cout << "[KDC] Request from " << ida << " for " << idb << "\n";

            auto ks = random_bytes(32);
            cout << "[KDC] Generated Ks: " << hex_encode(ks) << "\n";

            // Alice gets Ks encrypted for her, while Bob gets a ticket encrypted with Bob's master key.
            auto enc_for_alice = aes_encrypt(KA_KDC, ks);

            string ticket_plain = pack_fields({hex_encode(ks), ida});
            auto ticket_enc = aes_encrypt(KB_KDC, str_to_bytes(ticket_plain));

            string response = pack_fields({
                "KDC_RESP",
                hex_encode(enc_for_alice),
                hex_encode(ticket_enc)
            });

            send_string(client, response);
        }

        close(client);
    }

    close(server_fd);
    return 0;
}
