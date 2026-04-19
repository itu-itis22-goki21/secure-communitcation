#include "common.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>


const string ALICE_ID = "Alice";
const string BOB_ID = "Bob";

namespace {
int port_from_env(const char* name, int fallback) {
    // Docker can inject ports through environment variables without changing code.
    const char* raw = getenv(name);
    if (!raw || !*raw) return fallback;

    try {
        int port = stoi(raw);
        if (port > 0 && port <= 65535) return port;
    } catch (const exception&) {
    }

    return fallback;
}
}

int KDC_PORT = port_from_env("KDC_PORT", 5000);
int BOB_PORT = port_from_env("BOB_PORT", 5001);

// 32-byte AES-256 master keys
const vector<unsigned char> KA_KDC = {
    'A','L','I','C','E','_','M','A','S','T','E','R','_','K','E','Y',
    '_','3','2','_','B','Y','T','E','S','_','L','E','N','_','!','!'
};

const vector<unsigned char> KB_KDC = {
    'B','O','B','_','_','M','A','S','T','E','R','_','K','E','Y','_',
    '_','3','2','_','B','Y','T','E','S','_','L','E','N','_','!','!'
};

vector<unsigned char> random_bytes(size_t n) {
    vector<unsigned char> out(n);
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw runtime_error("RAND_bytes failed");
    }
    return out;
}

vector<unsigned char> sha256_bytes(const string& data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash.data());
    return hash;
}

string hex_encode(const vector<unsigned char>& data) {
    ostringstream oss;
    for (unsigned char c : data) {
        oss << hex << setw(2) << setfill('0') << (int)c;
    }
    return oss.str();
}

vector<unsigned char> hex_decode(const string& hex) {
    if (hex.size() % 2 != 0) throw runtime_error("Invalid hex length");
    vector<unsigned char> out;
    for (size_t i = 0; i < hex.size(); i += 2) {
        string byte = hex.substr(i, 2);
        out.push_back(static_cast<unsigned char>(stoi(byte, nullptr, 16)));
    }
    return out;
}

vector<unsigned char> aes_encrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

    vector<unsigned char> iv = random_bytes(16);
    vector<unsigned char> ciphertext(plaintext.size() + 16);

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EncryptInit failed");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EncryptFinal failed");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    // Prefix the IV so the receiver can decrypt with the same random IV.
    vector<unsigned char> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

vector<unsigned char> aes_decrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& ciphertext
) {
    if (ciphertext.size() < 16) throw runtime_error("Ciphertext too short");

    vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + 16);
    vector<unsigned char> enc(ciphertext.begin() + 16, ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

    vector<unsigned char> plaintext(enc.size() + 16);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("DecryptInit failed");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, enc.data(), enc.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("DecryptFinal failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

vector<unsigned char> str_to_bytes(const string& s) {
    return vector<unsigned char>(s.begin(), s.end());
}

string bytes_to_str(const vector<unsigned char>& v) {
    return string(v.begin(), v.end());
}

bool send_string(int sock, const string& msg) {
    // Send a fixed-size length header first so recv_string knows how many bytes to read.
    uint32_t len = htonl(static_cast<uint32_t>(msg.size()));
    if (send(sock, &len, sizeof(len), 0) != sizeof(len)) return false;

    size_t total = 0;
    while (total < msg.size()) {
        ssize_t sent = send(sock, msg.data() + total, msg.size() - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}

string recv_string(int sock) {
    uint32_t len_net = 0;
    ssize_t r = recv(sock, &len_net, sizeof(len_net), MSG_WAITALL);
    if (r != sizeof(len_net)) return "";

    uint32_t len = ntohl(len_net);
    string msg(len, '\0');

    r = recv(sock, msg.data(), len, MSG_WAITALL);
    if (r != static_cast<ssize_t>(len)) return "";
    return msg;
}

string pack_fields(const vector<string>& fields) {
    ostringstream oss;
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i) oss << "||";
        oss << fields[i];
    }
    return oss.str();
}

vector<string> unpack_fields(const string& packed) {
    vector<string> fields;
    size_t start = 0;
    while (true) {
        size_t pos = packed.find("||", start);
        if (pos == string::npos) {
            fields.push_back(packed.substr(start));
            break;
        }
        fields.push_back(packed.substr(start, pos - start));
        start = pos + 2;
    }
    return fields;
}
