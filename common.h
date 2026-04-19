#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <cstdint>
using namespace std;

extern const string ALICE_ID;
extern const string BOB_ID;

extern int KDC_PORT;
extern int BOB_PORT;

extern const vector<unsigned char> KA_KDC;
extern const vector<unsigned char> KB_KDC;

// Crypto and encoding helpers shared by all three programs.
vector<unsigned char> random_bytes(size_t n);
vector<unsigned char> sha256_bytes(const string& data);
string hex_encode(const vector<unsigned char>& data);
vector<unsigned char> hex_decode(const string& hex);

vector<unsigned char> aes_encrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& plaintext
);

vector<unsigned char> aes_decrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& ciphertext
);

vector<unsigned char> str_to_bytes(const string& s);
string bytes_to_str(const vector<unsigned char>& v);

bool send_string(int sock, const string& msg);
string recv_string(int sock);

// Messages are serialized as field1||field2||... for this homework protocol.
string pack_fields(const vector<string>& fields);
vector<string> unpack_fields(const string& packed);

#endif
