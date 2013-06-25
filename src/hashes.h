#ifndef BM_HASHES_H
#define BM_HASHES_H

#include <string>
#include "utils.h"

enum DigestBase { dec, hex };

template<class T>
ByteArray bm_hash(const ByteArray& data, DigestBase db);

ByteArray bm_ripemd160(const ByteArray& data, DigestBase db);
ByteArray bm_sha256(const ByteArray& data, DigestBase db);
ByteArray bm_sha512(const ByteArray& data, DigestBase db);

template<class T>
ByteArray bm_hmac(const ByteArray& data, DigestBase db);

ByteArray bm_hmac_sha256(const ByteArray& data, DigestBase db);
ByteArray bm_hmac_sha512(const ByteArray& data, DigestBase db);

template<class T>
std::string bm_pbkdf2_hmac(const std::string& password, const ByteArray& salt, DigestBase db, int iterations = 10000);

std::string bm_pbkdf2_hmac_sha256(const std::string& password, const ByteArray& salt, DigestBase db, int iterations = 10000);
std::string bm_pbkdf2_hmac_sha512(const std::string& password, const ByteArray& salt, DigestBase db, int iterations = 10000);

//void bm_doubleSha512(char *string, char outputBuffer[129], int hexdigest);

#endif
