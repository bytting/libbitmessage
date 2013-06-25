#ifndef BM_HASHES_H
#define BM_HASHES_H

#include <string>
#include "utils.h"

enum DigestFormat { DF_NONE, DF_HEX };

ByteVector bm_ripemd160(const ByteVector& data, DigestFormat fmt = DF_NONE);
ByteVector bm_sha256(const ByteVector& data, DigestFormat fmt = DF_NONE);
ByteVector bm_sha512(const ByteVector& data, DigestFormat fmt = DF_NONE);

ByteVector bm_hmac_sha256(const ByteVector& data, DigestFormat fmt = DF_NONE);
ByteVector bm_hmac_sha512(const ByteVector& data, DigestFormat fmt = DF_NONE);

OctetVector bm_pbkdf2_hmac_sha256(const std::string& password, const ByteVector& salt, int iterations = 10000);
OctetVector bm_pbkdf2_hmac_sha512(const std::string& password, const ByteVector& salt, int iterations = 10000);

#endif
