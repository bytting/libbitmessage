#include <sstream>
#include <cstdio>
#include <botan/hash.h>
#include <botan/mdx_hash.h>
#include <botan/rmd160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/hmac.h>
#include <botan/pbkdf2.h>
#include <botan/symkey.h>
#include "hashes.h"

void makeByteVectorHex(const ByteVector& src, ByteVector& dest)
{
    char cbuffer[2];
    dest.clear();
    for(int i = 0; i < src.size(); ++i)
    {
        sprintf(cbuffer, "%02x", (char)src[i]);
        dest.push_back((Byte)cbuffer[0]);
        dest.push_back((Byte)cbuffer[1]);
    }
}

template<class T>
ByteVector bm_hash(const ByteVector& data, DigestFormat fmt)
{
    T hashObject;
    ByteVector bytes = hashObject.process(data);

    if(fmt == DF_HEX)
    {
        ByteVector hexBytes;
        makeByteVectorHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

ByteVector bm_ripemd160(const ByteVector& data, DigestFormat fmt)
{
    return bm_hash<Botan::RIPEMD_160>(data, fmt);
}

ByteVector bm_sha256(const ByteVector& data, DigestFormat fmt)
{
    return bm_hash<Botan::SHA_256>(data, fmt);
}

ByteVector bm_sha512(const ByteVector& data, DigestFormat fmt)
{
    return bm_hash<Botan::SHA_512>(data, fmt);
}

template<class T>
ByteVector bm_hmac_hash(const ByteVector& data, DigestFormat fmt)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    ByteVector bytes = hmac.process(data);

    if(fmt == DF_HEX)
    {
        ByteVector hexBytes;
        makeByteVectorHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

ByteVector bm_hmac_sha256(const ByteVector& data, DigestFormat fmt)
{
    return bm_hmac_hash<Botan::SHA_256>(data, fmt);
}

ByteVector bm_hmac_sha512(const ByteVector& data, DigestFormat fmt)
{
    return bm_hmac_hash<Botan::SHA_512>(data, fmt);
}

template<class T>
std::string bm_pbkdf2_hmac_hash(const std::string& password, const ByteVector& salt, int desiredKeyLength, DigestFormat fmt, int iterations)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    Botan::PKCS5_PBKDF2 pbkdf2(&hmac);

    Botan::OctetString okey = pbkdf2.derive_key(desiredKeyLength, password, &salt[0], salt.size(), iterations);
    std::string key = okey.as_string();

    if(fmt == DF_HEX)
    {
        std::stringstream ss;
        char cbuffer[2];
        for(int i = 0; i < key.size(); ++i)
        {
            sprintf(cbuffer, "%02x", key[i]);
            ss << cbuffer[0] << cbuffer[1];
        }
        return ss.str();
    }
    return key;
}

std::string bm_pbkdf2_hmac_sha256(const std::string& password, const ByteVector& salt, int desiredKeyLength, DigestFormat fmt, int iterations)
{
    bm_pbkdf2_hmac_hash<Botan::SHA_256>(password, salt, desiredKeyLength, fmt, iterations);
}

std::string bm_pbkdf2_hmac_sha512(const std::string& password, const ByteVector& salt, int desiredKeyLength, DigestFormat fmt, int iterations)
{
    bm_pbkdf2_hmac_hash<Botan::SHA_512>(password, salt, desiredKeyLength, fmt, iterations);
}
