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

namespace // anonymous namespace
{

void _makeByteArrayHex(const ByteArray& src, ByteArray& dest)
{
    char cbuffer[2];
    dest.resize(src.size() * 2);
    for(int i = 0; i < src.size(); ++i)
    {
        sprintf(cbuffer, "%02x", (char)src[i]);
        dest.push_back((Byte)cbuffer[0]);
        dest.push_back((Byte)cbuffer[1]);
    }
}

} // end anonymous namespace

template<class T>
ByteArray bm_hash(const ByteArray& data, DigestBase db)
{
    T hashObject;
    ByteArray bytes = hashObject.process(data);

    if(db == hex)
    {
        ByteArray hexBytes;
        _makeByteArrayHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

template ByteArray bm_hash<Botan::RIPEMD_160>(const ByteArray&, DigestBase);
template ByteArray bm_hash<Botan::SHA_256>(const ByteArray&, DigestBase);
template ByteArray bm_hash<Botan::SHA_512>(const ByteArray&, DigestBase);

template<class T>
ByteArray bm_hmac_hash(const ByteArray& data, DigestBase db)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    ByteArray bytes = hmac.process(data);

    if(db == hex)
    {
        ByteArray hexBytes;
        _makeByteArrayHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

template ByteArray bm_hmac_hash<Botan::SHA_256>(const ByteArray&, DigestBase);
template ByteArray bm_hmac_hash<Botan::SHA_512>(const ByteArray&, DigestBase);

template<class T>
std::string bm_pbkdf2_hmac_hash(const std::string& password, const ByteArray& salt, int desiredKeyLength, DigestBase db, int iterations)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    Botan::PKCS5_PBKDF2 pbkdf2(&hmac);

    Botan::OctetString okey = pbkdf2.derive_key(desiredKeyLength, password, &salt[0], salt.size(), iterations);
    std::string key = okey.as_string();

    if(db == hex)
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

template std::string bm_pbkdf2_hmac_hash<Botan::SHA_256>(const std::string&, const ByteArray&, int, DigestBase, int);
template std::string bm_pbkdf2_hmac_hash<Botan::SHA_512>(const std::string&, const ByteArray&, int, DigestBase, int);

/*
void bm_doubleSha512(char *string, char outputBuffer[129], int hexdigest)
{
    unsigned char hash[SHA512_DIGEST_LENGTH];
	char buffer[129];

	bm_sha512(string, buffer, 0);
	bm_sha512((char*)buffer, outputBuffer, hexdigest);
}
*/
