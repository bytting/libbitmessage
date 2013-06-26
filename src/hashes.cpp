/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// CONTRIBUTORS AND COPYRIGHT HOLDERS (c) 2013:
// Bob Mottram (bob@robotics.uk.to)
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

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

namespace bm {

namespace internal {

void makeByteVectorHex(const ByteVector& src, ByteVector& dest)
{
    char cbuffer[2];
    dest.clear();
    for(size_t i = 0; i < src.size(); ++i)
    {
        sprintf(cbuffer, "%02x", (char)src[i]);
        dest.push_back((Byte)cbuffer[0]);
        dest.push_back((Byte)cbuffer[1]);
    }
}

template<class T, class H>
ByteVector hash(const T& data, DigestFormat fmt)
{
    H hashObject;
    ByteVector bytes = hashObject.process(data);

    if(fmt == FORMAT_HEX)
    {
        ByteVector hexBytes;
        internal::makeByteVectorHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

template<class T>
ByteVector hmac_hash(const ByteVector& data, DigestFormat fmt)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    ByteVector bytes = hmac.process(data);

    if(fmt == FORMAT_HEX)
    {
        ByteVector hexBytes;
        internal::makeByteVectorHex(bytes, hexBytes);
        return hexBytes;
    }
    return bytes;
}

template<class T>
OctetVector pbkdf2_hmac_hash(const std::string& password, const ByteVector& salt, int desiredKeyLength, int iterations)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    Botan::PKCS5_PBKDF2 pbkdf2(&hmac);
    return pbkdf2.derive_key(desiredKeyLength, password, &salt[0], salt.size(), iterations);
}

} // namespace internal

ByteVector ripemd160(const ByteVector& data, DigestFormat fmt)
{
    return internal::hash<ByteVector, Botan::RIPEMD_160>(data, fmt);
}

ByteVector sha256(const ByteVector& data, DigestFormat fmt)
{
    return internal::hash<ByteVector, Botan::SHA_256>(data, fmt);
}

ByteVector sha256(const std::string& data, DigestFormat fmt)
{
    return internal::hash<std::string, Botan::SHA_256>(data, fmt);
}

ByteVector sha512(const ByteVector& data, DigestFormat fmt)
{
    return internal::hash<ByteVector, Botan::SHA_512>(data, fmt);
}

ByteVector sha512(const std::string& data, DigestFormat fmt)
{
    return internal::hash<std::string, Botan::SHA_512>(data, fmt);
}

ByteVector hmac_sha256(const ByteVector& data, DigestFormat fmt)
{
    return internal::hmac_hash<Botan::SHA_256>(data, fmt);
}

ByteVector hmac_sha512(const ByteVector& data, DigestFormat fmt)
{
    return internal::hmac_hash<Botan::SHA_512>(data, fmt);
}

OctetVector pbkdf2_hmac_sha256(const std::string& password, const ByteVector& salt, int desiredKeyLength, int iterations)
{
    return internal::pbkdf2_hmac_hash<Botan::SHA_256>(password, salt, desiredKeyLength, iterations);
}

OctetVector pbkdf2_hmac_sha512(const std::string& password, const ByteVector& salt, int desiredKeyLength, int iterations)
{
    return internal::pbkdf2_hmac_hash<Botan::SHA_512>(password, salt, desiredKeyLength, iterations);
}

} // namespace bm

