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
#include <botan/filters.h>
#include "hashes.h"

namespace bm {

namespace internal {

template<class T, class H>
ByteVector hash(const T& data)
{
    H hashObject;
    return hashObject.process(data);
}

ByteVector hmac_hash(const ByteVector& data, const ByteVector& key, const std::string& hmac_name)
{
    OctetVector okey(key);
    Botan::Pipe pipe(new Botan::MAC_Filter(hmac_name, okey));
    pipe.process_msg(data);
    ByteVector mac = pipe.read_all();
    return mac;
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

ByteVector ripemd160(const ByteVector& data)
{
    return internal::hash<ByteVector, Botan::RIPEMD_160>(data);
}

ByteVector ripemd160(const std::string& data)
{
    return internal::hash<std::string, Botan::RIPEMD_160>(data);
}

ByteVector sha256(const ByteVector& data)
{
    return internal::hash<ByteVector, Botan::SHA_256>(data);
}

ByteVector sha256(const std::string& data)
{
    return internal::hash<std::string, Botan::SHA_256>(data);
}

ByteVector sha512(const ByteVector& data)
{
    return internal::hash<ByteVector, Botan::SHA_512>(data);
}

ByteVector sha512(const std::string& data)
{
    return internal::hash<std::string, Botan::SHA_512>(data);
}

ByteVector hmac_sha256(const ByteVector& data, const ByteVector& key)
{
    return internal::hmac_hash(data, key, "HMAC(SHA-256)");
}

ByteVector hmac_sha512(const ByteVector& data, const ByteVector& key)
{
    return internal::hmac_hash(data, key, "HMAC(SHA-512)");
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

