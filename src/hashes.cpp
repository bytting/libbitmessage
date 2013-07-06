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
#include <botan/pipe.h>
#include <botan/filters.h>
#include "hashes.h"

namespace bm {

namespace hash {

namespace internal {

template<class T, class H>
byte_vector_type hash(const T& data)
{
    H hashObject;
    return hashObject.process(data);
}

byte_vector_type hmac_hash(const byte_vector_type& data, const byte_vector_type& key, const std::string& hmac_name)
{
    octet_string_type okey(key);
    Botan::Pipe pipe(new Botan::MAC_Filter(hmac_name, okey));
    pipe.process_msg(data);
    return pipe.read_all();
}

template<class T>
octet_string_type pbkdf2_hmac_hash(const std::string& password, const byte_vector_type& salt, int desiredKeyLength, int iterations)
{
    T hashObject;
    Botan::HMAC hmac(&hashObject);
    Botan::PKCS5_PBKDF2 pbkdf2(&hmac);
    return pbkdf2.derive_key(desiredKeyLength, password, &salt[0], salt.size(), iterations);
}

} // namespace internal

byte_vector_type ripemd160(const byte_vector_type& data)
{
    return internal::hash<byte_vector_type, Botan::RIPEMD_160>(data);
}

byte_vector_type ripemd160(const std::string& data)
{
    return internal::hash<std::string, Botan::RIPEMD_160>(data);
}

byte_vector_type sha256(const byte_vector_type& data)
{
    return internal::hash<byte_vector_type, Botan::SHA_256>(data);
}

byte_vector_type sha256(const std::string& data)
{
    return internal::hash<std::string, Botan::SHA_256>(data);
}

byte_vector_type sha512(const byte_vector_type& data)
{
    return internal::hash<byte_vector_type, Botan::SHA_512>(data);
}

byte_vector_type sha512(const std::string& data)
{
    return internal::hash<std::string, Botan::SHA_512>(data);
}

byte_vector_type hmac_sha256(const byte_vector_type& data, const byte_vector_type& key)
{
    return internal::hmac_hash(data, key, "HMAC(SHA-256)");
}

byte_vector_type hmac_sha512(const byte_vector_type& data, const byte_vector_type& key)
{
    return internal::hmac_hash(data, key, "HMAC(SHA-512)");
}

octet_string_type pbkdf2_hmac_sha256(const std::string& password, const byte_vector_type& salt, int desiredKeyLength, int iterations)
{
    return internal::pbkdf2_hmac_hash<Botan::SHA_256>(password, salt, desiredKeyLength, iterations);
}

octet_string_type pbkdf2_hmac_sha512(const std::string& password, const byte_vector_type& salt, int desiredKeyLength, int iterations)
{
    return internal::pbkdf2_hmac_hash<Botan::SHA_512>(password, salt, desiredKeyLength, iterations);
}

} // namespace hash

} // namespace bm

