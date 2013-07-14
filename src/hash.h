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

#ifndef BM_HASH_H
#define BM_HASH_H

#include <string>
#include "btypes.h"

namespace bm {

namespace hash {

byte_vector_type ripemd160(const byte_vector_type& data);
byte_vector_type ripemd160(const std::string& data);
byte_vector_type sha256(const byte_vector_type& data);
byte_vector_type sha256(const std::string& data);
byte_vector_type sha512(const byte_vector_type& data);
byte_vector_type sha512(const std::vector<uint8_t>& data);
byte_vector_type sha512(const std::string& data);
byte_vector_type hmac_sha256(const byte_vector_type& data, const byte_vector_type& key);
byte_vector_type hmac_sha512(const byte_vector_type& data, const byte_vector_type& key);
octet_string_type pbkdf2_hmac_sha256(const std::string& password, const byte_vector_type& salt, int iterations = 10000);
octet_string_type pbkdf2_hmac_sha512(const std::string& password, const byte_vector_type& salt, int iterations = 10000);

} // namespace hash

} // namespace bm

#endif
