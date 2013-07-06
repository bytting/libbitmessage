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

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <string>
//#include <botan/botan.h>
#include <botan/auto_rng.h>
#include "btypes.h"

namespace bm {

namespace utils {

Botan::AutoSeeded_RNG& random_number_generator();

byte_vector_type random_bytes(uint32_t count);
uint32_t seconds_since_epoc();

std::string encode_hex(const byte_vector_type& v);
std::string encode_hex(const std::vector<byte_type>& v);
byte_vector_type decode_hex(const std::string& encoded);

std::string encode_base58(const big_integer_type& src);
big_integer_type decode_base58(const std::string& encoded);
byte_vector_type decode_base58v(const std::string& encoded);

std::string encode_base64(const byte_vector_type& data);
byte_vector_type decode_base64(const std::string& encoded);

byte_vector_type serialize_varint(uint64_t integer);
uint64_t deserialize_varint(const byte_vector_type& data, int &nbytes);

} //namespace utils

} //namespace bm

#endif
