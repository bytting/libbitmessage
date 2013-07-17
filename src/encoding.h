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
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#ifndef BM_ENCODING_H
#define BM_ENCODING_H

#include <stdint.h>
#include <string>
#include "btypes.h"

namespace bm {

namespace encode {

std::string hex(const byte_vector_type& v);
std::string hex(const std::vector<byte_type>& v);

std::string base58(const big_integer_type& src);
std::string base58(const byte_vector_type& src);

std::string base64(const byte_vector_type& data);
std::string base64(const std::vector<uint8_t>& data);

byte_vector_type varint(uint64_t integer);

std::string wif(const byte_vector_type& key);

} // namespace encode

namespace decode {

byte_vector_type hex(const std::string& encoded);

big_integer_type base58(const std::string& encoded);
byte_vector_type base58v(const std::string& encoded);

byte_vector_type base64(const std::string& encoded);

uint64_t varint(const byte_vector_type& data, int &nbytes);

} // namespace decode

} // namespace bm

#endif
