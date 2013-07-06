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

#ifndef BTYPES_H
#define BTYPES_H

#include <cstdint>
#include <botan/types.h>
#include <botan/bigint.h>
#include <botan/secmem.h>
#include <botan/symkey.h>

#if defined(__linux__)
#include <endian.h>
#define big_to_host_16(v) be16toh(v)
#define big_to_host_32(v) be32toh(v)
#define big_to_host_64(v) be64toh(v)
#define host_to_big_16(v) htobe16(v)
#define host_to_big_32(v) htobe32(v)
#define host_to_big_64(v) htobe64(v)
#elif defined(_WIN32)
    #error endian not implemented for Windows
    //#if defined(_WIN64)
    //#endif
#elif defined(__unix__)
    #error endian not implemented for UNIX
#elif defined(__APPLE__)
    #error endian not implemented for Apple
#elif defined(__FreeBSD__)
    #error endian not implemented for FreeBSD
#endif

namespace bm {

typedef Botan::byte byte_type;
typedef Botan::SecureVector<byte_type> byte_vector_type;
typedef Botan::OctetString octet_string_type;
typedef Botan::BigInt big_integer_type;

} // namespace bm

#endif
