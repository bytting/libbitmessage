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
#include <chrono>
#include <botan/botan.h>
#include <botan/rng.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include "utils.h"
#include "exceptions.h"
#include "hashes.h"
#include "base58.h"

namespace bm {

namespace utils {

ByteVector random_bytes(uint32_t count)
{
    Botan::AutoSeeded_RNG rng;
    return rng.random_vec(count);
}

uint32_t seconds_since_epoc()
{
    using namespace std::chrono;
    system_clock::time_point tp = system_clock::now();
    system_clock::duration dtn = tp.time_since_epoch();
    return dtn.count() * system_clock::period::num / system_clock::period::den;
}

std::string encode_hex(const ByteVector& v)
{
    Botan::Pipe pipe(new Botan::Hex_Encoder());
    pipe.process_msg(v);
    return pipe.read_all_as_string();
}

ByteVector encode_varint(uint64_t integer)
{
    ByteVector v;
    if (integer < 253)
    {
        v.resize(1);
        uint8_t ui8 = (uint8_t)integer;
        memcpy(&v[0], &ui8, 1);
    }
    else if (integer >= 253 && integer < 65536)
    {
        v.resize(3);
        uint8_t ui8 = (uint8_t)253;
        memcpy(&v[0], &ui8, 1);
        uint16_t ui16 = host_to_big_16((uint16_t)integer);
        memcpy(&v[1], &ui16, 2);
    }
    if (integer >= 65536 && integer < 4294967296)
    {
        v.resize(5);
        uint8_t ui8 = (uint8_t)254;
        memcpy(&v[0], &ui8, 1);
        uint32_t ui32 = host_to_big_32((uint32_t)integer);
        memcpy(&v[1], &ui32, 4);
    }
    if (integer >= 4294967296)
    {
        v.resize(9);
        uint8_t ui8 = (uint8_t)255;
        memcpy(&v[0], &ui8, 1);
        uint64_t ui64 = host_to_big_64((uint64_t)integer);
        memcpy(&v[1], &ui64, 8);
    }

    return v;
}

std::string encode_address(uint64_t version, uint64_t stream, const ByteVector& ripe)
{
    if(ripe.size() != 20)
        throw SizeException(__FILE__, __LINE__, "create_random_address(): The ripe length is not 20");

    ByteVector r = ripe;
    if(r[0] == 0x00 && r[1] == 0x00)
    {
        ByteVector tmp(&r[2], r.size() - 2);
        r = tmp;
    }
    else if(ripe[0] == 0x00)
    {
        ByteVector tmp(&r[1], r.size() - 1);
        r = tmp;
    }

    ByteVector v = encode_varint(version);
    v += encode_varint(stream);
    v += r;

    ByteVector sha1 = sha512(v);
    ByteVector sha2 = sha512(sha1);
    ByteVector checksum(&sha2[0], 4);

    v += checksum;
    Botan::BigInt bi(&v[0], v.size());
    char buffer[512];
    base58::encode(bi, buffer, 512);

    return "BM-" + std::string(buffer);
}

} // namespace utils

} // namespace bm
