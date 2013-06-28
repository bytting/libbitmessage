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

namespace internal {

const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int decode_char(unsigned char ch)
{
    if (ch >= '1' && ch <= '9')
        return ch - '1';

    if (ch >= 'a' && ch <= 'k')
        return ch - 'a' + 9;

    if (ch >= 'm' && ch <= 'z')
        return ch - 'm' + 20;

    if (ch >= 'A' && ch <= 'H')
        return ch - 'A' + 34;

    if (ch >= 'J' && ch <= 'N')
        return ch - 'J' + 42;

    if (ch >= 'P' && ch <= 'Z')
        return ch - 'P' + 47;

    return -1;
}

} // namespace internal

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
        v[0] = (uint8_t)integer;
    }
    else if (integer >= 253 && integer < 65536)
    {
        v.resize(3);
        v[0] = (uint8_t)253;
        uint16_t ui16 = host_to_big_16((uint16_t)integer);
        memcpy(&v[1], &ui16, 2);
    }
    if (integer >= 65536 && integer < 4294967296)
    {
        v.resize(5);
        v[0] = (uint8_t)254;
        uint32_t ui32 = host_to_big_32((uint32_t)integer);
        memcpy(&v[1], &ui32, 4);
    }
    if (integer >= 4294967296)
    {
        v.resize(9);
        v[0] = (uint8_t)255;
        uint64_t ui64 = host_to_big_64((uint64_t)integer);
        memcpy(&v[1], &ui64, 8);
    }

    return v;
}

uint64_t decode_varint(const ByteVector& data, int &nbytes)
{
    if (data.size() == 0)
        throw SizeException(__FILE__, __LINE__, "decode_varint: data buffer is empty");

    uint8_t first_byte;
    uint64_t result;
    nbytes = 0;

    first_byte = data[0];

    if (first_byte < 253) {
        nbytes = 1;
        return first_byte;
    }
    else if (first_byte == 253) {
        nbytes = 3;
        uint16_t ui16;
        memcpy(&ui16, &data[1], 2);
        ui16 = big_to_host_16(ui16);
        result = ui16;
    }
    else if (first_byte == 254) {
        nbytes = 5;
        uint32_t ui32;
        memcpy(&ui32, &data[1], 4);
        ui32 = big_to_host_32(ui32);
        result = ui32;
    }
    else {
        nbytes = 9;
        uint64_t ui64;
        memcpy(&ui64, &data[1], 8);
        ui64 = big_to_host_32(ui64);
        result = ui64;
    }

    return result;
}

std::string encode_base58(const Botan::BigInt& src)
{
    std::stringstream ss;
    Botan::BigInt num, id_num = src;
    uint32_t remainder;

    while (id_num > 0) {

        num = id_num / 58;
        remainder = id_num % 58;

        ss << internal::BASE58[remainder];

        id_num = num;
    }

    std::string output = ss.str();
    std::reverse(output.begin(), output.end());

    return output;
}

Botan::BigInt decode_base58(const std::string& encoded)
{
    if(encoded.empty())
        throw SizeException(__FILE__, __LINE__, "decode_base58: encoded string is empty");

    Botan::BigInt output_num = 0;

    size_t unprocessed = encoded.length();
    while (--unprocessed) {

        int idx = encoded.length() - unprocessed - 1;
        int num = internal::decode_char(encoded[idx]);
        if (num == -1)
            throw RangeException(__FILE__, __LINE__, "decode_base58: character not within base58");

        output_num += num;
        output_num *= 58;
    }

    int remainder = internal::decode_char(encoded[encoded.length() - 1]);
    if (remainder == -1)
        throw RangeException(__FILE__, __LINE__, "decode_base58: character not within base58");

    return output_num + remainder;
}

std::string encode_base64(const ByteVector& data)
{
    Botan::Pipe pipe(new Botan::Base64_Encoder());
    pipe.process_msg(data);
    return pipe.read_all_as_string();
}

ByteVector decode_base64(const std::string& encoded)
{
    Botan::Pipe pipe(new Botan::Base64_Decoder());
    pipe.process_msg(encoded);
    return pipe.read_all();
}

std::string encode_address(uint64_t version, uint64_t stream, const ByteVector& ripe)
{
    if(ripe.size() != 20)
        throw SizeException(__FILE__, __LINE__, "create_random_address: The ripe length is not 20");

    ByteVector r = ripe;
    if(r[0] == 0x00 && r[1] == 0x00)
    {
        ByteVector tmp(&r[2], r.size() - 2);
        r = tmp;
    }
    else if(r[0] == 0x00)
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
    std::string s = utils::encode_base58(bi);

    return "BM-" + s;
}

} // namespace utils

} // namespace bm
