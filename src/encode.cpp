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

#include <algorithm>
#include <iterator>
#include <cstring>
#include <cmath>
#include <sstream>
#include <botan/pipe.h>
#include <botan/filters.h>
#include "encode.h"
#include "exceptions.h"
#include "hash.h"
#include "utils.h"

namespace bm {

namespace encode {

std::string hex(const SecureVector& v)
{
    Botan::Pipe pipe(new Botan::Hex_Encoder());
    pipe.process_msg(v);
    return pipe.read_all_as_string();
}

std::string hex(const ByteVector& v)
{
    Botan::Pipe pipe(new Botan::Hex_Encoder());
    pipe.process_msg(v.data(), v.size());
    return pipe.read_all_as_string();
}

std::string base58(const BigInteger& num)
{
    std::stringstream ss;

    if(num == 0)
    {
        ss << utils::BASE58[0];
        return ss.str();
    }

    BigInteger n = num;
    uint32_t r, base = 58;

    while (n > 0)
    {
        r = n % base;
        n = n / base;

        ss << utils::BASE58[r];
    }

    std::string output = ss.str();
    std::reverse(output.begin(), output.end());

    return output;
}

std::string base58(const SecureVector& src)
{
    BigInteger bit(src.data(), src.size());
    return base58(bit);
}

std::string base64(const SecureVector& data)
{
    Botan::Pipe pipe(new Botan::Base64_Encoder());
    pipe.process_msg(data);
    return pipe.read_all_as_string();
}

std::string base64(const ByteVector& data)
{
    Botan::Pipe pipe(new Botan::Base64_Encoder());
    pipe.process_msg(data);
    return pipe.read_all_as_string();
}

SecureVector varint(uint64_t integer)
{
    SecureVector v;

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
        std::memcpy(&v[1], &ui16, 2);
    }
    else if (integer >= 65536 && integer < 4294967296)
    {
        v.resize(5);
        v[0] = (uint8_t)254;
        uint32_t ui32 = host_to_big_32((uint32_t)integer);
        std::memcpy(&v[1], &ui32, 4);
    }
    else
    {
        v.resize(9);
        v[0] = (uint8_t)255;
        uint64_t ui64 = host_to_big_64((uint64_t)integer);
        std::memcpy(&v[1], &ui64, 8);
    }

    return v;
}

std::string wif(const SecureVector& key)
{
    SecureVector extended;

    extended.push_back(0x80);
    std::copy(key.begin(), key.end(), std::back_inserter(extended));

    SecureVector checksum = hash::sha256(hash::sha256(extended));
    std::copy(checksum.begin(), checksum.begin() + 4, std::back_inserter(extended));

    return encode::base58(extended);
}

} // namespace encode

} // namespace bm
