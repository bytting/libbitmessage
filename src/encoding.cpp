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

#include <cmath>
#include <sstream>
#include <botan/pipe.h>
#include <botan/filters.h>
#include "encoding.h"
#include "exceptions.h"

namespace bm {

namespace internal {

const std::string BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

} // namespace internal

namespace encode {

std::string hex(const byte_vector_type& v)
{
    Botan::Pipe pipe(new Botan::Hex_Encoder());
    pipe.process_msg(v);
    return pipe.read_all_as_string();
}

std::string hex(const std::vector<byte_type>& v)
{
    Botan::Pipe pipe(new Botan::Hex_Encoder());
    pipe.process_msg(&v[0], v.size());
    return pipe.read_all_as_string();
}

std::string base58(const big_integer_type& num)
{
    std::stringstream ss;

    if(num == 0)
    {
        ss << internal::BASE58[0];
        return ss.str();
    }

    big_integer_type n = num;
    uint32_t r, base = 58;

    while (n > 0)
    {
        r = n % base;
        n = n / base;

        ss << internal::BASE58[r];
    }

    std::string output = ss.str();
    std::reverse(output.begin(), output.end());

    return output;
}

std::string base58(const byte_vector_type& src)
{
    big_integer_type bit(&src[0], src.size());
    return base58(bit);
}

std::string base64(const byte_vector_type& data)
{
    Botan::Pipe pipe(new Botan::Base64_Encoder());
    pipe.process_msg(data);
    return pipe.read_all_as_string();
}

std::string base64(const std::vector<uint8_t>& data)
{
    Botan::Pipe pipe(new Botan::Base64_Encoder());
    pipe.process_msg(data);
    return pipe.read_all_as_string();
}

byte_vector_type varint(uint64_t integer)
{
    byte_vector_type v;

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
    else if (integer >= 65536 && integer < 4294967296)
    {
        v.resize(5);
        v[0] = (uint8_t)254;
        uint32_t ui32 = host_to_big_32((uint32_t)integer);
        memcpy(&v[1], &ui32, 4);
    }
    else
    {
        v.resize(9);
        v[0] = (uint8_t)255;
        uint64_t ui64 = host_to_big_64((uint64_t)integer);
        memcpy(&v[1], &ui64, 8);
    }

    return v;
}

} // namespace encode

namespace decode {

byte_vector_type hex(const std::string& encoded)
{
    Botan::Pipe pipe(new Botan::Hex_Decoder());
    pipe.process_msg(encoded);
    return pipe.read_all();
}

big_integer_type base58(const std::string& encoded)
{
    if(encoded.empty())
        throw size_exception(__FILE__, __LINE__, "decode_base58: encoded string is empty");

    big_integer_type num = 0;
    uint32_t base = 58;
    uint32_t exp = encoded.length() - 1;

    for(std::string::const_iterator it = encoded.begin(); it != encoded.end(); ++it, exp--)
    {
        uint64_t pos = internal::BASE58.find_first_of(*it);
        if(it == internal::BASE58.end())
            throw range_exception(__FILE__, __LINE__, "decode_base58: encoded character not in base58");

        num += pos * (uint64_t)std::pow((double)base, (double)exp);
    }

    return num;
}

byte_vector_type base58v(const std::string& encoded)
{    
    byte_vector_type result;

    uint32_t base = 58;
    big_integer_type bn = 0;

    for (std::string::const_iterator it = encoded.begin(); it != encoded.end(); ++it)
    {
        uint64_t pos = internal::BASE58.find_first_of(*it);
        if(it == internal::BASE58.end())
            throw range_exception(__FILE__, __LINE__, "decode_base58v: encoded character not in base58");

        bn = bn * base;
        bn += pos;
    }

    result.resize(bn.bytes());
    bn.binary_encode(&result[0]);

    /*
    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    */

    return result;
}

byte_vector_type base64(const std::string& encoded)
{
    Botan::Pipe pipe(new Botan::Base64_Decoder());
    pipe.process_msg(encoded);
    return pipe.read_all();
}

uint64_t varint(const byte_vector_type& data, int &nbytes)
{
    if (data.size() == 0)
        throw size_exception(__FILE__, __LINE__, "decode::varint: data buffer is empty");

    uint8_t first_byte;
    uint64_t result;
    nbytes = 0;

    first_byte = data[0];

    if (first_byte < 253)
    {
        nbytes = 1;
        return first_byte;
    }
    else if (first_byte == 253)
    {
        nbytes = 3;
        uint16_t ui16;
        memcpy(&ui16, &data[1], 2);
        result = big_to_host_16(ui16);
    }
    else if (first_byte == 254)
    {
        nbytes = 5;
        uint32_t ui32;
        memcpy(&ui32, &data[1], 4);
        result = big_to_host_32(ui32);
    }
    else
    {
        nbytes = 9;
        uint64_t ui64;
        memcpy(&ui64, &data[1], 8);
        result = big_to_host_64(ui64);
    }

    return result;
}

} // namespace decode

} // namespace bm
