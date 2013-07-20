/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
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
#include "enc.h"
#include "exceptions.h"
#include "hash.h"
#include "utils.h"

namespace bm {

namespace internal {

const std::string BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

} // namespace internal

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

std::string hex(const BigInteger& v)
{
    ByteVector result(v.bytes());
    v.binary_encode(result.data());
    return hex(result);
}

std::string base58(const BigInteger& num)
{
    std::stringstream ss;

    if(num == 0)
    {
        ss << internal::BASE58[0];
        return ss.str();
    }

    BigInteger n = num;
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

namespace decode {

SecureVector hex(const std::string& encoded)
{
    Botan::Pipe pipe(new Botan::Hex_Decoder());
    pipe.process_msg(encoded);
    return pipe.read_all();
}

BigInteger base58i(const std::string& encoded)
{
    if(encoded.empty())
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "Encoded string is empty");

    BigInteger num = 0;
    uint32_t base = 58;
    uint32_t exp = encoded.length() - 1;

    for(std::string::const_iterator it = encoded.begin(); it != encoded.end(); ++it, exp--)
    {
        uint64_t pos = internal::BASE58.find_first_of(*it);
        if(it == internal::BASE58.end())
            throw RangeException(__FILE__, __FUNCTION__, __LINE__, "Encoded character not in base58");

        num += pos * (uint64_t)std::pow((double)base, (double)exp);
    }

    return num;
}

SecureVector base58(const std::string& encoded)
{
    SecureVector result;

    uint32_t base = 58;
    BigInteger bn = 0;

    for (std::string::const_iterator it = encoded.begin(); it != encoded.end(); ++it)
    {
        uint64_t pos = internal::BASE58.find_first_of(*it);
        if(it == internal::BASE58.end())
            throw RangeException(__FILE__, __FUNCTION__, __LINE__, "Encoded character not in base58");

        bn = bn * base;
        bn += pos;
    }

    result.resize(bn.bytes());
    bn.binary_encode(result.data());

    /*
    // Get bignum as little endian data
    ByteVector vchTmp = bn.getvch();

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

SecureVector base64(const std::string& encoded)
{
    Botan::Pipe pipe(new Botan::Base64_Decoder());
    pipe.process_msg(encoded);
    return pipe.read_all();
}

uint64_t varint(const Byte* data, int &nbytes)
{
    if (!data)
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "Data buffer is empty");

    Byte first_byte;
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
        std::memcpy(&ui16, data + 1, 2);
        result = big_to_host_16(ui16);
    }
    else if (first_byte == 254)
    {
        nbytes = 5;
        uint32_t ui32;
        std::memcpy(&ui32, data + 1, 4);
        result = big_to_host_32(ui32);
    }
    else
    {
        nbytes = 9;
        uint64_t ui64;
        std::memcpy(&ui64, data + 1, 8);
        result = big_to_host_64(ui64);
    }

    return result;
}

SecureVector wif(const std::string& encoded)
{
    if(encoded.length() < 6)
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "Encoded WIF is too short");

    SecureVector result, decoded = decode::base58(encoded);
    std::copy(decoded.begin() + 1, decoded.end() - 4, std::back_inserter(result));
    return result;
}

} // namespace decode

} // namespace bm
