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
#include "decode.h"
#include "exceptions.h"
#include "hash.h"
#include "utils.h"

namespace bm {

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
        uint64_t pos = utils::BASE58.find_first_of(*it);
        if(it == utils::BASE58.end())
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
        uint64_t pos = utils::BASE58.find_first_of(*it);
        if(it == utils::BASE58.end())
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
