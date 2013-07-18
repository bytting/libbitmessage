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

#include <stdint.h>
#include <algorithm>
#include <iterator>
#include "address.h"
#include "exceptions.h"
#include "utils.h"
#include "check.h"
#include "enc.h"
#include "hash.h"
#include "ecc.h"

namespace bm {

Address::Address(uint64_t address_version_number, uint64_t stream_number, bool eighteen_byte_ripe)
{
    ECC sign_keys;
    SecureVector ripe;

    while(true)
    {
        ECC encrypt_keys;
        SecureVector key_merge;

        std::copy(sign_keys.public_key().begin(), sign_keys.public_key().end(), std::back_inserter(key_merge));
        std::copy(encrypt_keys.public_key().begin(), encrypt_keys.public_key().end(), std::back_inserter(key_merge));

        ripe = hash::ripemd160(hash::sha512(key_merge));

        if(eighteen_byte_ripe)
        {
            if(ripe[0] == 0x00 && ripe[1] == 0x00)
                break;
        }
        else
        {
            if(ripe[0] == 0x00)
                break;
        }
    }

    encode_address(address_version_number, stream_number, ripe);
}

std::ostream& operator << (std::ostream& out, const Address& address)
{
    out << "BM-"  << address.m_address;
    return out;
}

uint64_t Address::extract_stream_number(const std::string& address)
{
    if(!check::address(address))
        throw ParseException(__FILE__, __FUNCTION__, __LINE__, "Invalid address checksum");

    int nb;
    std::string addr = utils::remove_prefix(address, "BM-");
    SecureVector bytes = decode::base58(addr);

    decode::varint(bytes.data(), nb);
    return decode::varint(&bytes[nb], nb);
}

void Address::encode_address(uint64_t version, uint64_t stream, const SecureVector& ripe)
{
    if(ripe.size() != 20)
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "The ripe length is not 20");

    SecureVector ripex;

    if(ripe[0] == 0x00 && ripe[1] == 0x00)
        std::copy(ripe.begin() + 2, ripe.end(), std::back_inserter(ripex));
    else if(ripe[0] == 0x00)
        std::copy(ripe.begin() + 1, ripe.end(), std::back_inserter(ripex));
    else ripex = ripe;

    SecureVector bm_addr = encode::varint(version);
    bm_addr += encode::varint(stream);
    bm_addr += ripex;

    SecureVector checksum = hash::sha512(hash::sha512(bm_addr));
    std::copy(checksum.begin(), checksum.begin() + 4, std::back_inserter(bm_addr));

    m_address = encode::base58(bm_addr);
}

} // namespace bm
