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
#include "address.h"
#include "exceptions.h"
#include "encoding.h"
#include "hash.h"
#include "ecc.h"

namespace bm {

void address_type::generate_address()
{
    // FIXME: set these correctly
    bool eighteen_byte_ripe = false;
    uint64_t address_version = 3, stream = 1;

    ECC sign_keys, encrypt_keys;
    sign_keys.generate_key_pair();

    byte_vector_type ripe;

    while(true)
    {        
        encrypt_keys.generate_key_pair();

        ripe = hash::ripemd160(hash::sha512(encrypt_keys.public_key()));

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

    // FIXME: Only address version 3
    encode(address_version, stream, ripe);
}

std::string address_type::get_address() const
{
    return m_address;
}

std::string address_type::get_address_with_prefix() const
{
    return "BM-" + m_address;
}

void address_type::encode(uint64_t version, uint64_t stream, const byte_vector_type& ripe)
{
    if(ripe.size() != 20)
        throw size_exception(__FILE__, __LINE__, "address_type::encode: The ripe length is not 20");

    byte_vector_type ripex;

    if(ripe[0] == 0x00 && ripe[1] == 0x00)
        std::copy(ripe.begin() + 2, ripe.end(), std::back_inserter(ripex));
    else if(ripe[0] == 0x00)
        std::copy(ripe.begin() + 1, ripe.end(), std::back_inserter(ripex));
    else ripex = ripe;

    byte_vector_type bm_addr = encode::varint(version);
    bm_addr += encode::varint(stream);
    bm_addr += ripex;

    byte_vector_type checksum = hash::sha512(hash::sha512(bm_addr));
    std::copy(checksum.begin(), checksum.begin() + 4, std::back_inserter(bm_addr));

    m_address = encode::base58(bm_addr);
}

} // namespace bm
