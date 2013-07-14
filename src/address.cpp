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

    ecc::private_key_type private_signing_key;
    ecc::public_key_type public_signing_key;
    ecc::create_key_pair(private_signing_key, public_signing_key);

    byte_vector_type ripe;

    while(true)
    {
        ecc::private_key_type private_encryption_key;
        ecc::public_key_type public_encryption_key;
        ecc::create_key_pair(private_encryption_key, public_encryption_key);

        ripe = hash::ripemd160(hash::sha512(public_encryption_key));

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

    byte_vector_type r = ripe;

    if(r[0] == 0x00 && r[1] == 0x00)
        r.assign(ripe.begin() + 2, ripe.end());
    else if(r[0] == 0x00)    
        r.assign(ripe.begin() + 1, ripe.end());

    byte_vector_type v = encode::varint(version);
    v += encode::varint(stream);
    v += r;

    byte_vector_type sha = hash::sha512(hash::sha512(v));    
    byte_vector_type checksum;
    checksum.assign(sha.begin(), sha.begin() + 4);

    v += checksum;    
    m_address = encode::base58(v);
}

} // namespace bm
