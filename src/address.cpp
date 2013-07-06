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

#include "address.h"
#include "exceptions.h"
#include "utils.h"
#include "hashes.h"
#include "ecc.h"

namespace bm {

void Address::generate_address()
{
    // FIXME: set these correctly
    bool eighteen_byte_ripe = false;
    uint64_t address_version = 3, stream = 1;

    ECC signing_keys;
    byte_vector_type ripe;

    while(true)
    {
        ECC encryption_keys;        

        byte_vector_type sha = hash::sha512(encryption_keys.get_private_key());
        ripe = hash::ripemd160(sha);

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

void Address::encode(uint64_t version, uint64_t stream, const byte_vector_type& ripe)
{
    if(ripe.size() != 20)
        throw SizeException(__FILE__, __LINE__, "create_random_address: The ripe length is not 20");

    byte_vector_type r = ripe;
    if(r[0] == 0x00 && r[1] == 0x00)
    {
        byte_vector_type tmp(&r[2], r.size() - 2);
        r = tmp;
    }
    else if(r[0] == 0x00)
    {
        byte_vector_type tmp(&r[1], r.size() - 1);
        r = tmp;
    }

    byte_vector_type v = utils::serialize_varint(version);
    v += utils::serialize_varint(stream);
    v += r;

    byte_vector_type sha1 = hash::sha512(v);
    byte_vector_type sha2 = hash::sha512(sha1);
    byte_vector_type checksum(&sha2[0], 4);

    v += checksum;
    big_integer_type bi(&v[0], v.size());
    m_address = utils::encode_base58(bi);
}

} // namespace bm
