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

#ifndef BM_ECC_H
#define BM_ECC_H

#include <vector>
#include <string>
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include "btypes.h"

namespace bm {

class ECC
{        
public:

    ECC();
    ECC(const big_integer_type& value);
    ECC(const std::string& wif);
    ~ECC();    

    std::string get_wallet_import_format() const;

    byte_vector_type get_public_key() const;
    byte_vector_type get_private_key() const;
    big_integer_type get_private_value() const { return m_key->private_value(); }

    std::string get_public_key_pem_encoded() const;
    std::string get_private_key_pem_encoded() const;
    std::string get_private_key_pem_encoded_encrypted(const std::string& password) const;

    uint16_t get_curve_id() const;

private:    

    Botan::ECDSA_PrivateKey* m_key;
    byte_vector_type m_public_key;
    byte_vector_type m_private_key;

    // secp224r1 : 713
    // secp256k1 : 714
    // sect283r1 : 730
};

} // namespace bm

#endif
