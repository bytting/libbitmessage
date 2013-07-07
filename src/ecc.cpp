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

#include <botan/ec_group.h>
#include <botan/alg_id.h>
#include "ecc.h"
#include "utils.h"

#include <iostream> // FIXME

namespace bm {

ecc_type::ecc_type() : ecc_type((big_integer_type)0)
{
}

ecc_type::ecc_type(const big_integer_type& value) : m_key(0)
{
    Botan::EC_Group group("secp256k1");
    m_key = new Botan::ECDSA_PrivateKey(utils::random_number_generator(), group, value);
    m_private_key = m_key->pkcs8_private_key();
    m_public_key = m_key->x509_subject_public_key();
}
/*
ecc_type::ecc_type(const std::string& wif) : m_key(0)
{        
    byte_vector_type extended = utils::decode_base58v(wif);
    byte_vector_type checksum(&extended[extended.size() - 4], 4);
    byte_vector_type key(&extended[1], extended.size() - 1 - 4);

    // FIXME: Validate key        

    Botan::DataSource_Memory ds(&key[0], key.size());
    m_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(Botan::PKCS8::load_key(ds, utils::random_number_generator(), ""));

    m_private_key = m_key->pkcs8_private_key();
    m_public_key = m_key->x509_subject_public_key();
}
*/
ecc_type::~ecc_type()
{
    if(m_key)    
        delete m_key;    
}
/*
std::string ecc_type::get_wallet_import_format() const
{    
    byte_vector_type extended;
    extended.resize(m_private_key.size() + 1 + 4); // make room for 0x80 byte and the checksum
    extended.copy(1, m_private_key, m_private_key.size());
    extended[0] = 0x80;

    byte_vector_type sha = hash::sha256(hash::sha256(extended));

    byte_vector_type checksum(&sha[0], 4);
    extended.copy(1 + m_private_key.size(), &checksum[0], 4);    

    big_integer_type bit(&extended[0], extended.size());    
    return utils::encode_base58(bit);
}
*/
byte_vector_type ecc_type::get_public_key() const
{
    return m_public_key;
}

byte_vector_type ecc_type::get_private_key() const
{
    return m_private_key;
}

big_integer_type ecc_type::get_private_value() const
{
    return m_key->private_value();
}

std::string ecc_type::get_public_key_pem() const
{
    return Botan::X509::PEM_encode(*m_key);
}

std::string ecc_type::get_private_key_pem() const
{
    return Botan::PKCS8::PEM_encode(*m_key);
}

std::string ecc_type::get_private_key_pem_encrypted(const std::string& password) const
{
    return Botan::PKCS8::PEM_encode(*m_key, utils::random_number_generator(), password.c_str());
}

uint16_t ecc_type::get_curve_id() const
{
    return 714;
}

} // namespace bm
