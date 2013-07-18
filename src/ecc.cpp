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

#include <algorithm>
#include <iterator>
#include <memory>
#include <botan/alg_id.h>
#include <botan/ber_dec.h>
#include "ecc.h"
#include "utils.h"
#include "hash.h"
#include "encode.h"
#include "decode.h"

namespace bm {

ECC::ECC() : m_group("secp256k1"), m_key(0)
{
    initialize_keys((BigInteger)0);
}

ECC::ECC(const SecureVector& key_bytes) : m_group("secp256k1"), m_key(0)
{
    BigInteger ikey(key_bytes.data(), key_bytes.size());
    initialize_keys(ikey);
}

ECC::ECC(const std::string& key_hex) : m_group("secp256k1"), m_key(0)
{
    SecureVector key_bytes = decode::hex(key_hex);
    BigInteger ikey(key_bytes.data(), key_bytes.size());
    initialize_keys(ikey);
}

ECC::~ECC()
{
    if(m_key)
        delete m_key;
}

const SecureVector& ECC::private_key() const
{
    return m_private_key_bytes;
}

const ByteVector& ECC::public_key() const
{
    return m_public_key_bytes;
}

SecureVector ECC::PKCS8_BER()
{
    return Botan::PKCS8::BER_encode(*m_key);
}

std::string ECC::PKCS8_PEM()
{
    return Botan::PKCS8::PEM_encode(*m_key);
}

std::string ECC::PKCS8_PEM(const std::string& password)
{
    return Botan::PKCS8::PEM_encode(*m_key, utils::random_number_generator(), password);
}

ByteVector ECC::X509_BER()
{
    return Botan::X509::BER_encode(*m_key);
}

std::string ECC::X509_PEM()
{
    return Botan::X509::PEM_encode(*m_key);
}

uint16_t ECC::get_curve_id()
{
    return 714; // secp256k1
}

void ECC::reset()
{
    if(m_key)
    {
        delete m_key;
        m_key = 0;
    }

    m_private_key_bytes.clear();
    m_public_key_bytes.clear();
}

void ECC::initialize_keys(const BigInteger& ikey)
{
    reset();

    m_key = new Botan::ECDSA_PrivateKey(utils::random_number_generator(), m_group, ikey);

    BigInteger bi = m_key->private_value();
    m_private_key_bytes.resize(bi.bytes());
    bi.binary_encode(m_private_key_bytes.data());

    m_public_key_bytes.push_back(0x04);

    bi = m_key->public_point().get_affine_x();
    ByteVector pub(bi.bytes());
    bi.binary_encode(pub.data());
    std::copy(pub.begin(), pub.end(), std::back_inserter(m_public_key_bytes));

    pub.clear();
    bi = m_key->public_point().get_affine_y();
    pub.resize(bi.bytes());
    bi.binary_encode(pub.data());
    std::copy(pub.begin(), pub.end(), std::back_inserter(m_public_key_bytes));
}

} // namespace bm
