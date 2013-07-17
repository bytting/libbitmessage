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

#include <memory>
#include <botan/alg_id.h>
#include <botan/ber_dec.h>
#include "ecc.h"
#include "utils.h"
#include "hash.h"
#include "encoding.h"

namespace bm {

ECC::ECC() : m_group("secp256k1"), m_key(0)
{
}

ECC::~ECC()
{
    clear();
}

void ECC::generate_key_pair()
{
    clear();
    m_key = new Botan::ECDSA_PrivateKey(utils::random_number_generator(), m_group);
    Botan::ECDSA_PublicKey pub(m_group, m_key->public_point());

    BigInteger bit = m_key->private_value();
    m_private_key_bytes.resize(bit.bytes());
    bit.binary_encode(m_private_key_bytes.data());

    Botan::PointGFp gfp = Botan::OS2ECP(m_key->x509_subject_public_key(), m_key->public_point().get_curve());
    bit = gfp.get_affine_y();
    m_public_key_bytes.resize(bit.bytes());
    bit.binary_encode(m_public_key_bytes.data());
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

void ECC::clear()
{
    if(m_key)
    {
        delete m_key;
        m_key = 0;
    }
}

uint16_t get_curve_id()
{
    return 714;
}

} // namespace bm
