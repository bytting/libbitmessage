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
#include "ecc.h"
#include "exceptions.h"
#include "utils.h"

using namespace Botan;

namespace bm {

ECC::ECC() : m_key(0)
{
}

ECC::~ECC()
{
    if(m_key)
    {
        delete m_key;
    }
}

void ECC::generate_keys()
{                
    EC_Group group("secp256k1");
    m_key = new ECDSA_PrivateKey(utils::random_number_generator() , group);
    m_private_key = m_key->pkcs8_private_key();
    m_public_key = m_key->x509_subject_public_key();
}

ByteVector ECC::get_public_key() const
{
    return m_public_key;
}

ByteVector ECC::get_private_key() const
{
    return m_private_key;
}

std::string ECC::get_public_key_pem_encoded() const
{
    return X509::PEM_encode(*m_key);
}

std::string ECC::get_private_key_pem_encoded() const
{
    return PKCS8::PEM_encode(*m_key);
}

std::string ECC::get_private_key_pem_encoded_encrypted(const std::string& password) const
{
    return PKCS8::PEM_encode(*m_key, utils::random_number_generator(), password.c_str());
}

uint16_t ECC::get_curve_id() const
{
    return 714;
}

/*
string ECC::get_pubkey()
{
	//High level function which returns :
	//curve(2) + len_of_pubkeyX(2) + pubkeyX + len_of_pubkeyY + pubkeyY
    string s = utils::pack<unsigned short>(curve_id);
    s += utils::pack<unsigned short>(public_key_x.length());
	s += public_key_x;
    s += utils::pack<unsigned short>(public_key_y.length());
	s += public_key_y;
	return s;
}

string ECC::get_privkey()
{
	// High level function which returns
	// curve(2) + len_of_privkey(2) + privkey
    string s = utils::pack<unsigned short>(curve_id);
    s += utils::pack<unsigned short>(private_key.length());
	s += private_key;
	return s;
}

int ECC::decode_pubkey(bytes data)
{
    int i = 0;
    curve_id = utils::unpack<unsigned short>(data[i]);
    i += 2;
    unsigned int tmplen = utils::unpack<unsigned short>(data[i]);
    i += 2;
    public_key_x = data.substr(i,tmplen);
    i += tmplen;
    tmplen = utils::unpack<unsigned short>(data.substr(i,2));
    i += 2;
    public_key_y = data.substr(i, tmplen);
    i += tmplen;
    return i;
}

int ECC::decode_privkey(string data)
{
    int i = 0;
    curve_id = utils::unpack<unsigned int>(data.substr(i,2));
    i += 2;
    unsigned int tmplen = utils::unpack<unsigned int>(data.substr(i,2));
    i += 2;
    private_key = data.substr(i,tmplen);
    i += tmplen;
    return i;
}
*/

} // namespace bm
