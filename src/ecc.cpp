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
#include <botan/ec_group.h>
#include <botan/alg_id.h>
//#include <botan/botan.h>
#include <botan/ecdsa.h>
#include "ecc.h"
#include "utils.h"
#include "hash.h"
#include "encoding.h"

#include <iostream> // FIXME

namespace bm {

namespace ecc {

void create_key_pair(private_key_type& privkey, public_key_type& pubkey)
{
    Botan::EC_Group group("secp256k1");
    Botan::ECDSA_PrivateKey key(utils::random_number_generator(), group);
    //privkey = Botan::PKCS8::BER_encode(key);
    //pubkey = Botan::X509::BER_encode(key);    
    privkey = key.pkcs8_private_key();
    pubkey = key.x509_subject_public_key();
}

std::string pem_encode_private_key_encrypted(const private_key_type& privkey, const std::string& password)
{
    Botan::DataSource_Memory mem(privkey);
    std::auto_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(mem, utils::random_number_generator(), password));
    return Botan::PKCS8::PEM_encode(*key);
}

std::string pem_encode_public_key(const public_key_type& pubkey)
{
    std::auto_ptr<Botan::Public_Key> key(Botan::X509::load_key(pubkey));
    return Botan::X509::PEM_encode(*key);
}

uint16_t get_curve_id()
{
    return 714;
}

} // namespace ecc

} // namespace bm
