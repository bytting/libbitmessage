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

#include <botan/botan.h>
#include <botan/ecdh.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/rng.h>
 #include <botan/oids.h>
#include <botan/gost_3410.h>
#include "ecc.h"
//#include "utils.h"
//#include "hashes.h"

using namespace Botan;

namespace bm {

/*
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
void ECC::generateKeys()
{        
    AutoSeeded_RNG rng;
    //EC_Group ecGroup("secp256k1");
    EC_Group ecGroup("secp256r1");
    ECDSA_PrivateKey key(rng, ecGroup);
    mPublicKey = X509::PEM_encode(key);
    mPrivateKey = PKCS8::PEM_encode(key);
}

void ECC::generateKeysWithPassword(const std::string& password)
{
    AutoSeeded_RNG rng;
    EC_Group group("secp256r1");
    ECDSA_PrivateKey key(rng, group);
    mPublicKey = X509::PEM_encode(key);
    mPrivateKey = PKCS8::PEM_encode(key, rng, password.c_str());
}

/*
unsigned int ECC::get_curve_id()
{
	return curve_id;
}

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
*/

} // namespace bm
