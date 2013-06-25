#include <botan/botan.h>
#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/rng.h>
#include "ecc.h"
//#include "utils.h"
//#include "hashes.h"

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
int ECC::generate_keys()
{
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group group("secp256r1");
    Botan::ECDH_PrivateKey key(rng, group);
    mPublicKey = Botan::X509::PEM_encode(key);
    mPrivateKey = Botan::PKCS8::PEM_encode(key);
}

int ECC::generate_keys_with_password(const std::string& password)
{
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group group("secp256r1");
    Botan::ECDH_PrivateKey key(rng, group);
    mPublicKey = Botan::X509::PEM_encode(key);
    mPrivateKey = Botan::PKCS8::PEM_encode(key, rng, password.c_str());
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
