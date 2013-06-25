#ifndef BM_ECC_H
#define BM_ECC_H

#include <cstdint>
#include <string>

const uint16_t Secp256K1 = 714;
const uint16_t Sect283r1 = 730;

class ECC
{
public:    

    //int decode_pubkey(bytes data);
    //int decode_privkey(bytes data);
    void generate_keys();
    void generate_keys_with_password(const std::string& password);
    //unsigned int get_curve_id();

    //std::string get_public_key();
    //std::string get_private_key();

private:

    std::string mPublicKey;
    std::string mPrivateKey;
    //unsigned int curve_id;
};

#endif
