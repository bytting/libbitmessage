//#include <stdio.h>
//#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <assert.h>
#include <ctime>
#include <botan/botan.h>
#include <botan/rng.h>
#include "utils.h"
#include "ecc.h"
#include "hashes.h"
#include "address.h"
#include "bitmessage.h"
#include "unittests.h"

using namespace std;

static void test_ecc_keys()
{
    cout << "\n=== TEST ECC ===\n";
    cout << "\n=== Using password...\n";
    bm::ECC ecc;
    ecc.generate_keys_with_password("qwerty");
    cout << ecc.get_private_key() << "\n" << ecc.get_public_key();
    cout << "\n=== Without password...\n";
    ecc.generate_keys();
    cout << ecc.get_private_key() << "\n" << ecc.get_public_key();
    cout << "\n=== TEST ECC OK ===" << endl;
}

static void test_ripemd160()
{
    cout << "\n=== TEST RIPEMD160 ===\n";
    string str = "This is a string"; // 291850ad6a9a191487f01b5fbe19c215de1a5d67
    bm::ByteVector v1 = bm::ripemd160(str);
    bm::ByteVector v2 = bm::ripemd160(str);
    assert(v1.size() == 20);
    assert(v1 == v2);
    assert(v1[0] == 0x29);
    assert(v1[19] == 0x67);
    cout << "\n=== TEST RIPEMD160 OK ===" << endl;
}

static void test_sha256()
{
    cout << "\n=== TEST SHA256 ===\n";
    string str = "This is a string"; // 4E9518575422C9087396887CE20477AB5F550A4AA3D161C5C22A996B0ABB8B35
    bm::ByteVector v1 = bm::sha256(str);
    bm::ByteVector v2 = bm::sha256(str);
    assert(v1.size() == 32);
    assert(v1 == v2);
    assert(v1[0] == 0x4E);    
    assert(v1[31] == 0x35);
    cout << "\n=== TEST SHA256 OK ===" << endl;
}

static void test_sha512()
{
    cout << "\n=== TEST SHA512 ===\n";
    string str = "This is a string"; // F4D54D32E3523357FF023903EABA2721E8C8CFC7702663782CB3E52FAF2C56C002CC3096B5F2B6DF870BE665D0040E9963590EB02D03D166E52999CD1C430DB1
    bm::ByteVector v1 = bm::sha512(str);
    bm::ByteVector v2 = bm::sha512(str);
    assert(v1.size() == 64);
    assert(v1 == v2);
    assert(v1[0] == 0xF4);    
    assert(v1[63] == 0xB1);
    cout << "\n=== TEST SHA512 OK ===\n" << endl;
}

static void test_hmac_sha256()
{
    cout << "\n=== TEST HMAC_SHA256 ===\n";
    Botan::AutoSeeded_RNG rng;
    bm::ByteVector key = rng.random_vec(32);
    bm::ByteVector data = rng.random_vec(1024);
    bm::ByteVector mac = bm::hmac_sha256(data, key); // FIXME: Make a _real_ test
    bm::OctetVector ostr(mac);
    cout << ostr.as_string() << endl;
    // FIXME: Sanity checks
    cout << "\n=== TEST HMAC_SHA256 OK ===\n" << endl;
}

static void test_hmac_sha512()
{
    cout << "\n=== TEST HMAC_SHA512 ===\n";
    Botan::AutoSeeded_RNG rng;
    bm::ByteVector key = rng.random_vec(32);
    bm::ByteVector data = rng.random_vec(1024);
    bm::ByteVector mac = bm::hmac_sha512(data, key); // FIXME: Make a _real_ test
    bm::OctetVector ostr(mac);
    cout << ostr.as_string() << endl;
    // FIXME: Sanity checks
    cout << "\n=== TEST HMAC_SHA512 OK ===\n" << endl;
}

static void test_encode_varint()
{
    cout << "\n=== TEST ENCODE VARINT ===\n";
    uint64_t integer = 123;
    cout << "123: " << bm::utils::encode_hex(bm::utils::encode_varint(integer)) << "\n";
    integer = 1234;
    cout << "1234: " << bm::utils::encode_hex(bm::utils::encode_varint(integer)) << "\n";
    integer = 66666;
    cout << "66666: " << bm::utils::encode_hex(bm::utils::encode_varint(integer)) << "\n";
    integer = 4595967296;
    cout << "4595967296: " << bm::utils::encode_hex(bm::utils::encode_varint(integer)) << "\n";
    // FIXME: Sanity checks
    cout << "\n=== TEST ENCODE VARINT OK ===\n" << endl;
}

static void test_addresses()
{
    cout << "\n=== TEST ADDRESSES ===\n";
    std::string addr = bm::create_random_address();
    cout << "Address: " << addr;
    // FIXME: Sanity checks
    cout << "\n=== TEST ADDRESSES OK ===\n" << endl;
}

void run_unit_tests()
{
    test_ecc_keys();
    test_ripemd160();
    test_sha256();
    test_sha512();
    test_hmac_sha256();
    test_hmac_sha512();
    test_encode_varint();
    test_addresses();
}
