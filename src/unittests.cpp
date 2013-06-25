#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
//#include <gmp.h>
#include "utils.h"
#include "bitmessage.h"
#include "unittests.h"

static void test_sha512()
{
	char result[129];
	int retval=-1;

	printf("test_sha512...");

	bm_sha512((char*)"hello",result, 1);	
	retval =
		strncmp(result,
				"9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caa" \
				"dae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8" \
				"c5da0c4663475c2e5c3adef46f73bcdec043",128);
	if (retval != 0) {
		printf("Target:\n9b71d224bd62f3785d96d46ad3ea3d73319bfb" \
			   "c2890caadae2dff72519673ca72323c3d99ba5c11d7c7ac" \
			   "c6e14b8c5da0c4663475c2e5c3adef46f73bcdec043\n");
		printf("Actual:\n%s\n", (char*)result);
	}
	assert(retval == 0);

	printf("Ok\n");
}

static void test_double_sha512()
{
	char result[129];
	int retval=-1;

	printf("test_double_sha512...");

	bm_doubleSha512((char*)"hello",result, 1);	
	retval =
		strncmp(result,
				"0592a10584ffabf96539f3d780d776828c67da1ab5b169" \
				"e9e8aed838aaecc9ed36d49ff1423c55f019e050c66c63" \
				"24f53588be88894fef4dcffdb74b98e2b200", 128);
	if (retval != 0) {
		printf("Target:\n0592a10584ffabf96539f3d780d776828c67da" \
			   "1ab5b169e9e8aed838aaecc9ed36d49ff1423c55f019e05" \
			   "0c66c6324f53588be88894fef4dcffdb74b98e2b200\n");
		printf("Actual:\n%s\n", (char*)result);
	}
	assert(retval == 0);

	printf("Ok\n");
}

static void test_ripemd160()
{
	char result1[129],result2[41];
	int retval=-1;

	printf("test_ripemd160...");

	bm_sha512((char*)"hello",result1, 0);
	bm_ripemd160((char*)result1, result2, 1);
	retval =
		strncmp(result2,"79a324faeebcbf9849f310545ed531556882487e",40);
	if (retval != 0) {
		printf("Target:\n79a324faeebcbf9849f310545ed531556882487e\n");
		printf("Actual:\n%s\n", (char*)result2);
	}
	assert(retval == 0);

	printf("Ok\n");
}

static void test_pack()
{	
	string packed;
	unsigned long long v;

	printf("test_pack...");

    packed = utils::pack<unsigned char>((unsigned char)'j');
	assert(packed.length()==sizeof(unsigned char));
	assert(packed.substr(0,1).c_str()[0]=='j');

    packed = utils::pack<unsigned short>((unsigned short)1234);
    assert(packed.length()==sizeof(unsigned short));
    v = utils::unpack<unsigned short>(packed);
    assert(v == 1234);

    packed = utils::pack<unsigned int>((unsigned int)12345);
	assert(packed.length()==sizeof(unsigned int));
    v = utils::unpack<unsigned int>(packed);
	assert(v == 12345);

    packed = utils::pack<unsigned long long>((unsigned long long)1234567);
	assert(packed.length()==sizeof(unsigned long long));
    v = utils::unpack<unsigned long long>(packed);
	assert(v == 1234567);

	printf("Ok\n");
}

static void test_encodeVarint()
{
	string result;
	unsigned char firstByte;
	unsigned short vshort;
	unsigned int vint;
	unsigned long long vlong;
	int nbytes=0;

	printf("test_encodeVarint...");

	for (unsigned long long i = 0; i < 99999; i++) {
		result = bitmessage::encodeVarint(i);
		unsigned long long i2 = bitmessage::decodeVarint(result, &nbytes);
		if (i != i2) {
			printf("%lld %lld\n",i,i2);
		}
		assert(i==i2);
	}

	result = bitmessage::encodeVarint((unsigned char)123);
	assert(result.length() == 1);

	result = bitmessage::encodeVarint((unsigned short)1234);
	assert(result.length() == 3);
	assert(result.substr(0,1).c_str()[0] == (char)253);
	memcpy((void*)&vshort,(void*)result.substr(1,2).c_str(),2);
	assert(vshort == 1234);

	result = bitmessage::encodeVarint((unsigned int)68541);
	assert(result.length() == 5);
	assert(result.substr(0,1).c_str()[0] == (char)254);
	memcpy((void*)&vint,(void*)result.substr(1,4).c_str(),4);
	assert(vint == 68541);

	result = bitmessage::encodeVarint((unsigned long long)5294967296);
	assert(result.length() == 9);
	assert(result.substr(0,1).c_str()[0] == (char)255);
	memcpy((void*)&vlong,(void*)result.substr(1,8).c_str(),8);
	assert(vlong == 5294967296);

	printf("Ok\n");
}

static void test_proofOfWork()
{
	string payload;
	string embeddedTime = "1/2/3";
	string cyphertext = "This is a test";
	unsigned int payloadLengthExtraBytes=14000;
	unsigned int averageProofOfWorkNonceTrialsPerByte=320;
	clock_t begin_time, end_time;

	printf("test_proofOfWork...");

	begin_time = clock();
	payload = bitmessage::proofOfWork(1, embeddedTime,
									  cyphertext,
									  payloadLengthExtraBytes,
									  averageProofOfWorkNonceTrialsPerByte,
									  false);
	end_time = clock();
	int seconds = (int)((end_time-begin_time)/CLOCKS_PER_SEC);
	assert(seconds < 30);

    // proof of work should be correct
	assert(bitmessage::checkProofOfWork(payload,
										payloadLengthExtraBytes,
										averageProofOfWorkNonceTrialsPerByte));

	// if the proof of work is not correct
	unsigned long long real_nonce = 0;
	memcpy((void*)&real_nonce,(void*)payload.c_str(),8);
	char str[8];
	string s;
	string message_payload = payload.substr(8);
	for (unsigned long long bogus_nonce = 0; bogus_nonce < 100; bogus_nonce++) {
		if (real_nonce == bogus_nonce) break;
		memcpy((void*)str,(void*)&bogus_nonce,8);
		s = "";
		for (int i = 0; i < 8; i++) {
			s += str[i];
		}
		// the check should return false
		assert(!bitmessage::checkProofOfWork(s + message_payload,
											 payloadLengthExtraBytes,
											 averageProofOfWorkNonceTrialsPerByte));
	}
	
	printf("Ok\n");
}

static void test_base58()
{
	printf("test_base58...");

	for (unsigned int num = 0; num < 10000; num++) {
		string encoded = utils::encodeBase58(num);
		unsigned int decoded = utils::decodeBase58(encoded);
		assert(decoded == num);
	}

	printf("Ok\n");
}

static void test_address_encoding()
{
	printf("test_address_encoding...");

	string data = "01234567890123456789";

	for (unsigned int version = 2; version <=2; version++) {
		for (unsigned int streamNumber = 1; streamNumber < 300; streamNumber++) {
			string encoded = bitmessage::encodeAddress(version, streamNumber, data);

			assert(encoded.length() > 10);
			assert(encoded.substr(0,3)=="BM-");

			string decoded_status="";
			string decoded_data="";
			unsigned int decoded_version=0;
			unsigned int decoded_streamNumber=0;
			bitmessage::decodeAddress(encoded,
									  decoded_status,
									  decoded_data,
									  decoded_version,
									  decoded_streamNumber);
			if (decoded_status != "success") {
				printf("\nVersion %d   Stream %d\n", version, streamNumber);
				printf("Decode failed with status: %s\n",decoded_status.c_str());
			}
			assert(decoded_status == "success");
			if (decoded_version != version) {
				printf("\nVersion %d -> %d\n", version, decoded_version);
			}
			assert(decoded_version == version);
			if (decoded_streamNumber != streamNumber) {
				printf("\nstreamNumber %d -> %d\n", streamNumber, decoded_streamNumber);
			}
			assert(decoded_streamNumber == streamNumber);
		}
	}
	printf("Ok\n");
}

static void test_hex()
{
	printf("test_hex...");
	
	string original = "78910abcdefghijk";
	string encoded = utils::encodeHex(original);
	string decoded = utils::decodeHex(encoded);
	if (decoded != original) {
		printf("\nString\n  original %s\n  encoded %s\n  decoded %s\n",
			   original.c_str(), encoded.c_str(), decoded.c_str());
	}
	assert(encoded != decoded);
	assert(decoded == original);

	unsigned int num = 4539261;
	unsigned int decodedInt;
	encoded = utils::encodeHex(num);
	decodedInt = utils::decodeHexInt(encoded);
	if (decodedInt != num) {
		printf("\nInteger\n  num %d\n  encoded %s\n  decoded %d\n", num, encoded.c_str(), decodedInt);
	}
	assert(decodedInt == num);

	mpz_t decodedIntBig, numBig;
	mpz_init(decodedIntBig);
	mpz_init(numBig);
	string numStr = "12345677893347733782276";
	mpz_set_str(numBig,numStr.c_str(),10);
	encoded = utils::encodeHex(numBig);
	utils::decodeHexInt(encoded, decodedIntBig);
	char decodedStr[256];
	mpz_get_str(decodedStr,10,decodedIntBig);
	assert(strcmp(decodedStr,numStr.c_str())==0);

	printf("Ok\n");
}

static void test_extract_stream_number()
{
	printf("test_extract_stream_number...");

	string data = "01234567890123456789";
	string status="";

    for (unsigned int version = 2; version <= 2; version++) {
        for (unsigned int streamNumber = 1; streamNumber < 300; streamNumber++) {

            string encoded = bitmessage::encodeAddress(version, streamNumber, data);

            assert(encoded.length() > 10);

            unsigned int decoded_streamNumber = bitmessage::addressStreamNumber(encoded, status);
            if (decoded_streamNumber != streamNumber) {
                printf("\n%d %d\n",streamNumber,decoded_streamNumber);
            }
            assert(decoded_streamNumber == streamNumber);

            if (status != "success") {
                printf("\nVersion %d   Stream %d\n", version, streamNumber);
                printf("Decode failed with status: %s\n",status.c_str());
            }
            assert(status == "success");
        }
	}

	printf("Ok\n");
}

void bm_run_unit_tests()
{
	test_hex();
	test_sha512();
	test_double_sha512();
	test_ripemd160();
	test_pack();
	test_encodeVarint();
	test_base58();
	test_address_encoding();
    test_extract_stream_number();
	test_proofOfWork();    
}
