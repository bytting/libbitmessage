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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
//#include <sstream>
//#include <iostream>
#include "exceptions.h"
#include "hashes.h"
#include "ecc.h"
#include "bitmessage.h"

namespace bm {
/*
void decodeAddress(string address,
        string &status,
        string &data,
        uint32_t &version,
        uint32_t &streamNumber)
{
    //returns (status, address version number, stream number, data (almost certainly a ripe hash))
	mpz_t integer;

	data = "";
	version = 0;
	streamNumber = 0;

	if (address.length()<20) {
		printf("Address too short %s\n",address.c_str());
		status = "addresstooshort";
		return;
	}

    if (address.substr(0,3) == "BM-") {
        utils::decodeBase58(address.substr(3), integer);
	}
    else {
        utils::decodeBase58(address, integer);
	}

    if (mpz_cmp_ui(integer,(unsigned int)0) == 0) {
        status = "invalidcharacters";
        return;
	}

    // after converting to hex, the string will be prepended with a 0x and appended with a L
	string hexdata = utils::encodeHex(integer);

	if (hexdata.length() % 2 != 0) {
		hexdata = "0" + hexdata;
	}

    //print 'hexdata', hexdata
	data = utils::decodeHex(hexdata);
	if (data.length() <= 20) {
		printf("address: %s\n",address.c_str());
		printf("decodeAddress: data length too short %d/20 hex %d\n",(int)data.length(),(int)hexdata.length());
		return;
	}
    string checksum = data.substr(data.length()-4);
	string currentHash = getHashString512(data.substr(0,data.length()-4));
	string sha = getHashString512(currentHash);

    if (checksum != sha.substr(0,4)) {
        status = "checksumfailed";
        return;
	}

	int bytesUsedByVersionNumber=0;
    version = (unsigned int)decodeVarint(data.substr(0,9), &bytesUsedByVersionNumber);

	//printf("addressVersionNumber %d\n", addressVersionNumber);
	//printf("bytesUsedByVersionNumber %d\n", bytesUsedByVersionNumber);

    if (version > 2) {
        printf("cannot decode address version numbers this high\n");
        status = "versiontoohigh";
        return;
	}
    else {
		if (version == 0) {
			printf("cannot decode address version numbers of zero.\n");
			status = "versiontoohigh\n";
			return;
		}
	}

	int bytesUsedByStreamNumber = 0;
    streamNumber = (unsigned int)decodeVarint(data.substr(bytesUsedByVersionNumber),&bytesUsedByStreamNumber);
    status = "success";
    if (version == 1) {
		data = data.substr(data.length()-24,20);
        return;
	}
    else {
		if (version == 2) {
			string temp_str =
				data.substr(bytesUsedByVersionNumber + bytesUsedByStreamNumber,
							data.length() - (4 + bytesUsedByVersionNumber + bytesUsedByStreamNumber));
			//printf("bytesUsedByStreamNumber %d\n",bytesUsedByStreamNumber);
			//printf("data.length() %d\n",(int)data.length());
			//printf("temp_str.length() %d\n",(int)temp_str.length());
			if (temp_str.length() == 19) {
				data = "\x00" + temp_str;
				return;
			}
			else if (temp_str.length() == 20) {
				data = temp_str;
				return;
			}
			else if (temp_str.length() == 18) {
				data = "\x00\x00" + temp_str;
				return;
			}
			else if (temp_str.length() < 18) {
				status = "ripetooshort";
				return;
			}
			else if (temp_str.length() > 20) {
				status = "ripetooshort";
				return;
			}
			else {
				status = "otherproblem";
			}
		}
	}
}
*/

ByteVector calculateInventoryHash(const ByteVector& data)
{    
    ByteVector sha1 = sha512(data);
    ByteVector sha2 = sha512(sha1);
    if(sha2.size() < 32)
        throw RangeException(__FILE__, __LINE__, "calculateInventoryHash: Hash size is less than 32");
    return ByteVector(&sha2[0], 32);
}

/*
uint64_t Bitmessage::getProofOfWorkTrialValue(unsigned long long nonce, string initialHash)
{
	char str[129];
    string nonce_hash = utils::pack<unsigned long long>(nonce) + initialHash;
	bm_doubleSha512((char*)nonce_hash.c_str(), str, HASH_DIGEST);
	// take the last 8 bytes of the hash
	string lastBytes = "";
	for (int i = 0; i < 8; i++) {
		lastBytes += str[SHA512_DIGEST_LENGTH-8+i];
	}
    return utils::unpack<unsigned long long>(lastBytes);
}

string proofOfWork(
        uint32_t streamNumber,
        string embeddedTime,
        string cyphertext,
        uint32_t payloadLengthExtraBytes,
        uint32_t averageProofOfWorkNonceTrialsPerByte,
        bool verbose)
{
    uint64_t nonce = 0;
	// the maximum 64bit value
    uint64_t trialValue = 18446744073709551615ULL;
    uint64_t target;
	clock_t begin_time, end_time;
	char str[129];
	string lastBytes;
	string encodedStreamNumber = encodeVarint(streamNumber);
	string payload = embeddedTime + encodedStreamNumber + cyphertext;

	target = 18446744073709551615ULL /
		((8+payload.length()+payloadLengthExtraBytes) *
		 averageProofOfWorkNonceTrialsPerByte);

	if (verbose) {
		printf("(For msg message) Doing proof of work. Target: %lld\n",target);
	}

	begin_time = clock();
	string initialHash = getHashString512(payload);
    uint64_t best = 0;
	while (trialValue > target) {
		if (nonce == 0) {
			nonce = 1;
		}
		else {
			nonce += 32;
		}
#pragma omp parallel for
        for (uint64_t index = 0; index < 4; index++) {
            uint64_t n = getProofOfWorkTrialValue(nonce + index, initialHash);
			if (n <= target) {
				trialValue = n;
				best = nonce + index;
			}
		}
    }
	nonce = best;
	end_time = clock();
	
	if (verbose) {
		printf("(For msg message) Found proof of work %lld", trialValue);
		printf(" Nonce: %lld\n", nonce);
		
		if (end_time>begin_time) {
			printf("POW took %d seconds.  ",
				   (int)((end_time-begin_time)/CLOCKS_PER_SEC));
			printf("%lld nonce trials per second.\n",
				   nonce / (unsigned long long)((end_time-begin_time)/CLOCKS_PER_SEC));
		}
	}
	// prepend the nonce value.  This can then be used by the receiver to check that the payload is valid
    payload = utils::pack<unsigned long long>(nonce) + payload;
	return payload;
}

bool checkProofOfWork(
        string payload,
        uint32_t payloadLengthExtraBytes,
        uint32_t averageProofOfWorkNonceTrialsPerByte)
{
	if (payload.length() <= 8) return false;

	const char * payload_str = payload.c_str();
	char * message_payload = (char*)&payload_str[8];
	unsigned long long nonce;

	// extract the nonce value from the first 8 bytes
	memcpy((void*)&nonce,(void*)payload_str,8);

	unsigned long long target = 18446744073709551615ULL /
		((payload.length()+payloadLengthExtraBytes) *
		 averageProofOfWorkNonceTrialsPerByte);

	string initialHash = getHashString512(message_payload);
	return (getProofOfWorkTrialValue(nonce, initialHash) <= target);
}

// returns the stream number of an address or False if there is a problem with the address.
unsigned int addressStreamNumber(string address, string &status)
{
    // check for the BM- at the front of the address. If it isn't there, this address might be for a different version of Bitmessage
	if (address.substr(0,3) != "BM-") {
        status = "missingbm";
		return 0;
	}

    // here we take off the BM-
    mpz_t integer;
	utils::decodeBase58(address.substr(3), integer);

    // after converting to hex, the string will be prepended with a 0x and appended with a L
	string hexdata = utils::encodeHex(integer);

    if (hexdata.length() % 2 != 0) {
        hexdata = "0" + hexdata;
	}

    // print 'hexdata', hexdata

	string data = utils::decodeHex(hexdata);
	if (data.length() <= 4) {
		printf("WARNING: data length too short\n");
		return 0;
	}
    string checksum = data.substr(data.length()-4);
	string currentHash = getHashString512(data.substr(0,data.length()-4));
	string sha = getHashString512(currentHash);

    if (checksum != sha.substr(0,4)) {
        status = "checksumfailed";
        return 0;
	}

	int bytesUsedByVersionNumber=0;
	unsigned int version = (unsigned int)decodeVarint(data.substr(0,9), &bytesUsedByVersionNumber);

	if (version < 1) {
		printf("cannot decode version address version numbers this high\n");
		status = "versiontoohigh";
		return 0;
	}

	int bytesUsedByStreamNumber=0;
	unsigned int streamNumber =
		(unsigned int)decodeVarint(data.substr(bytesUsedByVersionNumber,9+bytesUsedByVersionNumber),
								   &bytesUsedByStreamNumber);

    status = "success";
    return streamNumber;
}
*/

} // namespace bm
