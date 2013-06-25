#ifndef BITMESSAGE_H
#define BITMESSAGE_H

#include <string>
#include "utils.h"

//pubkey bitfield
#define BM_PUBKEY_DOES_ACK 31

// Message encodings
enum {
	BM_ENCODING_IGNORE = 0,
	BM_ENCODING_TRIVIAL,
	BM_ENCODING_SIMPLE
};

// Message header
struct bm_message_header_struct {
	unsigned int magic;
	char command[12];
	unsigned int length;
	unsigned int checksum;
};
typedef struct bm_message_header_struct bm_message_header;

// Network address
struct bm_net_addr_struct {
	unsigned int time;
	unsigned int stream;
	unsigned long long services;
	char IP_address[16];
	unsigned int port;
};
typedef struct bm_net_addr_struct bm_net_addr;

// Inventory vector element
struct bm_inventory_element_struct {
	char hash[32];
};
typedef struct bm_inventory_element_struct bm_inventory_element;

// Version request
struct bm_version_header_struct {
	int version;
	unsigned long long services;
	long long timestamp;
	bm_net_addr addr_recv;
	bm_net_addr addr_from;
	unsigned long long nonce;
};
typedef struct bm_version_header_struct bm_version_header;

class bitmessage
{
 protected:

    static ByteArray calculateInventoryHash(const ByteArray& data);
    static ByteArray getHashString512(const ByteArray& data);
    static unsigned long long getProofOfWorkTrialValue(unsigned long long nonce, const ByteArray& initialHash);

 public:

    template<class T>
    static std::string encodeVarint(T integer);

    static unsigned long long decodeVarint(const ByteArray& data, int &nbytes);

    static std::string proofOfWork(unsigned int streamNumber,
                              std::string embeddedTime,
                              std::string cyphertext,
							  unsigned int payloadLengthExtraBytes=14000,
							  unsigned int averageProofOfWorkNonceTrialsPerByte=320,
							  bool verbose=false);

    static bool checkProofOfWork(std::string payload,
								 unsigned int payloadLengthExtraBytes=14000,
								 unsigned int averageProofOfWorkNonceTrialsPerByte=320);
/*
    static string encodeAddress(unsigned int version, unsigned int streamNumber, string ripe);
    static void decodeAddress(string address,
							  string &status,
							  string &data,
							  unsigned int &version,
							  unsigned int &streamNumber);
*/
    static std::string addBMIfNotPresent(std::string address);

    static unsigned int addressStreamNumber(std::string address, std::string &status);
};

#endif
