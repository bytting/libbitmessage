#ifndef BITMESSAGE_H
#define BITMESSAGE_H

#include <cstdint>
#include <string>
#include "utils.h"

//pubkey bitfield
//#define BM_PUBKEY_DOES_ACK 31 // FIXME

// Message encodings
enum {
	BM_ENCODING_IGNORE = 0,
	BM_ENCODING_TRIVIAL,
	BM_ENCODING_SIMPLE
};

// Message header
struct bm_message_header_struct {
    uint32_t magic;
	char command[12];
    uint32_t length;
    uint32_t checksum;
};
typedef struct bm_message_header_struct bm_message_header;

// Network address
struct bm_net_addr_struct {
    uint32_t time;
    uint32_t stream;
    uint64_t services;
    char ip_address[16];
    uint16_t port;
};
typedef struct bm_net_addr_struct bm_net_addr;

// Inventory vector element
struct bm_inventory_element_struct {
	char hash[32];
};
typedef struct bm_inventory_element_struct bm_inventory_element;

// Version request
struct bm_version_header_struct {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
	bm_net_addr addr_recv;
	bm_net_addr addr_from;
    uint64_t nonce;
};
typedef struct bm_version_header_struct bm_version_header;

class Bitmessage
{
    public:

        static ByteVector calculateInventoryHash(const ByteVector& data);
        static ByteVector getHashString512(const ByteVector& data);
        static uint64_t getProofOfWorkTrialValue(uint64_t nonce, const ByteVector& initialHash);

        template<class T>
        static std::string encodeVarint(T integer);

        static uint64_t decodeVarint(const ByteVector& data, int &nbytes);

        static std::string proofOfWork(uint32_t streamNumber,
                                  std::string embeddedTime,
                                  std::string cyphertext,
                                  uint32_t payloadLengthExtraBytes=14000,
                                  uint32_t averageProofOfWorkNonceTrialsPerByte=320,
                                  bool verbose=false);

        static bool checkProofOfWork(std::string payload,
                                     uint32_t payloadLengthExtraBytes=14000,
                                     uint32_t averageProofOfWorkNonceTrialsPerByte=320);
/*
        static string encodeAddress(unsigned int version, unsigned int streamNumber, string ripe);
        static void decodeAddress(string address,
                                  string &status,
                                  string &data,
                                  unsigned int &version,
                                  unsigned int &streamNumber);
*/
        static std::string addBMIfNotPresent(std::string address);

        static uint32_t addressStreamNumber(std::string address, std::string &status);
};

#endif
