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

#ifndef BITMESSAGE_H
#define BITMESSAGE_H

#include <string>
#include "btypes.h"

namespace bm {

#define PAYLOAD_LENGTH_EXTRA_BYTES  14000
#define AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE 320

//pubkey bitfield
//#define BM_PUBKEY_DOES_ACK 31 // FIXME: what is this

// Message encodings
enum {
	BM_ENCODING_IGNORE = 0,
	BM_ENCODING_TRIVIAL,
	BM_ENCODING_SIMPLE
};

// Message header
struct message_header_struct {
    uint32_t magic;
	char command[12];
    uint32_t length;
    uint32_t checksum;
};
typedef struct message_header_struct message_header;

// Network address
struct net_addr_struct {
    uint32_t time;
    uint32_t stream;
    uint64_t services;
    char ip_address[16];
    uint16_t port;
};
typedef struct net_addr_struct net_addr;

// Inventory vector element
struct inventory_element_struct {
	char hash[32];
};
typedef struct inventory_element_struct inventory_element;

// Version request
struct bm_version_header_struct {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
    net_addr addr_recv;
    net_addr addr_from;
    uint64_t nonce;
};
typedef struct version_header_struct version_header;


byte_vector_type calculateInventoryHash(const byte_vector_type& data);

uint64_t getProofOfWorkTrialValue(uint64_t nonce, const byte_vector_type& initialHash);

std::string proofOfWork(
        uint32_t streamNumber,
        std::string embeddedTime,
        std::string cyphertext,
        uint32_t payloadLengthExtraBytes = PAYLOAD_LENGTH_EXTRA_BYTES,
        uint32_t averageProofOfWorkNonceTrialsPerByte = AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE,
        bool verbose=false);

bool checkProofOfWork(
        std::string payload,
        uint32_t payloadLengthExtraBytes = PAYLOAD_LENGTH_EXTRA_BYTES,
        uint32_t averageProofOfWorkNonceTrialsPerByte = AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

uint32_t addressStreamNumber(std::string address, std::string &status);

} // namespace bm

#endif
