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

#include <algorithm>
#include <iterator>
#include "pow.h"
#include "encode.h"
#include "decode.h"
#include "hash.h"

namespace bm {

namespace pow {

uint64_t get_proof_of_work_trial_value(uint64_t nonce, const SecureVector& initial_hash)
{
    SecureVector trial_value, nonce_hash = encode::varint(nonce);
    nonce_hash += initial_hash;

    SecureVector sha = hash::sha512(hash::sha512(nonce_hash));
    std::copy(sha.end() - 8, sha.end(), std::back_inserter(trial_value));

    int nb;
    return decode::varint(trial_value.data(), nb);
}
/*
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
    std::memcpy((void*)&nonce,(void*)payload_str,8);

    unsigned long long target = 18446744073709551615ULL /
        ((payload.length()+payloadLengthExtraBytes) *
         averageProofOfWorkNonceTrialsPerByte);

    string initialHash = getHashString512(message_payload);
    return (getProofOfWorkTrialValue(nonce, initialHash) <= target);
}
*/
} // namespace pow

} // namespace bm
