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

#ifndef POW_H
#define POW_H

#include <stdint.h>
#include <string>
#include "btypes.h"

#define PAYLOAD_LENGTH_EXTRA_BYTES  14000
#define AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE 320

namespace bm {

namespace pow {

uint64_t get_proof_of_work_trial_value(uint64_t nonce, const SecureVector& initial_hash);
/*
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
        */

} // namespace pow

} // namespace bm

#endif
