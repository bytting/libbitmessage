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

SecureVector append_proof_of_work(
        uint64_t stream_number,
        const SecureVector& embedded_time,
        const SecureVector& cyphertext,
        uint32_t payload_length_extra_bytes = PAYLOAD_LENGTH_EXTRA_BYTES,
        uint32_t average_proof_of_work_nonce_trials_per_byte = AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

bool validate_proof_of_work(const SecureVector &payload,
        uint32_t payload_length_extra_bytes = PAYLOAD_LENGTH_EXTRA_BYTES,
        uint32_t average_proof_of_work_nonce_trials_per_byte = AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

} // namespace pow

} // namespace bm

#endif
