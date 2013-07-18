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

#include "config.h"
#include <algorithm>
#include <iterator>
#include <limits>
#include <ctime> // FIXME chrono
#ifdef BM_DEBUG
#include <iostream>
#endif
#include "pow.h"
#include "enc.h"
#include "hash.h"

namespace bm {

namespace pow {

namespace internal {

uint64_t get_proof_of_work_trial_value(uint64_t nonce, const SecureVector& initial_hash)
{
    SecureVector trial_value, nonce_hash = encode::varint(nonce);
    nonce_hash += initial_hash;

    SecureVector sha = hash::sha512(hash::sha512(nonce_hash));
    std::copy(sha.end() - 8, sha.end(), std::back_inserter(trial_value));

    int nb;
    return decode::varint(trial_value.data(), nb);
}

} // namespace internal

SecureVector append_proof_of_work(
        uint64_t stream_number,
        const SecureVector& embedded_time,
        const SecureVector& cyphertext,
        uint32_t payload_length_extra_bytes,
        uint32_t average_proof_of_work_nonce_trials_per_byte)
{
    uint64_t target, nonce = 0;
    uint64_t trial_value = std::numeric_limits<uint64_t>::max();
    clock_t begin_time, end_time;

    SecureVector payload = embedded_time;
    payload += encode::varint(stream_number);
    payload += cyphertext;

    target = std::numeric_limits<uint64_t>::max() / ((8 + payload.size() + payload_length_extra_bytes) * average_proof_of_work_nonce_trials_per_byte);

    begin_time = std::clock();
    SecureVector initial_hash = hash::sha512(payload);
    uint64_t best = 0;
    while (trial_value > target)
    {
        if (nonce == 0)
            nonce = 1;
        else
            nonce += 32;

// #pragma omp parallel for
        for (uint64_t index = 0; index < 4; index++)
        {
            uint64_t n = internal::get_proof_of_work_trial_value(nonce + index, initial_hash);
            if (n <= target)
            {
                trial_value = n;
                best = nonce + index;
            }
        }
    }

    nonce = best;
    end_time = std::clock();

#ifdef BM_DEBUG

    std::clog << "Found proof of work: " << trial_value << std::endl;
    std::clog << "Nonce: " << nonce << std::endl;

    if (end_time > begin_time)
    {
        std::clog << "POW took " << (int)((end_time - begin_time) / CLOCKS_PER_SEC) << " seconds" << std::endl;
        std::clog << nonce / (uint64_t)((end_time - begin_time) / CLOCKS_PER_SEC) << " nonce trials per second" << std::endl;
    }

#endif

    // prepend the nonce value.  This can then be used by the receiver to check that the payload is valid
    SecureVector result = encode::varint(nonce);
    result += payload;
    return result;
}

bool validate_proof_of_work(const SecureVector& payload,
        uint32_t payload_length_extra_bytes,
        uint32_t average_proof_of_work_nonce_trials_per_byte)
{
    if (payload.size() < 2)
        return false;

    int nb;
    SecureVector tmp_payload;

    uint64_t nonce = decode::varint(&payload[0], nb);
    std::copy(payload.begin() + nb, payload.end(), std::back_inserter(tmp_payload));

    uint64_t target = std::numeric_limits<uint64_t>::max() / ((payload.size() + payload_length_extra_bytes) * average_proof_of_work_nonce_trials_per_byte);

    SecureVector initial_hash = hash::sha512(tmp_payload);
    return internal::get_proof_of_work_trial_value(nonce, initial_hash) <= target;
}

} // namespace pow

} // namespace bm
