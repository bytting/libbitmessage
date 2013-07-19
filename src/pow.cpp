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

#include <cstring>
#include <algorithm>
#include <iterator>
#include <limits>
#include "pow.h"
#include "enc.h"
#include "hash.h"

namespace bm {

namespace pow {

namespace internal {

void do_generate_nonce(const SecureVector& payload, uint64_t& trials, uint64_t& nonce)
{
    bm::SecureVector initial_hash = bm::hash::sha512(payload);
    uint64_t target = std::numeric_limits<uint64_t>::max() / ((payload.size() + PAYLOAD_LENGTH_EXTRA_BYTES + 8) * AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

    bm::SecureVector v, v2;
    uint64_t nonce_test = 0;
    uint64_t trials_test = std::numeric_limits<uint64_t>::max();

    while(trials_test > target)
    {
        nonce_test += 1;
        v = bm::encode::varint(nonce_test);
        v += initial_hash;
        v2 = bm::hash::sha512(bm::hash::sha512(v));
        std::memcpy(&trials_test, &v2[0], 8);
    }

    trials = trials_test;
    nonce = nonce_test;
}

} // namespace internal

void generate_nonce(const SecureVector& payload, uint64_t& nonce)
{
    uint64_t trials;
    internal::do_generate_nonce(payload, trials, nonce);
}

bool validate_nonce(const SecureVector& payload)
{
    if (payload.size() < 2)
        return false;

    int nb;
    SecureVector original_payload;
    uint64_t original_nonce = decode::varint(&payload[0], nb);
    std::copy(payload.begin() + nb, payload.end(), std::back_inserter(original_payload));

    uint64_t trials, nonce;
    internal::do_generate_nonce(original_payload, trials, nonce);

    return nonce == original_nonce;
}

} // namespace pow

} // namespace bm
