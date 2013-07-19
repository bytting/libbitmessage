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
#include <thread>
#include "pow.h"
#include "enc.h"
#include "hash.h"

namespace bm {

namespace pow {

namespace internal {

volatile bool tflag;

void do_generate_nonce(const SecureVector& payload, uint64_t& nonce)
{
    bm::SecureVector initial_hash = bm::hash::sha512(payload);
    uint64_t target = std::numeric_limits<uint64_t>::max() / ((payload.size() + PAYLOAD_LENGTH_EXTRA_BYTES + 8) * AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

    bm::SecureVector v;
    uint64_t nonce_test = 0;
    uint64_t trials_test = std::numeric_limits<uint64_t>::max();

    while(trials_test > target)
    {
        ++nonce_test;
        v = bm::encode::varint(nonce_test);
        v += initial_hash;
        v = bm::hash::sha512(bm::hash::sha512(v));
        std::memcpy(&trials_test, v.data(), 8);
    }

    nonce = nonce_test;
}

void do_generate_nonce_parallel_worker(const SecureVector& payload, uint64_t offset, uint64_t iterations, uint64_t* nonce)
{
    *nonce = 0;
    bm::SecureVector initial_hash = bm::hash::sha512(payload);
    uint64_t target = std::numeric_limits<uint64_t>::max() / ((payload.size() + PAYLOAD_LENGTH_EXTRA_BYTES + 8) * AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

    bm::SecureVector v;
    uint64_t i = offset, nonce_test = offset;
    uint64_t trials_test = std::numeric_limits<uint64_t>::max();

    while(trials_test > target)
    {
        if(tflag)
            return;
        if(++i - offset > iterations)
            return;
        ++nonce_test;
        v = bm::encode::varint(nonce_test);
        v += initial_hash;
        v = bm::hash::sha512(bm::hash::sha512(v));
        std::memcpy(&trials_test, v.data(), 8);
    }

    tflag = true;
    *nonce = nonce_test;
}

void do_generate_nonce_parallel(const SecureVector& payload, uint64_t& nonce)
{
    unsigned int concurent_threads_supported = std::thread::hardware_concurrency();
    if(!concurent_threads_supported)
        concurent_threads_supported = 1;
    else if(concurent_threads_supported > 4) // FIXME: More than 4 threads gives bad performance for some reason
        concurent_threads_supported = 4;

    uint64_t iterations = std::numeric_limits<uint64_t>::max() / concurent_threads_supported;
    uint64_t vnonce[concurent_threads_supported];

    tflag = false;

    std::vector<std::thread> threads;
    for(unsigned int i = 0; i < concurent_threads_supported; i++)
        threads.push_back(std::thread(do_generate_nonce_parallel_worker, payload, i * iterations, iterations, &vnonce[i]));

    for(auto& thread : threads)
        thread.join();

    for(unsigned int i = 0; i < concurent_threads_supported; i++)
    {
        if(vnonce[i])
        {
            nonce = vnonce[i];
            break;
        }
    }
}

} // namespace internal

uint64_t generate_nonce(const SecureVector& payload, bool parallel)
{
    uint64_t nonce;

    if(parallel)
        internal::do_generate_nonce_parallel(payload, nonce);
    else
        internal::do_generate_nonce(payload, nonce);

    return nonce;
}

bool validate_nonce(const SecureVector& payload)
{
    if (payload.size() < 2)
        return false;

    int offset;
    bm::SecureVector v, initial_payload;
    uint64_t trials_test, nonce = decode::varint(payload.data(), offset);
    std::copy(payload.begin() + offset, payload.end(), std::back_inserter(initial_payload));
    bm::SecureVector initial_hash = bm::hash::sha512(initial_payload);
    uint64_t target = std::numeric_limits<uint64_t>::max() / ((initial_payload.size() + PAYLOAD_LENGTH_EXTRA_BYTES + 8) * AVERAGE_PROOF_OF_WORK_NONCE_TRIALS_PER_BYTE);

    v = bm::encode::varint(nonce);
    v += initial_hash;
    v = bm::hash::sha512(bm::hash::sha512(v));
    std::memcpy(&trials_test, v.data(), 8);

    return trials_test <= target;
}

} // namespace pow

} // namespace bm
