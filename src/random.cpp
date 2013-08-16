/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// CONTRIBUTORS AND COPYRIGHT HOLDERS (c) 2013:
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#include "random.h"

namespace bm {

namespace random {

namespace internal {

struct RandomNumberGeneratorAutoSeeded
{
    static Botan::AutoSeeded_RNG& instance()
    {
        static Botan::AutoSeeded_RNG generator;
        return generator;
    }
};

} // namespace internal

Botan::AutoSeeded_RNG& generator()
{
    return internal::RandomNumberGeneratorAutoSeeded::instance();
}

SecureVector bytes(uint32_t count)
{
    return internal::RandomNumberGeneratorAutoSeeded::instance().random_vec(count);
}

} // namespace random

} // namespace bm
