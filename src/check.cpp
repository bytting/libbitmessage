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
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#include <algorithm>
#include <iterator>
#include "check.h"
#include "exceptions.h"
#include "btypes.h"
#include "decode.h"
#include "hash.h"

namespace bm {

namespace check {

bool wif(const std::string& encoded)
{
    if(encoded.length() < 5)
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "Encoded WIF is too short");

    SecureVector checksum1, checksum2, extended, decoded = decode::base58(encoded);

    std::copy(decoded.end() - 4, decoded.end(), std::back_inserter(checksum1));
    std::copy(decoded.begin(), decoded.end() - 4, std::back_inserter(extended));
    SecureVector sha = hash::sha256(hash::sha256(extended));
    std::copy(sha.begin(), sha.begin() + 4, std::back_inserter(checksum2));

    return checksum1 == checksum2;
}

} // namespace check

} // namespace bm
