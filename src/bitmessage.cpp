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
// Bob Mottram (bob@robotics.uk.to)
// Dag Robøle (BM-2DAS9BAs92wLKajVy9DS1LFcDiey5dxp5c)

#include <cstring>
#include "exceptions.h"
#include "hash.h"
#include "bitmessage.h"

namespace bm {

SecureVector calculateInventoryHash(const SecureVector& data)
{
    SecureVector sha = hash::sha512(hash::sha512(data));
    if(sha.size() < 32)
        throw SizeException(__FILE__, __FUNCTION__, __LINE__, "Hash size is less than 32");
    return sha;
}

} // namespace bm
