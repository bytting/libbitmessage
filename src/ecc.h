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

#ifndef BM_ECC_H
#define BM_ECC_H

#include <vector>
#include <string>
#include "btypes.h"

namespace bm {

namespace ecc {

typedef byte_vector_type private_key_type;
typedef std::vector<uint8_t> public_key_type;

void create_key_pair(private_key_type& privkey, public_key_type& pubkey);

std::string pem_encode_private_key_encrypted(const private_key_type& privkey, const std::string& password);
std::string pem_encode_public_key(const public_key_type& pubkey);

uint16_t get_curve_id();

} // namespace ecc

} // namespace bm

#endif
