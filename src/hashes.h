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

#ifndef BM_HASHES_H
#define BM_HASHES_H

#include <string>
#include "utils.h"

namespace bm {

enum DigestFormat {
    DM_FORMAT_NONE = 0,
    DM_FORMAT_HEX
};

ByteVector ripemd160(const ByteVector& data, DigestFormat fmt = DM_FORMAT_NONE);
ByteVector sha256(const ByteVector& data, DigestFormat fmt = DM_FORMAT_NONE);
ByteVector sha512(const ByteVector& data, DigestFormat fmt = DM_FORMAT_NONE);

ByteVector hmac_sha256(const ByteVector& data, DigestFormat fmt = DM_FORMAT_NONE);
ByteVector hmac_sha512(const ByteVector& data, DigestFormat fmt = DM_FORMAT_NONE);

OctetVector pbkdf2_hmac_sha256(const std::string& password, const ByteVector& salt, int iterations = 10000);
OctetVector pbkdf2_hmac_sha512(const std::string& password, const ByteVector& salt, int iterations = 10000);

} // namespace bm

#endif
