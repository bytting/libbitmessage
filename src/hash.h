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

#ifndef BM_HASH_H
#define BM_HASH_H

#include <string>
#include "btypes.h"

namespace bm {

namespace hash {

SecureVector ripemd160(const SecureVector& data);
SecureVector ripemd160(const std::string& data);

SecureVector sha256(const SecureVector& data);
SecureVector sha256(const std::string& data);

SecureVector sha512(const SecureVector& data);
SecureVector sha512(const ByteVector& data);
SecureVector sha512(const std::string& data);

SecureVector double_sha512(const SecureVector& data);

SecureVector hmac_sha256(const SecureVector& data, const SecureVector& key);
SecureVector hmac_sha512(const SecureVector& data, const SecureVector& key);

OctetString pbkdf2_hmac_sha256(const std::string& password, const SecureVector& salt, int iterations = 10000);
OctetString pbkdf2_hmac_sha512(const std::string& password, const SecureVector& salt, int iterations = 10000);

} // namespace hash

} // namespace bm

#endif
