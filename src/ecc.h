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

#include <cstdint>
#include <string>

namespace bm {

const uint16_t Secp256K1 = 714;
const uint16_t Sect283r1 = 730;

struct ECC
{
    //int decode_pubkey(bytes data);
    //int decode_privkey(bytes data);
    void generateKeys();
    void generateKeysWithPassword(const std::string& password);
    //unsigned int get_curve_id();

    inline std::string getPublicKey() const { return mPublicKey; }
    inline std::string getPrivateKey() const { return mPrivateKey; }

private:

    std::string mPublicKey;
    std::string mPrivateKey;
    //unsigned int curve_id;
};

} // namespace bm

#endif
