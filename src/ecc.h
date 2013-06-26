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

#include <string>
#include <map>
#include "btypes.h"

namespace bm {

class ECC
{
public:

    ECC() : m_curve("secp256k1") {}

    const std::map<std::string, uint16_t> curves = {
        { "secp224r1", 713 },
        { "secp256k1", 714 },
        //{ "sect283r1", 730 }
    };

    void set_curve(const std::string& curve);
    inline std::string get_curve() const { return m_curve; }
    inline uint16_t get_curve_id() const { return curves.at(m_curve) ; }

    inline bool has_keys() const { return m_private_key.length() > 0; }
    inline std::string get_public_key() const { return m_public_key; }
    inline std::string get_private_key() const { return m_private_key; }

    void generate_keys();
    void generate_keys_with_password(const std::string& password);

    //int decode_pubkey(bytes data);
    //int decode_privkey(bytes data);

    inline void clear();

private:

    std::string m_public_key;
    std::string m_private_key;
    std::string m_curve;
};

} // namespace bm

#endif
