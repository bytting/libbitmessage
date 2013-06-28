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
    typedef std::map<std::string, uint16_t> CurveMap;

public:               

    inline bool curve_exists(const std::string& curve) const  { return curves.find(curve) != curves.end(); }
    inline std::string get_curve() const { return m_curve; }
    inline uint16_t get_curve_id() const;

    inline bool has_keys() const { return m_private_key.length() > 0; }
    inline std::string get_public_key() const { return m_public_key; }
    inline std::string get_private_key() const { return m_private_key; }

    void generate_keys(const std::string& curve = "secp256k1");
    void generate_keys_with_password(const std::string& password, const std::string& curve = "secp256k1");

    inline void clear();

private:

    void set_curve(const std::string& curve);

    std::string m_public_key;
    std::string m_private_key;
    std::string m_curve;    

    const CurveMap curves = {        
        { "secp224r1", 713 },
        { "secp256k1", 714 },        
        { "sect283r1", 730 }
    };
};

} // namespace bm

#endif
