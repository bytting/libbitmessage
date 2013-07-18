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

#ifndef BM_ADDRESS_H
#define BM_ADDRESS_H

#include <string>
#include <ostream>
#include "btypes.h"

namespace bm {

class Address
{
public:

    Address(uint64_t address_version_number, uint64_t stream_number, bool eighteen_byte_ripe = false);
    ~Address() {}    

    operator std::string() { return "BM-" + m_address; }
    friend std::ostream& operator << (std::ostream& out, const Address& address);

    static uint64_t extract_stream_number(const std::string& address);

private:

    std::string m_address;    

    void encode_address(uint64_t version, uint64_t stream, const SecureVector& ripe);
};

} // namespace bm

#endif
