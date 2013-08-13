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

#ifndef BM_ECC_H
#define BM_ECC_H

#include <vector>
#include <string>
#include <ostream>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include "btypes.h"

namespace bm {

class ECC
{
public:

    ECC();
    ECC(const SecureVector& key_bytes);
    ECC(const std::string& key_hex);
    ~ECC();

    const SecureVector& private_key() const;
    const ByteVector& public_key() const;

    SecureVector PKCS8_BER() const;
    std::string PKCS8_PEM() const;
    std::string PKCS8_PEM(const std::string& password) const;
    ByteVector X509_BER() const;
    std::string X509_PEM() const;

    uint16_t get_curve_id() const;

    static bool validate_wif_checksum(const std::string& encoded);

    friend std::ostream& operator << (std::ostream& out, const ECC& ecc);

private:

    void reset();

    void initialize_keys(const BigInteger& ikey);

    const Botan::EC_Group m_group;
    Botan::ECDSA_PrivateKey* m_key;
    SecureVector m_private_key_bytes;
    ByteVector m_public_key_bytes;
};

} // namespace bm

#endif
