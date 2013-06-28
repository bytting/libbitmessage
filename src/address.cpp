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

#include "address.h"
#include "exceptions.h"
#include "utils.h"
#include "hashes.h"
#include "ecc.h"

#include <iostream> // FIXME: remove this

namespace bm {

std::string encode_address(uint64_t version, uint64_t stream, const ByteVector& ripe)
{
    if(ripe.size() != 20)
        throw SizeException(__FILE__, __LINE__, "create_random_address: The ripe length is not 20");

    ByteVector r = ripe;
    if(r[0] == 0x00 && r[1] == 0x00)
    {
        ByteVector tmp(&r[2], r.size() - 2);
        r = tmp;
    }
    else if(r[0] == 0x00)
    {
        ByteVector tmp(&r[1], r.size() - 1);
        r = tmp;
    }

    ByteVector v = utils::encode_varint(version);
    v += utils::encode_varint(stream);
    v += r;

    ByteVector sha1 = sha512(v);
    ByteVector sha2 = sha512(sha1);
    ByteVector checksum(&sha2[0], 4);

    v += checksum;
    Botan::BigInt bi(&v[0], v.size());
    std::string address = utils::encode_base58(bi);

    add_bm_prefix(address);

    return address;
}

std::string create_random_address()
{
    // FIXME: set these correctly
    bool eighteen_byte_ripe = false;
    uint64_t address_version = 3, stream = 1;

    ECC signing_keys;
    signing_keys.generate_keys();
    ByteVector ripe;
    while(true)
    {
        ECC encryption_keys;
        encryption_keys.generate_keys();
        ByteVector sha = sha512(encryption_keys.get_private_key());
        ripe = ripemd160(sha);
        if(eighteen_byte_ripe)
        {
            if(ripe[0] == 0x00 && ripe[1] == 0x00)
                break;
        } else {
            if(ripe[0] == 0x00)
                break;
        }
    }

    // FIXME: Only address version 3

    return encode_address(address_version, stream, ripe);

    /*
     * FIXME
    # An excellent way for us to store our keys is in Wallet Import Format. Let us convert now.
    # https://en.bitcoin.it/wiki/Wallet_import_format
    privSigningKey = '\x80' + potentialPrivSigningKey
    checksum = hashlib.sha256(hashlib.sha256(
        privSigningKey).digest()).digest()[0:4]
    privSigningKeyWIF = arithmetic.changebase(
        privSigningKey + checksum, 256, 58)
    # print 'privSigningKeyWIF',privSigningKeyWIF

    privEncryptionKey = '\x80' + potentialPrivEncryptionKey
    checksum = hashlib.sha256(hashlib.sha256(
        privEncryptionKey).digest()).digest()[0:4]
    privEncryptionKeyWIF = arithmetic.changebase(
        privEncryptionKey + checksum, 256, 58)
    # print 'privEncryptionKeyWIF',privEncryptionKeyWIF

    shared.config.add_section(address)
    shared.config.set(address, 'label', label)
    shared.config.set(address, 'enabled', 'true')
    shared.config.set(address, 'decoy', 'false')
    shared.config.set(address, 'noncetrialsperbyte', str(
        nonceTrialsPerByte))
    shared.config.set(address, 'payloadlengthextrabytes', str(
        payloadLengthExtraBytes))
    shared.config.set(
        address, 'privSigningKey', privSigningKeyWIF)
    shared.config.set(
        address, 'privEncryptionKey', privEncryptionKeyWIF)
    with open(shared.appdata + 'keys.dat', 'wb') as configfile:
        shared.config.write(configfile)

    # It may be the case that this address is being generated
    # as a result of a call to the API. Let us put the result
    # in the necessary queue.
    shared.apiAddressGeneratorReturnQueue.put(address)

    shared.UISignalQueue.put((
        'updateStatusBar', tr.translateText("MainWindow", "Done generating address. Doing work necessary to broadcast it...")))
    shared.UISignalQueue.put(('writeNewAddressToTable', (
        label, address, streamNumber)))
    shared.reloadMyAddressHashes()
    shared.workerQueue.put((
        'doPOWForMyV3Pubkey', ripe.digest()))
    */
}

void add_bm_prefix(std::string& address)
{
    if(address.substr(0, 3) != "BM-")
        address = "BM-" + address;
}

} // namespace bm
