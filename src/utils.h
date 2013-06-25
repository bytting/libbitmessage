/*
  cppbitmessage: a bitmessage daemon
  Copyright (C) 2013 Bob Mottram
  bob@robotics.uk.to

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

#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <botan/types.h>
#include <botan/secmem.h>
#include <botan/symkey.h>

#if defined(__linux__)
#include <endian.h>
#define big_to_host_16(v) be16toh(v)
#define big_to_host_32(v) be32toh(v)
#define big_to_host_64(v) be64toh(v)
#define host_to_big_16(v) htobe16(v)
#define host_to_big_32(v) htobe32(v)
#define host_to_big_64(v) htobe64(v)
#elif defined(_WIN32)
    #error endian not implemented for Windows
    //#if defined(_WIN64)
    //#endif
#elif defined(__unix__)
    #error endian not implemented for UNIX
#elif defined(__APPLE__)
    #error endian not implemented for Apple
#elif defined(__FreeBSD__)
    #error endian not implemented for FreeBSD
#endif

typedef Botan::byte Byte;
typedef Botan::SecureVector<Byte> ByteVector;
typedef Botan::OctetString OctetVector;

class utils
{
public:

    static unsigned int ipow(int base, int exponent);
    //static std::string encodeHex(const std::string& buf);
    //static std::string decodeHex(const std::string& hex);
    //static unsigned long long decodeHexInt(const std::string& hex);
    //static std::string encodeHex(unsigned int value);

    //static std::string encodeHex(mpz_t value);
    //static void decodeHexInt(const std::string& hex, mpz_t& result);

    //static bytes base58ToBytes(const std::string& encoded);
    //static std::string bytesToBase58(const bytes& encoded);

    template<class T>
    static ByteVector pack(T value);

    template<class T>
    static T unpack(const ByteVector& data);
};

#endif
