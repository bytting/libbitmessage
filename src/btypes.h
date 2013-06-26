
#ifndef BTYPES_H
#define BTYPES_H

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

namespace bm {

typedef Botan::byte Byte;
typedef Botan::SecureVector<Byte> ByteVector;
typedef Botan::OctetString OctetVector;

} // namespace bm

#endif
