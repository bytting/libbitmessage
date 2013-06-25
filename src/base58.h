
/** an implementation of the base 58 encode & decode
 *
 *  author: Yeonwoon Jung
 *  e-mail: flow3r@gmail.com
 *
 *  license:
 *      Public domain
 *
 *  references
 *      1. http://www.flickr.com/groups/api/discuss/72157616713786392/
 *      2. https://gist.github.com/101674
 */

#ifndef BASE58_H
#define BASE58_H

#include <botan/bigint.h>

namespace base58
{
    /** encode number into base58
     *  
     *  @param  id_num      number to encode.
     *  @param  output      pointer to a output buffer.
     *  @param  output_len  size of output buffer in bytes.
     *  
     *  @return
     *      0 if failed. otherwise, number of bytes written.
     */
    size_t encode(Botan::BigInt id_num, char* output, size_t output_len);

    /** decode base58 into number
     *  
     *  @param  encoded     input string that is encoded with base58.
     *  @param  encoded_len num of bytes given string. if this value is -1, the string considered as a null-terminated.
     *  @param  output      pointer to a output buffer.
     *  
     *  @return
     *      true if successful, otherwise, false.
     */
    bool decode(const char* encoded, size_t encoded_len, Botan::BigInt* output);
}

#endif
