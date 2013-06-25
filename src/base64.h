
/** an implementation of the base 64 encode & decode
 *
 *  author: Yeonwoon Jung
 *  e-mail: flow3r@gmail.com
 *
 *  license:
 *      Public domain
 *
 *  references
 *      1. http://tools.ietf.org/html/rfc3548
 *      2. http://en.wikipedia.org/wiki/Base64
 */

#ifndef BASE64_H
#define BASE64_H

#include <cstddef>

namespace bm {

namespace base64
{
    /** encode data into base64
     *  
     *  @param  data        addr of a data to encode.
     *  @param  data_len    num of bytes to encode.
     *  @param  output      pointer to a output buffer.
     *  @param  output_len  size of output buffer in bytes.
     *  
     *  @return
     *      0 if failed. otherwise, number of bytes written.
     */
    size_t encode(const void* data, size_t data_len, char* output, size_t output_len);

    /** decode base64 into data
     *  
     *  @param  encoded     input string that is encoded with base64.
     *  @param  encoded_len num of bytes given string. if this value is -1, the string considered as a null-terminated.
     *  @param  output      pointer to a output buffer. there won't be null-terminate.
     *  @param  output_len  size of output buffer in bytes.
     *  
     *  @return
     *      0 if failed. otherwise, number of bytes written.
     */
    size_t decode(const char* encoded, size_t encoded_len, void* output, size_t output_len);
}

} // namespace bm

#endif
