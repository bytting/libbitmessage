
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

#include "base64.h"

#include <cstring>

namespace bm {

namespace
{
    const char* kPrintableChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // FIXME: Check this
    const unsigned int kMaxDataLen = 3221225472L; // 3G
    const unsigned int kMaxCodeLen = 4294967295L; // 4G - 1

    unsigned char decode_char(unsigned char ch) {
        if (ch >= 'A' && ch <= 'Z')
            return ch - 'A';

        if (ch >= 'a' && ch <= 'z')
            return ch - 'a' + 26;

        if (ch >= '0' && ch <= '9')
            return ch - '0' + 52;

        if (ch == '+') return 62;
        if (ch == '/') return 63;
        if (ch == '=') return 0;

        return 255;
    }

    size_t base64_length(size_t data_len) {

        int num  = data_len / 3;
        int rest = data_len % 3;

        return (rest ? num+1 : num) * 4;
    }

    size_t data_length(size_t base64_len) {

        int num  = base64_len / 4;
        return num * 3;
    }
}

namespace base64
{
    size_t encode(const void* data, size_t data_len, char* output, size_t output_len)
    {
        if (data == 0 || data_len == 0 || data_len > kMaxDataLen)
            return 0;

        if (output == 0)
            return 0;

        if (output_len < base64_length(data_len) + 1)
            return 0;

        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        size_t output_wpos = 0;

        size_t unprocessed = data_len;
        while (unprocessed > 0) {

            size_t pos = data_len - unprocessed;

            output[output_wpos+0] = kPrintableChars[(bytes[pos] & 0xFC) >> 2];
            output[output_wpos+1] = kPrintableChars[((bytes[pos] & 0x03) << 4) + ((unprocessed < 2) ? 0 : ((bytes[pos+1] & 0xF0) >> 4))];
            output[output_wpos+2] = (unprocessed < 2) ? '=' : kPrintableChars[((bytes[pos+1] & 0x0F) << 2) + ((unprocessed < 3) ? 0 : ((bytes[pos+2] & 0xC0) >> 6))];
            output[output_wpos+3] = (unprocessed < 3) ? '=' : kPrintableChars[bytes[pos+2] & 0x3F];
            output_wpos += 4;

            if (unprocessed < 3)
                break;

            unprocessed -= 3;
        }

        output[output_wpos] = '\0';

        return output_wpos;
    }

    size_t decode(const char* encoded, size_t encoded_len, void* output, size_t output_len)
    {
        if (encoded == 0 || encoded_len == 0)
            return 0;

        if (encoded_len == -1) // FIXME: unsigned comparison
            encoded_len = std::strlen(encoded);

        if ((encoded_len & 3) != 0 || encoded_len > kMaxCodeLen)
            return 0;

        if (output == 0)
            return 0;

        if (output_len < data_length(encoded_len))
            return 0;

        unsigned char* output_bytes = static_cast<unsigned char*>(output);

        size_t output_wpos = 0;
        unsigned char data[4];

        size_t unprocessed = encoded_len;
        while (unprocessed > 0) {

            size_t pos = encoded_len - unprocessed;

            *reinterpret_cast<int*>(data) = 0;
            for (int i = 0; i < 4; ++i) {

                data[i] = decode_char(encoded[pos+i]);
                if (data[i] == 255) {

                    return 0;
                }
            }

            output_bytes[output_wpos+0] = (data[0] << 2) + (data[1] >> 4);
            output_bytes[output_wpos+1] = (data[1] << 4) + (data[2] >> 2);
            output_bytes[output_wpos+2] = (data[2] << 6) + data[3];
            output_wpos += 3;

            unprocessed -= 4;
        }

        if (data[3] == 0) output_wpos -= 1;
        if (data[2] == 0) output_wpos -= 1;

        return output_wpos;
    }
}

} // namespace bm
