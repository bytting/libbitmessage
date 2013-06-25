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

#include <sstream>
#include <iomanip>
#include <algorithm>
#include "exceptions.h"
#include "utils.h"

namespace bm {

using namespace std;

/*
string utils::encodeHex(const string& str)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < str.length(); i++)
        ss << std::setw(2) << int(str[i]);
    return ss.str();
}

string utils::encodeHex(unsigned int value)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(4) << value;
    return ss.str();
}

string utils::encodeHex(mpz_t value)
{
	char str[1024];
    stringstream hexstr;

    mpz_get_str(str, 16, value);
	for (int i = 0; i < strlen(str); i++) {
        hexstr << str[i];
	}
    return hexstr.str();
}

string utils::decodeHex(const string& hexString)
{
	string str = "";

    for (int i = 0; i < hexString.length(); i += 2) {
        unsigned long num = strtol(hexString.substr(i,2).c_str(),NULL,16);
		str += (char)num;
	}
	return str;    
}

void utils::decodeHexInt(const string& hexString, mpz_t &result)
{
	mpz_init(result);
    mpz_set_str(result, (char*)hexString.c_str(), 16);
}

unsigned long long utils::decodeHexInt(const string& hexString)
{
    unsigned long long val;
    std::stringstream ss;
    ss << std::hex;
    ss << hexString;
    ss >> val;
    return val;
}
*/

/*
static bytes utils::base58ToBytes(const string& encoded)
{
    bytes bts;
    mpz_t big, b58;

    // Initialize integers
    mpz_init(big);
    mpz_init(b58);
    mpz_set_si(b58, 58);

    for(string::iterator it = encoded.begin(); it != encoded.end(); ++it)
    {
        if(*it >= 0 && *it < B58.length())
        {
            mpz_mul(big, big, b58);
            mpz_add_ui(big, big, B58[*it]);
        }
        else
            throw Exception_PostFence(__FILE__, __LINE__, "Base58 character out of bounds");
    }

    // convert integer to char array
    int siz = mpz_sizeinbase(big, 10) + 2;
    bts.resize(siz);
    char buf[siz];
    char* pbuf = mpz_get_str(buf, 10, big);

    // copy char array to byte array
    memcpy(&bts[0], pbuf, siz);

    // clean up integers
    mpz_clear(b58);
    mpz_clear(big);

    // remove trailing zero's
    bytes::iterator it = bts.back();
    while(!*it)
    {
        bts.erase(it);
        it = bts.back();
    }

    // reverse byte array
    reverse(bts.begin(), bts.end());

    return bts;
}

static string utils::bytesToBase58(const bytes& encoded)
{
    bytes bts = encoded;
    reverse(bts.begin(), bts.end());



    // ===

    byte[] positiveBa;
    if (tmp[tmp.Length - 1] >= 0x80)
    {
        positiveBa = new byte[ba.Length + 1];
        Array.Copy(tmp, positiveBa, tmp.Length);
    }
    else positiveBa = tmp;

    BigInteger addrremain = new BigInteger(positiveBa);
    if (addrremain<0) throw new Exception("Negative? I wont positive");

    StringBuilder rv = new StringBuilder(100);

    while (addrremain.CompareTo(BigInteger.Zero) > 0)
    {
        var remainder = addrremain % 58;
        addrremain    = addrremain / 58;
        rv.Insert(0, B58[(int) remainder]);
    }

    // handle leading zeroes
    foreach (byte b in ba)
    {
        if (b != 0) break;
        rv = rv.Insert(0, '1');
    }
    string result = rv.ToString();
    return result;
}
*/

/*
// Encode a number in Base X
string utils::encodeBase58(unsigned long long num, const string& alphabet)
{
    if (num == 0) {
        return alphabet.substr(0,1);
	}
    string arr = "";
	unsigned long long base = alphabet.length();
	while (num) {
        unsigned long long rem = num % base;
        num /= base;
		arr = alphabet.substr(rem,1) + arr;
	}
    return arr;
}

string utils::encodeBase58(mpz_t num, const string& alphabet)
{
    if (num == 0) {
        return alphabet.substr(0,1);
	}
    string arr = "";
	mpz_t base, rem;
	mpz_init(base);
	mpz_init(rem);

	mpz_set_ui(base,(unsigned int)alphabet.length());
	while (mpz_cmp_ui(num,(unsigned int)0)>0) {
		mpz_mod(rem,num,base);
		mpz_div(num,num,base);
		arr = alphabet.substr((int)mpz_get_ui(rem),1) + arr;
	}
    return arr;
}

// Decode a Base X encoded string into the number
unsigned long long utils::decodeBase58(const string& encoded, const string& alphabet)
{
    unsigned long long base = alphabet.length();
    unsigned long long str_len = encoded.length();
    unsigned long long num = 0, index;

	unsigned long long power = str_len - 1;
	for (int i = 0; i < str_len; i++) {
		index = 0;
		while (index < base) {
			if (alphabet.substr(index,1)==encoded.substr(i,1)) break;
			index++;
		}
		if (index < base) {
		    num += index * ipow(base,power);
		}
        power--;
	}
	return num;
}

// Decode a Base X encoded string into the number
void utils::decodeBase58(const string& encoded, mpz_t &result, const string& alphabet)
{
	unsigned int str_len = encoded.length();
	unsigned long long power = str_len - 1;
	mpz_t base, num, index, temp1, temp2;

	mpz_init(result);
	mpz_set_ui(result,(unsigned int)0);
	mpz_init(base);
	mpz_set_ui(base,alphabet.length());
	mpz_init(num);
	mpz_set_ui(num,(unsigned int)0);
	mpz_init(index);
	mpz_init(temp1);
	mpz_init(temp2);

	for (unsigned int i = 0; i < str_len; i++) {
		mpz_set_ui(index,(unsigned int)0);
		while (mpz_cmp(index,base) < 0) {
			if (alphabet.substr(mpz_get_ui(index),1)==encoded.substr(i,1)) break;
			mpz_add_ui(index,index,(unsigned int)1);
		}
		if (mpz_cmp(index,base) < 0) {
			mpz_pow_ui(temp1,base,power);
			mpz_mul(temp2,index,temp1);
			mpz_add(num,num,temp2);
		}
        power--;
	}
	mpz_add(result,result,num);
}
*/

template<class T>
ByteVector utils::pack(T value)
{
    ByteVector b;

    switch(sizeof(value))
    {
    case 1:
        b.resize(1);
        memcpy((void*)&b[0], &value, 1);
        break;
    case 2:
        b.resize(2);
        value = host_to_big_16(value);
        memcpy((void*)&b[0], &value, 2);
        break;
    case 4:
        b.resize(4);
        value = host_to_big_32(value);
        memcpy((void*)&b[0], &value, 4);
        break;
    case 8:
        b.resize(8);
        value = host_to_big_64(value);
        memcpy((void*)&b[0], &value, 8);
        break;
    }

    return b;
}

template ByteVector utils::pack(uint8_t);
template ByteVector utils::pack(uint16_t);
template ByteVector utils::pack(uint32_t);
template ByteVector utils::pack(uint64_t);

template<class T>
T utils::unpack(const ByteVector& data)
{
    //if(data.size() < sizeof(T)) // FIXME: report error
    T result = 0;
    memcpy((void*)&result, (void*)&data[0], sizeof(T));
    switch(sizeof(T))
    {
    case 2: result = big_to_host_16(result); break;
    case 4: result = big_to_host_32(result); break;
    case 8: result = big_to_host_64(result); break;
    }
    return result;
}

template uint8_t utils::unpack(const ByteVector&);
template uint16_t utils::unpack(const ByteVector&);
template uint32_t utils::unpack(const ByteVector&);
template uint64_t utils::unpack(const ByteVector&);

} // namespace bm
