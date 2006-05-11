/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**@file sofia-sip/sha1.h
 *
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 * @par
 *      The SHA-1 produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 * @par Portability Issues
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *      bit unsigned integer types.  If your C compiler does not
 *      support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 * @par Caveats
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long. Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 *
 * @par
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#ifndef SU_TYPES_H
#include <sofia-sip/su_types.h>
/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 *    name              meaning
 *  uint32_t         unsigned 32 bit integer
 *  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
 *  int_least16_t    integer of >= 16 bits
 *
 */
#endif

SOFIA_BEGIN_DECLS

#ifndef _SHA_enum_
#define _SHA_enum_
/** SHA1 Error Codes */
enum 
{
    shaSuccess = 0,	/**< Successful call */
    shaNull,            /**< Null pointer parameter */
    shaInputTooLong,    /**< Input data too long */
    shaStateError       /**< Called Input after Result */
};
#endif

#define SHA1HashSize 20

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /**< Message Digest  */

    uint32_t Length_Low;	/**< Message length in bits      */
    uint32_t Length_High;	/**< Message length in bits      */

    unsigned Computed : 1;	/**< Is the digest computed?          */
    unsigned Corrupted : 1;	/**< Is the message digest corrupted? */
    unsigned : 0;
				/** Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];	/**< 512-bit message blocks      */

} SHA1Context;

/*
 *  Function Prototypes
 */


SOFIAPUBFUN int SHA1Reset(  SHA1Context *);
SOFIAPUBFUN int SHA1Input(  SHA1Context *,
			    const uint8_t *,
			    unsigned int);
SOFIAPUBFUN int SHA1Result( SHA1Context *,
			    uint8_t Message_Digest[SHA1HashSize]);
SOFIA_END_DECLS

#endif
