// SPDX-License-Identifier: GPL-2.0-or-later
/* ASN.1 Object identifier (OID) registry
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include "oid_registry.h"
#include "errno.h"

#include "../rewrite/Lib.SoulExtraction.rewrite.h"

//
// struct
//

struct t1
{
    unsigned char hash;
    enum OID oid : 8;
};

// global
static const unsigned char oid_data[381] = {
    42, 134, 72, 206, 46,  4,   3,                  // id_dsa_with_sha1
    42, 134, 72, 206, 56,  4,   1,                  // id_dsa
    42, 134, 72, 206, 61,  4,   1,                  // id_ecdsa_with_sha1
    42, 134, 72, 206, 61,  2,   1,                  // id_ecPublicKey
    42, 134, 72, 134, 247, 13,  1,  1,  1,          // rsaEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  2,          // md2WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  3,          // md3WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  4,          // md4WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  5,          // sha1WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  11,         // sha256WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  12,         // sha384WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  13,         // sha512WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  1,  14,         // sha224WithRSAEncryption
    42, 134, 72, 134, 247, 13,  1,  7,  1,          // data
    42, 134, 72, 134, 247, 13,  1,  7,  2,          // signed_data
    42, 134, 72, 134, 247, 13,  1,  9,  1,          // email_address
    42, 134, 72, 134, 247, 13,  1,  9,  3,          // contentType
    42, 134, 72, 134, 247, 13,  1,  9,  4,          // messageDigest
    42, 134, 72, 134, 247, 13,  1,  9,  5,          // signingTime	2a864886f70d010905
    42, 134, 72, 134, 247, 13,  1,  9,  15,         // smimeCapabilites
    42, 134, 72, 134, 247, 13,  1,  9,  16, 2,  11, // smimeAuthenticatedAttrs
    42, 134, 72, 134, 247, 13,  2,  2,              // md2
    42, 134, 72, 134, 247, 13,  2,  4,              // md4
    42, 134, 72, 134, 247, 13,  2,  5,              // md5
    43, 6,   1,  4,   1,   130, 55, 2,  1,  4,      // msIndirectData
    43, 6,   1,  4,   1,   130, 55, 2,  1,  11,     // msStatementType
    43, 6,   1,  4,   1,   130, 55, 2,  1,  12,     // msSpOpusInfo
    43, 6,   1,  4,   1,   130, 55, 2,  1,  15,     // msPeImageDataObjId
    43, 6,   1,  4,   1,   130, 55, 2,  1,  21,     // msIndividualSPKeyPurpose
    43, 6,   1,  4,   1,   130, 55, 16, 4,          // msOutlookExpress
    43, 6,   1,  5,   5,   7,   1,  1,              // certAuthInfoAccess
    43, 14,  3,  2,   26,                           // sha1
    96, 134, 72, 1,   101, 3,   4,  2,  1,          // sha256
    96, 134, 72, 1,   101, 3,   4,  2,  2,          // sha384
    96, 134, 72, 1,   101, 3,   4,  2,  3,          // sha512
    96, 134, 72, 1,   101, 3,   4,  2,  4,          // sha224
    85, 4,   3,                                     // commonName
    85, 4,   4,                                     // surname		55040314
    85, 4,   6,                                     // countryName
    85, 4,   7,                                     // locality
    85, 4,   8,                                     // stateOrProvinceName
    85, 4,   10,                                    // organizationName
    85, 4,   11,                                    // organizationUnitName
    85, 4,   12,                                    // title
    85, 4,   13,                                    // description
    85, 4,   41,                                    // name
    85, 4,   42,                                    // givenName
    85, 4,   43,                                    // initials
    85, 4,   44,                                    // generationalQualifier
    85, 29,  14,                                    // subjectKeyIdentifier
    85, 29,  15,                                    // keyUsage
    85, 29,  17,                                    // subjectAltName
    85, 29,  18,                                    // issuerAltName
    85, 29,  19,                                    // basicConstraints
    85, 29,  31,                                    // crlDistributionPoints
    85, 29,  32,                                    // certPolicies
    85, 29,  35,                                    // authorityKeyIdentifier
    85, 29,  37,                                    // extKeyUsage
};

unsigned short oid_index[OID__NR + 1] = {
    [OID_id_dsa_with_sha1] = 0,
    [OID_id_dsa] = 7,
    [OID_id_ecdsa_with_sha1] = 14,
    [OID_id_ecPublicKey] = 21,
    [OID_rsaEncryption] = 28,
    [OID_md2WithRSAEncryption] = 37,
    [OID_md3WithRSAEncryption] = 46,
    [OID_md4WithRSAEncryption] = 55,
    [OID_sha1WithRSAEncryption] = 64,
    [OID_sha256WithRSAEncryption] = 73,
    [OID_sha384WithRSAEncryption] = 82,
    [OID_sha512WithRSAEncryption] = 91,
    [OID_sha224WithRSAEncryption] = 100,
    [OID_data] = 109,
    [OID_signed_data] = 118,
    [OID_email_address] = 127,
    [OID_contentType] = 136,
    [OID_messageDigest] = 145,
    [OID_signingTime] = 154,
    [OID_smimeCapabilites] = 163,
    [OID_smimeAuthenticatedAttrs] = 172,
    [OID_md2] = 183,
    [OID_md4] = 191,
    [OID_md5] = 199,
    [OID_msIndirectData] = 207,
    [OID_msStatementType] = 217,
    [OID_msSpOpusInfo] = 227,
    [OID_msPeImageDataObjId] = 237,
    [OID_msIndividualSPKeyPurpose] = 247,
    [OID_msOutlookExpress] = 257,
    [OID_certAuthInfoAccess] = 266,
    [OID_sha1] = 274,
    [OID_sha256] = 279,
    [OID_sha384] = 288,
    [OID_sha512] = 297,
    [OID_sha224] = 306,
    [OID_commonName] = 315,
    [OID_surname] = 318,
    [OID_countryName] = 321,
    [OID_locality] = 324,
    [OID_stateOrProvinceName] = 327,
    [OID_organizationName] = 330,
    [OID_organizationUnitName] = 333,
    [OID_title] = 336,
    [OID_description] = 339,
    [OID_name] = 342,
    [OID_givenName] = 345,
    [OID_initials] = 348,
    [OID_generationalQualifier] = 351,
    [OID_subjectKeyIdentifier] = 354,
    [OID_keyUsage] = 357,
    [OID_subjectAltName] = 360,
    [OID_issuerAltName] = 363,
    [OID_basicConstraints] = 366,
    [OID_crlDistributionPoints] = 369,
    [OID_certPolicies] = 372,
    [OID_authorityKeyIdentifier] = 375,
    [OID_extKeyUsage] = 378,
    [OID__NR] = 38,
};

static const struct t1 oid_search_table[OID__NR + 1] = {
    {10, OID_title},                    // 55040c
    {23, OID_issuerAltName},            // 551d12
    {23, OID_initials},                 // 55042b
    {29, OID_md2WithRSAEncryption},     // 2a864886f70d010102
    {30, OID_md2},                      // 2a864886f70d0202
    {32, OID_id_dsa_with_sha1},         // 2a8648ce2e0403
    {35, OID_contentType},              // 2a864886f70d010903
    {35, OID_sha256WithRSAEncryption},  // 2a864886f70d01010b
    {36, OID_authorityKeyIdentifier},   // 551d23
    {37, OID_description},              // 55040d
    {43, OID_id_dsa},                   // 2a8648ce380401
    {51, OID_msIndividualSPKeyPurpose}, // 2b060104018237020115
    {54, OID_basicConstraints},         // 551d13
    {54, OID_generationalQualifier},    // 55042c
    {60, OID_md3WithRSAEncryption},     // 2a864886f70d010103
    {64, OID_signed_data},              // 2a864886f70d010702
    {77, OID_countryName},              // 550406
    {77, OID_id_ecdsa_with_sha1},       // 2a8648ce3d0401
    {83, OID_sha256},                   // 608648016503040201
    {85, OID_smimeCapabilites},         // 2a864886f70d01090f
    {87, OID_sha1},                     // 2b0e03021a
    {97, OID_email_address},            // 2a864886f70d010901
    {106, OID_extKeyUsage},             // 551d25
    {106, OID_msPeImageDataObjId},      // 2b06010401823702010f
    {110, OID_locality},                // 550407
    {126, OID_rsaEncryption},           // 2a864886f70d010101
    {132, OID_smimeAuthenticatedAttrs}, // 2a864886f70d010910020b
    {142, OID_id_ecPublicKey},          // 2a8648ce3d0201
    {142, OID_sha224WithRSAEncryption}, // 2a864886f70d01010e
    {143, OID_stateOrProvinceName},     // 550408
    {146, OID_subjectKeyIdentifier},    // 551d0e
    {157, OID_sha512},                  // 608648016503040203
    {160, OID_data},                    // 2a864886f70d010701
    {161, OID_crlDistributionPoints},   // 551d1f
    {173, OID_msOutlookExpress},        // 2b0601040182371004
    {178, OID_sha384},                  // 608648016503040202
    {179, OID_keyUsage},                // 551d0f
    {195, OID_md4WithRSAEncryption},    // 2a864886f70d010104
    {198, OID_certPolicies},            // 551d20
    {200, OID_msSpOpusInfo},            // 2b06010401823702010c
    {201, OID_organizationName},        // 55040a
    {204, OID_messageDigest},           // 2a864886f70d010904
    {204, OID_sha384WithRSAEncryption}, // 2a864886f70d01010c
    {212, OID_name},                    // 550429
    {213, OID_commonName},              // 550403
    {220, OID_md4},                     // 2a864886f70d0204
    {226, OID_sha1WithRSAEncryption},   // 2a864886f70d010105
    {227, OID_md5},                     // 2a864886f70d0205
    {228, OID_certAuthInfoAccess},      // 2b06010505070101
    {231, OID_msStatementType},         // 2b06010401823702010b
    {234, OID_organizationUnitName},    // 55040b
    {237, OID_signingTime},             // 2a864886f70d010905
    {237, OID_sha512WithRSAEncryption}, // 2a864886f70d01010d
    {244, OID_surname},                 // 550404
    {245, OID_subjectAltName},          // 551d11
    {245, OID_givenName},               // 55042a
    {252, OID_sha224},                  // 608648016503040204
    {255, OID_msIndirectData},          // 2b060104018237020104

};

/**
 * look_up_OID - Find an OID registration for the specified data
 * @data: Binary representation of the OID
 * @datasize: Size of the binary representation
 */
enum OID
look_up_OID(const void *data, size_t datasize)
{
    const unsigned char *octets = data;
    enum OID oid;
    unsigned char xhash;
    unsigned i, j, k, hash;
    size_t len;

    /* Hash the OID data */
    hash = datasize - 1;

    for (i = 0; i < datasize; i++)
        hash += octets[i] * 33;
    hash = (hash >> 24) ^ (hash >> 16) ^ (hash >> 8) ^ hash;
    hash &= 0xff;

    /* Binary search the OID registry.  OIDs are stored in ascending order
     * of hash value then ascending order of size and then in ascending
     * order of reverse value.
     */
    i = 0;
    k = OID__NR;
    while (i < k)
    {
        j = (i + k) / 2;

        xhash = oid_search_table[j].hash;
        if (xhash > hash)
        {
            k = j;
            continue;
        }
        if (xhash < hash)
        {
            i = j + 1;
            continue;
        }

        oid = oid_search_table[j].oid;
        len = oid_index[oid + 1] - oid_index[oid];
        if (len > datasize)
        {
            k = j;
            continue;
        }
        if (len < datasize)
        {
            i = j + 1;
            continue;
        }

        /* Variation is most likely to be at the tail end of the
         * OID, so do the comparison in reverse.
         */
        while (len > 0)
        {
            unsigned char a = oid_data[oid_index[oid] + --len];
            unsigned char b = octets[len];
            if (a > b)
            {
                k = j;
                goto next;
            }
            if (a < b)
            {
                i = j + 1;
                goto next;
            }
        }
        return oid;
    next:;
    }

    return OID__NR;
}
// EXPORT_SYMBOL_GPL(look_up_OID);

/*
 * sprint_OID - Print an Object Identifier into a buffer
 * @data: The encoded OID to print
 * @datasize: The size of the encoded OID
 * @buffer: The buffer to render into
 * @bufsize: The size of the buffer
 *
 * The OID is rendered into the buffer in "a.b.c.d" format and the number of
 * bytes is returned.  -EBADMSG is returned if the data could not be intepreted
 * and -ENOBUFS if the buffer was too small.
 */
int
sprint_oid(const void *data, size_t datasize, char *buffer, size_t bufsize)
{
    char tmp1[] = {//%u.%u
                   '%',
                   'u',
                   '.',
                   '%',
                   'u',
                   0};

    char tmp2[] = {//.%lu
                   '.',
                   '%',
                   'l',
                   'u',
                   0};

    char tmp3[] = {//(bad)
                   '(',
                   'b',
                   'a',
                   'd',
                   ')',
                   0};

    const unsigned char *v = data, *end = v + datasize;
    unsigned long num;
    unsigned char n;
    size_t ret;
    /*int*/ size_t count;

    if (v >= end)
        goto bad;

    n = *v++;
    /*ret = count = snprintf(buffer, bufsize, tmp1, n / 40, n % 40);*/
    count = (size_t)kmysnprintf(buffer, bufsize, tmp1, n / 40, n % 40);
    ret = count;

    if (count >= bufsize)
        return -ENOBUFS;
    buffer += count;
    bufsize -= count;

    while (v < end)
    {
        num = 0;
        n = *v++;
        if (!(n & 0x80))
        {
            num = n;
        }
        else
        {
            num = n & 0x7f;
            do
            {
                if (v >= end)
                    goto bad;
                n = *v++;
                num <<= 7;
                num |= n & 0x7f;
            } while (n & 0x80);
        }
        ret += count = kmysnprintf(buffer, bufsize, tmp2, num);
        if (count >= bufsize)
            return -ENOBUFS;
        buffer += count;
        bufsize -= count;
    }

    return ret;

bad:
    kmysnprintf(buffer, bufsize, tmp3);
    return -EBADMSG;
}
// EXPORT_SYMBOL_GPL(sprint_oid);

/**
 * sprint_OID - Print an Object Identifier into a buffer
 * @oid: The OID to print
 * @buffer: The buffer to render into
 * @bufsize: The size of the buffer
 *
 * The OID is rendered into the buffer in "a.b.c.d" format and the number of
 * bytes is returned.
 */
// int sprint_OID(enum OID oid, char *buffer, size_t bufsize)
//{
//	int ret;
//
//	//BUG_ON(oid >= OID__NR);
//
//	ret = sprint_oid(oid_data + oid_index[oid],
//			 oid_index[oid + 1] - oid_index[oid],
//			 buffer, bufsize);
//	//BUG_ON(ret == -EBADMSG);
//	return ret;
// }
// EXPORT_SYMBOL_GPL(sprint_OID);
