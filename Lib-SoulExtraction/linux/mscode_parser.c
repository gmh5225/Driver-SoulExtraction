// SPDX-License-Identifier: GPL-2.0-or-later
/* Parse a Microsoft Individual Code Signing blob
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

//#define pr_fmt(fmt) "MSCODE: "fmt
//#include <linux/kernel.h>
//#include <linux/slab.h>
//#include <linux/err.h>
//#include <linux/oid_registry.h>
//#include <crypto/pkcs7.h>
//#include "verify_pefile.h"
//#include "mscode.asn1.h"

#include "verify_pefile.h"
#include "pkcs7.h"
#include "asn1.h"
#include "asn1_ber_bytecode.h"
#include "asn1_decoder.h"
#include "errno.h"
#include "oid_registry.h"

#include "../rewrite/Lib.SoulExtraction.rewrite.h"

#define pr_debug
#define pr_devel
#define pr_warn
#define pr_err
#define printk

#define GFP_ATOMIC /*(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)*/ 1
#define GFP_KERNEL /*(__GFP_RECLAIM | __GFP_IO | __GFP_FS)*/ 2
#define GFP_KERNEL_ACCOUNT /*(GFP_KERNEL | __GFP_ACCOUNT)*/ 3
#define GFP_NOWAIT /*(__GFP_KSWAPD_RECLAIM)*/ 4
#define GFP_NOIO /*(__GFP_RECLAIM)*/ 5
#define GFP_NOFS /*(__GFP_RECLAIM | __GFP_IO)*/ 6
#define GFP_USER /*(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)*/ 7
#define GFP_DMA /*__GFP_DMA*/ 8
#define GFP_DMA32 /*__GFP_DMA32*/ 9
#define GFP_HIGHUSER /*(GFP_USER | __GFP_HIGHMEM)*/ 10
#define GFP_HIGHUSER_MOVABLE /*(GFP_HIGHUSER | __GFP_MOVABLE)*/ 11
#define GFP_TRANSHUGE_LIGHT 12
#define GFP_TRANSHUGE /*(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)*/ 13

#define ERR_PTR(err) ((void *)((long)(err)))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(ptr) > (unsigned long)(-1000))

//
// fun decla
//

/*
 * Check the content type OID
 */
int
mscode_note_content_type(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the digest we're guaranteeing with this certificate
 */
int
mscode_note_digest(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the digest algorithm OID
 */
int
mscode_note_digest_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

//
// enum
//

enum mscode_actions
{
    ACT_mscode_note_content_type = 0,
    ACT_mscode_note_digest = 1,
    ACT_mscode_note_digest_algo = 2,
    NR__mscode_actions = 3
};

//
// global
//

static const asn1_action_t mscode_action_table[NR__mscode_actions] = {
    mscode_note_content_type,
    mscode_note_digest,
    mscode_note_digest_algo,
};

static const unsigned char mscode_machine[] = {
    // MSCode
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH, // type
    _tag(UNIV, CONS, SEQ),
    // ContentType
    ASN1_OP_MATCH_ACT,
    _tag(UNIV, PRIM, OID),
    _action(ACT_mscode_note_content_type),
    ASN1_OP_MATCH_ANY, // parameters
    ASN1_OP_END_SEQ,
    ASN1_OP_MATCH, // content
    _tag(UNIV, CONS, SEQ),
    // DigestAlgorithmIdentifier
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // algorithm
    _tag(UNIV, PRIM, OID),
    _action(ACT_mscode_note_digest_algo),
    ASN1_OP_MATCH_ANY_OR_SKIP, // parameters
    ASN1_OP_END_SEQ,
    ASN1_OP_MATCH_ACT, // digest
    _tag(UNIV, PRIM, OTS),
    _action(ACT_mscode_note_digest),
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SEQ,
    ASN1_OP_COMPLETE,
};

const struct asn1_decoder mscode_decoder = {
    mscode_machine,
    sizeof(mscode_machine),
    mscode_action_table,
};

/*
 * Parse a Microsoft Individual Code Signing blob
 */
int
mscode_parse(void *_ctx, const void *content_data, size_t data_len, size_t asn1hdrlen)
{
    struct pefile_context *ctx = _ctx;

    content_data = (void *)((unsigned char *)content_data - asn1hdrlen);
    data_len += asn1hdrlen;
    pr_devel("Data: %zu [%*ph]\n", data_len, (unsigned)(data_len), content_data);

    return asn1_ber_decoder(&mscode_decoder, ctx, content_data, data_len);
}

/*
 * Check the content type OID
 */
int
mscode_note_content_type(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    enum OID oid;

    oid = look_up_OID(value, vlen);
    if (oid == OID__NR)
    {
        char buffer[50];

        sprint_oid(value, vlen, buffer, sizeof(buffer));
        pr_err("Unknown OID: %s\n", buffer);
        return -EBADMSG;
    }

    /*
     * pesign utility had a bug where it was putting
     * OID_msIndividualSPKeyPurpose instead of OID_msPeImageDataObjId
     * So allow both OIDs.
     */
    if (oid != OID_msPeImageDataObjId && oid != OID_msIndividualSPKeyPurpose)
    {
        pr_err("Unexpected content type OID %u\n", oid);
        return -EBADMSG;
    }

    return 0;
}

/*
 * Note the digest algorithm OID
 */
int
mscode_note_digest_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    char tmp1[] = {// md4
                   'm',
                   'd',
                   '4',
                   0};

    char tmp2[] = {// md5
                   'm',
                   'd',
                   '5',
                   0};

    char tmp3[] = {// sha1
                   's',
                   'h',
                   'a',
                   '1',
                   0};

    char tmp4[] = {// sha256
                   's',
                   'h',
                   'a',
                   '2',
                   '5',
                   '6',
                   0};

    char tmp5[] = {// sha384
                   's',
                   'h',
                   'a',
                   '3',
                   '8',
                   '4',
                   0};

    char tmp6[] = {// sha512
                   's',
                   'h',
                   'a',
                   '5',
                   '1',
                   '2',
                   0};

    char tmp7[] = {// sha224
                   's',
                   'h',
                   'a',
                   '2',
                   '2',
                   '4',
                   0};

    struct pefile_context *ctx = context;
    char buffer[50];
    enum OID oid;

    oid = look_up_OID(value, vlen);
    switch (oid)
    {
    case OID_md4:
        ctx->digest_algo = tmp1;
        break;
    case OID_md5:
        ctx->digest_algo = tmp2;
        break;
    case OID_sha1:
        ctx->digest_algo = tmp3;
        break;
    case OID_sha256:
        ctx->digest_algo = tmp4;
        break;
    case OID_sha384:
        ctx->digest_algo = tmp5;
        break;
    case OID_sha512:
        ctx->digest_algo = tmp6;
        break;
    case OID_sha224:
        ctx->digest_algo = tmp7;
        break;

    case OID__NR:
        sprint_oid(value, vlen, buffer, sizeof(buffer));
        pr_err("Unknown OID: %s\n", buffer);
        return -EBADMSG;

    default:
        pr_err("Unsupported content type: %u\n", oid);
        return -ENOPKG;
    }

    return 0;
}

/*
 * Note the digest we're guaranteeing with this certificate
 */
int
mscode_note_digest(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pefile_context *ctx = context;

    ctx->digest = kmemdup(value, vlen, GFP_KERNEL);
    if (!ctx->digest)
        return -ENOMEM;

    ctx->digest_len = vlen;

    return 0;
}
