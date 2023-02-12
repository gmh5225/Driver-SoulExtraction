// SPDX-License-Identifier: GPL-2.0-or-later
/* X.509 certificate parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <stdint.h>

#include "../rewrite/Lib.SoulExtraction.rewrite.h"

#include "oid_registry.h"
#include "x509_parser.h"
#include "errno-base.h"
#include "asn1_ber_bytecode.h"
#include "asn1.h"
#include "asn1_decoder.h"
#include "errno.h"
#include "x509_parser.h"

#include "config.h"

// shoudong tianjia...ca
typedef unsigned char u8;
typedef unsigned short u16;

//
// func decl
//

/*
 * Extract the data for the public key algorithm
 */
int
x509_extract_key_data(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int
x509_extract_name_segment(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int
x509_note_OID(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_note_issuer(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_note_not_after(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_note_not_before(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Record the public key algorithm
 */
int
x509_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the certificate serial number
 */
int
x509_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the whereabouts and type of the signature.
 */
int
x509_note_signature(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_note_subject(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_note_tbs_certificate(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int
x509_process_extension(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note a key identifier-based AuthorityKeyIdentifier
 */
int
x509_akid_note_kid(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

int
x509_akid_note_name(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note a serial number in an AuthorityKeyIdentifier
 */
int
x509_akid_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

//
// macro
//

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

#define ERR_PTR(err) ((void *)((LONG_PTR)(err)))
#define PTR_ERR(ptr) ((LONG_PTR)(ptr))
#define IS_ERR(ptr) ((ULONG_PTR)(ptr) > (ULONG_PTR)(-1000))

//
// enum
//

enum x509_actions
{
    ACT_x509_extract_key_data = 0,
    ACT_x509_extract_name_segment = 1,
    ACT_x509_note_OID = 2,
    ACT_x509_note_issuer = 3,
    ACT_x509_note_not_after = 4,
    ACT_x509_note_not_before = 5,
    ACT_x509_note_pkey_algo = 6,
    ACT_x509_note_serial = 7,
    ACT_x509_note_signature = 8,
    ACT_x509_note_subject = 9,
    ACT_x509_note_tbs_certificate = 10,
    ACT_x509_process_extension = 11,
    NR__x509_actions = 12
};

enum x509_akid_actions
{
    ACT_x509_akid_note_kid1 = 0,
    ACT_x509_akid_note_name1 = 1,
    ACT_x509_akid_note_serial1 = 2,
    ACT_x509_extract_name_segment1 = 3,
    ACT_x509_note_OID1 = 4,
    NR__x509_akid_actions1 = 5
};

//
// global
//

static const unsigned char x509_machine[] = {
    // Certificate
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // TBSCertificate
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_JUMP_OR_SKIP, // version
    _tagn(CONT, CONS, 0),
    _jump_target(70),
    // CertificateSerialNumber
    ASN1_OP_MATCH,
    _tag(UNIV, PRIM, INT),
    ASN1_OP_ACT,
    _action(ACT_x509_note_serial),
    // AlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(74), // --> AlgorithmIdentifier
    ASN1_OP_ACT,
    _action(ACT_x509_note_pkey_algo),
    // Name
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(80), // --> Name
    ASN1_OP_ACT,
    _action(ACT_x509_note_issuer),
    // Validity
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // Time
    ASN1_OP_MATCH_OR_SKIP, // utcTime
    _tag(UNIV, PRIM, UNITIM),
    ASN1_OP_COND_MATCH_OR_SKIP, // generalTime
    _tag(UNIV, PRIM, GENTIM),
    ASN1_OP_COND_FAIL,
    ASN1_OP_ACT,
    _action(ACT_x509_note_not_before),
    // Time
    ASN1_OP_MATCH_OR_SKIP, // utcTime
    _tag(UNIV, PRIM, UNITIM),
    ASN1_OP_COND_MATCH_OR_SKIP, // generalTime
    _tag(UNIV, PRIM, GENTIM),
    ASN1_OP_COND_FAIL,
    ASN1_OP_ACT,
    _action(ACT_x509_note_not_after),
    ASN1_OP_END_SEQ,
    // Name
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(80), // --> Name
    ASN1_OP_ACT,
    _action(ACT_x509_note_subject),
    // SubjectPublicKeyInfo
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // AlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(74),  // --> AlgorithmIdentifier
    ASN1_OP_MATCH_ACT, // subjectPublicKey
    _tag(UNIV, PRIM, BTS),
    _action(ACT_x509_extract_key_data),
    ASN1_OP_END_SEQ,
    +                      // UniqueIdentifier
    ASN1_OP_MATCH_OR_SKIP, // issuerUniqueID
    _tagn(CONT, PRIM, 1),
    // UniqueIdentifier
    ASN1_OP_MATCH_OR_SKIP, // subjectUniqueID
    _tagn(CONT, PRIM, 2),
    ASN1_OP_MATCH_JUMP_OR_SKIP, // extensions
    _tagn(CONT, CONS, 3),
    _jump_target(95),
    ASN1_OP_END_SEQ,
    ASN1_OP_ACT,
    _action(ACT_x509_note_tbs_certificate),
    // AlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(74),  // --> AlgorithmIdentifier
    ASN1_OP_MATCH_ACT, // signature
    _tag(UNIV, PRIM, BTS),
    _action(ACT_x509_note_signature),
    ASN1_OP_END_SEQ,
    ASN1_OP_COMPLETE,

    // Version
    ASN1_OP_MATCH,
    _tag(UNIV, PRIM, INT),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ACT, // algorithm
    _tag(UNIV, PRIM, OID),
    _action(ACT_x509_note_OID),
    ASN1_OP_MATCH_ANY_OR_SKIP, // parameters
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // RelativeDistinguishedName
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SET),
    // AttributeValueAssertion
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // attributeType
    _tag(UNIV, PRIM, OID),
    _action(ACT_x509_note_OID),
    ASN1_OP_MATCH_ANY_ACT, // attributeValue
    _action(ACT_x509_extract_name_segment),
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SET_OF,
    _jump_target(82),
    ASN1_OP_END_SEQ_OF,
    _jump_target(80),
    ASN1_OP_RETURN,

    // Extensions
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // Extension
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // extnid
    _tag(UNIV, PRIM, OID),
    _action(ACT_x509_note_OID),
    ASN1_OP_MATCH_OR_SKIP, // critical
    _tag(UNIV, PRIM, BOOL),
    ASN1_OP_MATCH_ACT, // extnValue
    _tag(UNIV, PRIM, OTS),
    _action(ACT_x509_process_extension),
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SEQ_OF,
    _jump_target(97),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,
};

static const asn1_action_t x509_action_table[NR__x509_actions] = {
    x509_extract_key_data,
    x509_extract_name_segment,
    x509_note_OID,
    x509_note_issuer,
    x509_note_not_after,
    x509_note_not_before,
    x509_note_pkey_algo,
    x509_note_serial,
    x509_note_signature,
    x509_note_subject,
    x509_note_tbs_certificate,
    x509_process_extension,
};

struct asn1_decoder x509_decoder = {
    x509_machine,
    sizeof(x509_machine),
    x509_action_table,
};

static const asn1_action_t x509_akid_action_table[NR__x509_akid_actions1] = {
    x509_akid_note_kid,
    x509_akid_note_name,
    x509_akid_note_serial,
    x509_extract_name_segment,
    x509_note_OID,
};

static const UCHAR x509_akid_machine[] = {
    // AuthorityKeyIdentifier
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // KeyIdentifier
    ASN1_OP_MATCH_ACT_OR_SKIP, // keyIdentifier
    _tagn(CONT, PRIM, 0),
    _action(ACT_x509_akid_note_kid1),
    // GeneralNames
    ASN1_OP_MATCH_JUMP_OR_SKIP, // authorityCertIssuer
    _tagn(CONT, CONS, 1),
    _jump_target(13), // --> GeneralNames
    // CertificateSerialNumber
    ASN1_OP_MATCH_ACT_OR_SKIP, // authorityCertSerialNumber
    _tagn(CONT, PRIM, 2),
    _action(ACT_x509_akid_note_serial1),
    ASN1_OP_END_SEQ,
    ASN1_OP_COMPLETE,

    // GeneralName
    ASN1_OP_MATCH_JUMP_OR_SKIP, // otherName
    _tagn(CONT, CONS, 0),
    _jump_target(44),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // rfc822Name
    _tagn(CONT, CONS, 1),
    _jump_target(47),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // dNSName
    _tagn(CONT, CONS, 2),
    _jump_target(51),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // x400Address
    _tagn(CONT, CONS, 3),
    _jump_target(55),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // directoryName
    _tagn(CONT, CONS, 4),
    _jump_target(58),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // ediPartyName
    _tagn(CONT, CONS, 5),
    _jump_target(78),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // uniformResourceIdentifier
    _tagn(CONT, CONS, 6),
    _jump_target(81),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // iPAddress
    _tagn(CONT, CONS, 7),
    _jump_target(85),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // registeredID
    _tagn(CONT, CONS, 8),
    _jump_target(89),
    ASN1_OP_COND_FAIL,
    ASN1_OP_END_SEQ_OF,
    _jump_target(13),
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ANY, // otherName
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // rfc822Name
    _tag(UNIV, PRIM, IA5STR),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // dNSName
    _tag(UNIV, PRIM, IA5STR),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ANY, // x400Address
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // Name
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // RelativeDistinguishedName
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SET),
    // AttributeValueAssertion
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // attributeType
    _tag(UNIV, PRIM, OID),
    _action(ACT_x509_note_OID),
    ASN1_OP_MATCH_ANY_ACT, // attributeValue
    _action(ACT_x509_extract_name_segment),
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SET_OF,
    _jump_target(62),
    ASN1_OP_END_SEQ_OF,
    _jump_target(60),
    ASN1_OP_ACT,
    _action(ACT_x509_akid_note_name1),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ANY, // ediPartyName
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // uniformResourceIdentifier
    _tag(UNIV, PRIM, IA5STR),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // iPAddress
    _tag(UNIV, PRIM, OTS),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // registeredID
    _tag(UNIV, PRIM, OID),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,
};

struct asn1_decoder x509_akid_decoder = {
    x509_akid_machine,
    sizeof(x509_akid_machine),
    x509_akid_action_table,
};

/*
 * Free an X.509 certificate
 */
void
x509_free_certificate(struct x509_certificate *cert)
{
    if (cert)
    {
        public_key_free(cert->pub);
        public_key_signature_free(cert->sig);
        kfree(cert->issuer);
        kfree(cert->subject);
        kfree(cert->id);
        kfree(cert->skid);
        kfree(cert);
    }
}
// EXPORT_SYMBOL_GPL(x509_free_certificate);

/*
 * Parse an X.509 certificate
 */
struct x509_certificate *
x509_cert_parse(const void *data, size_t datalen)
{
    struct x509_certificate *cert;
    struct x509_parse_context *ctx;
    struct asymmetric_key_id *kid;
    /*long*/ LONG_PTR ret;

    ret = -ENOMEM;
    cert = kzalloc(sizeof(struct x509_certificate), GFP_KERNEL);
    if (!cert)
        goto error_no_cert;
    cert->pub = kzalloc(sizeof(struct public_key), GFP_KERNEL);
    if (!cert->pub)
        goto error_no_ctx;
    cert->sig = kzalloc(sizeof(struct public_key_signature), GFP_KERNEL);
    if (!cert->sig)
        goto error_no_ctx;
    ctx = kzalloc(sizeof(struct x509_parse_context), GFP_KERNEL);
    if (!ctx)
        goto error_no_ctx;

    ctx->cert = cert;
    /*ctx->data = (unsigned long)data;*/

    ctx->data = (void *)data;

    /* Attempt to decode the certificate */
    ret = asn1_ber_decoder(&x509_decoder, ctx, data, datalen);
    if (ret < 0)
        goto error_decode;

    /* Decode the AuthorityKeyIdentifier */
    if (ctx->raw_akid)
    {
        cert->raw_akid_size = ctx->raw_akid_size;

        pr_devel("AKID: raw_akid_size=%u raw_akid=%p\n", ctx->raw_akid_size, ctx->raw_akid);
        ret = asn1_ber_decoder(&x509_akid_decoder, ctx, ctx->raw_akid, ctx->raw_akid_size);
        if (ret < 0)
        {
            pr_warn("Couldn't decode AuthKeyIdentifier\n");
            goto error_decode;
        }
    }

    ret = -ENOMEM;
    cert->pub->key = kmemdup(ctx->key, ctx->key_size, GFP_KERNEL);
    if (!cert->pub->key)
        goto error_decode;

    cert->pub->keylen = ctx->key_size;

    /*cert->pub->params = (const void	*)kmemdup(ctx->params, ctx->params_size, GFP_KERNEL);
    if (!cert->pub->params)
    goto error_decode;

    cert->pub->paramlen = ctx->params_size;
    cert->pub->algo = ctx->key_algo;*/

    /* Grab the signature bits */

    /*ret = x509_get_sig_params(cert);
    if (ret < 0)
    goto error_decode;*/

    /* Generate cert issuer + serial number key ID */
    kid = asymmetric_key_generate_id(cert->raw_serial, cert->raw_serial_size, cert->raw_issuer, cert->raw_issuer_size);

    if (IS_ERR(kid))
    {
        ret = PTR_ERR(kid);
        goto error_decode;
    }
    cert->id = kid;

    /* Detect self-signed certificates */

    /*ret = x509_check_for_self_signed(cert);
    if (ret < 0)
        goto error_decode;*/

    kfree(ctx);
    return cert;

error_decode:
    kfree(ctx);
error_no_ctx:
    x509_free_certificate(cert);
error_no_cert:
    return ERR_PTR(ret);
}
// EXPORT_SYMBOL_GPL(x509_cert_parse);

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int
x509_note_OID(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;

    ctx->last_oid = look_up_OID(value, vlen);
    if (ctx->last_oid == OID__NR)
    {
        char buffer[50];
        sprint_oid(value, vlen, buffer, sizeof(buffer));
        pr_debug("Unknown OID: [%lu] %s\n", (ULONG_PTR)value - (ULONG_PTR)ctx->data, buffer);
    }
    return 0;
}

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int
x509_note_tbs_certificate(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;

    pr_debug(
        "x509_note_tbs_certificate(,%u,%02x,%ld,%u)!\n", hdrlen, tag, (ULONG_PTR)value - (ULONG_PTR)ctx->data, vlen);

    ctx->cert->tbs = (const void *)((unsigned char *)value - hdrlen);
    ctx->cert->tbs_size = vlen + hdrlen;
    return 0;
}

/*
 * Record the public key algorithm
 */
int
x509_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    char tmp1[] = {// md4
                   'm',
                   'd',
                   '4',
                   0};

    char tmp2[] = {// rsa
                   'r',
                   's',
                   'a',
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

    struct x509_parse_context *ctx = context;

    pr_debug("PubKey Algo: %u\n", ctx->last_oid);

    switch (ctx->last_oid)
    {
    case OID_md2WithRSAEncryption:
    case OID_md3WithRSAEncryption:
    default:
        return -ENOPKG; /* Unsupported combination */

    case OID_md4WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp1;
        ctx->cert->sig->pkey_algo = "sar";
        break;

    case OID_sha1WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp3;
        ctx->cert->sig->pkey_algo = "sar";
        break;

    case OID_sha256WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp4;
        ctx->cert->sig->pkey_algo = "sar";
        break;

    case OID_sha384WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp5;
        ctx->cert->sig->pkey_algo = "sar";
        break;

    case OID_sha512WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp6;
        ctx->cert->sig->pkey_algo = "sar";
        break;

    case OID_sha224WithRSAEncryption:
        ctx->cert->sig->hash_algo = tmp7;
        ctx->cert->sig->pkey_algo = "sar";
        break;
    }

    ctx->algo_oid = ctx->last_oid;
    return 0;
}

/*
 * Note the whereabouts and type of the signature.
 */
int
x509_note_signature(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    // char tmp1[] = {//rsa
    //	'r','s','a',0
    // };

    char tmp1[] = {// rsa
                   's',
                   'a',
                   'r',
                   0};

    struct x509_parse_context *ctx = context;

    pr_debug("Signature type: %u size %zu\n", ctx->last_oid, vlen);

    if (ctx->last_oid != ctx->algo_oid)
    {
        pr_warn("Got cert with pkey (%u) and sig (%u) algorithm OIDs\n", ctx->algo_oid, ctx->last_oid);
        return -EINVAL;
    }

    if (strcmp(ctx->cert->sig->pkey_algo, tmp1) == 0)
    {
        /* Discard the BIT STRING metadata */
        if (vlen < 1 || *(const u8 *)value != 0)
            return -EBADMSG;

        value = (void *)((unsigned char *)value + 1);
        vlen--;
    }

    ctx->cert->raw_sig = value;
    ctx->cert->raw_sig_size = vlen;
    return 0;
}

/*
 * Note the certificate serial number
 */
int
x509_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    ctx->cert->raw_serial = value;
    ctx->cert->raw_serial_size = vlen;
    return 0;
}

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int
x509_extract_name_segment(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;

    switch (ctx->last_oid)
    {
    case OID_commonName:
        ctx->cn_size = vlen;
        ctx->cn_offset = (u16)((ULONG_PTR)value - (ULONG_PTR)ctx->data);
        break;
    case OID_organizationName:
        ctx->o_size = vlen;
        ctx->o_offset = (u16)((ULONG_PTR)value - (ULONG_PTR)ctx->data);
        break;
    case OID_email_address:
        ctx->email_size = vlen;
        ctx->email_offset = (u16)((ULONG_PTR)value - (ULONG_PTR)ctx->data);
        break;
    default:
        break;
    }

    return 0;
}

/*
 * Fabricate and save the issuer and subject names
 */
static int
x509_fabricate_name(struct x509_parse_context *ctx, size_t hdrlen, unsigned char tag, char **_name, size_t vlen)
{
    const void *name, *data = (const void *)ctx->data;
    size_t namesize;
    char *buffer;

    if (*_name)
        return -EINVAL;

    /* Empty name string if no material */
    if (!ctx->cn_size && !ctx->o_size && !ctx->email_size)
    {
        buffer = kmalloc(1, GFP_KERNEL);
        if (!buffer)
            return -ENOMEM;
        buffer[0] = 0;
        goto done;
    }

    if (ctx->cn_size && ctx->o_size)
    {
        /* Consider combining O and CN, but use only the CN if it is
         * prefixed by the O, or a significant portion thereof.
         */
        namesize = ctx->cn_size;
        name = (void *)((unsigned char *)data + ctx->cn_offset);
        if (ctx->cn_size >= ctx->o_size && memcmp(
                                               (void *)((unsigned char *)data + ctx->cn_offset),
                                               (void *)((unsigned char *)data + ctx->o_offset),
                                               ctx->o_size) == 0)
            goto single_component;
        if (ctx->cn_size >= 7 && ctx->o_size >= 7 &&
            memcmp(
                (void *)((unsigned char *)data + ctx->cn_offset), (void *)((unsigned char *)data + ctx->o_offset), 7) ==
                0)
            goto single_component;

        buffer = kmalloc(ctx->o_size + 2 + ctx->cn_size + 1, GFP_KERNEL);
        if (!buffer)
            return -ENOMEM;

        memcpy(buffer, (void *)((unsigned char *)data + ctx->o_offset), ctx->o_size);
        buffer[ctx->o_size + 0] = ':';
        buffer[ctx->o_size + 1] = ' ';
        memcpy(buffer + ctx->o_size + 2, (void *)((unsigned char *)data + ctx->cn_offset), ctx->cn_size);
        buffer[ctx->o_size + 2 + ctx->cn_size] = 0;
        goto done;
    }
    else if (ctx->cn_size)
    {
        namesize = ctx->cn_size;
        name = (void *)((unsigned char *)data + ctx->cn_offset);
    }
    else if (ctx->o_size)
    {
        namesize = ctx->o_size;
        name = (void *)((unsigned char *)data + ctx->o_offset);
    }
    else
    {
        namesize = ctx->email_size;
        name = (void *)((unsigned char *)data + ctx->email_offset);
    }

single_component:
    buffer = kmalloc(namesize + 1, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;
    memcpy(buffer, name, namesize);
    buffer[namesize] = 0;

done:
    *_name = buffer;
    pr_debug("x509_fabricate_name:name=%s,tag=%d\n", buffer, tag);
    ctx->cn_size = 0;
    ctx->o_size = 0;
    ctx->email_size = 0;
    return 0;
}

int
x509_note_issuer(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    ctx->cert->raw_issuer = value;
    ctx->cert->raw_issuer_size = vlen;
    ctx->cert->issuer_tag = tag;
    pr_debug("x509_note_issuer:tag=%d,raw_issuer=%p\n", tag, value);
    return x509_fabricate_name(ctx, hdrlen, tag, &ctx->cert->issuer, vlen);
}

int
x509_note_subject(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    ctx->cert->raw_subject = value;
    ctx->cert->raw_subject_size = vlen;
    ctx->cert->subject_tag = tag;
    pr_debug("x509_note_subject:tag=%d,raw_subject=%p\n", tag, value);
    return x509_fabricate_name(ctx, hdrlen, tag, &ctx->cert->subject, vlen);
}

/*
 * Extract the parameters for the public key
 */
// int x509_note_params(void *context, size_t hdrlen,
//		     unsigned char tag,
//		     const void *value, size_t vlen)
//{
//	struct x509_parse_context *ctx = context;
//
//	/*
//	 * AlgorithmIdentifier is used three times in the x509, we should skip
//	 * first and ignore third, using second one which is after subject and
//	 * before subjectPublicKey.
//	 */
//	if (!ctx->cert->raw_subject || ctx->key)
//		return 0;
//	ctx->params = (void*)((unsigned char*)value - hdrlen);
//	ctx->params_size = vlen + hdrlen;
//	return 0;
// }

/*
 * Extract the data for the public key algorithm
 */
int
x509_extract_key_data(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    char tmp1[] = {'s', 'a', 'r', 0};

    struct x509_parse_context *ctx = (struct x509_parse_context *)context;

    if (ctx->last_oid != OID_rsaEncryption)
        return -EBADMSG;

    ctx->cert->pub->pkey_algo = tmp1;

    /* Discard the BIT STRING metadata */
    if (vlen < 1 || *(const UCHAR *)value != 0)
        return -EBADMSG;
    ctx->key = (void *)((unsigned char *)value + 1);
    ctx->key_size = vlen - 1;
    return 0;
}

/* The keyIdentifier in AuthorityKeyIdentifier SEQUENCE is tag(CONT,PRIM,0) */
#define SEQ_TAG_KEYID (ASN1_CONT << 6)

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int
x509_process_extension(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    struct asymmetric_key_id *kid;
    const unsigned char *v = value;

    pr_debug("Extension: %u\n", ctx->last_oid);

    if (ctx->last_oid == OID_subjectKeyIdentifier)
    {
        /* Get hold of the key fingerprint */
        if (ctx->cert->skid || vlen < 3)
            return -EBADMSG;
        if (v[0] != ASN1_OTS || v[1] != vlen - 2)
            return -EBADMSG;
        v += 2;
        vlen -= 2;

        ctx->cert->raw_skid_size = vlen;
        ctx->cert->raw_skid = v;
        pr_debug("subjkeyid raw_skid_size=%d,raw_skid=%p\n", vlen, v);

        kid = asymmetric_key_generate_id(v, vlen, "", 0);

        if (IS_ERR(PtrToUlong(kid)))
            return PTR_ERR(PtrToUlong(kid));
        ctx->cert->skid = kid;
        pr_debug("subjkeyid %p\n", kid->len, kid->data);
        return 0;
    }

    if (ctx->last_oid == OID_authorityKeyIdentifier)
    {
        /* Get hold of the CA key fingerprint */
        ctx->raw_akid = v;
        ctx->raw_akid_size = vlen;
        return 0;
    }

    return 0;
}

/**
 * x509_decode_time - Decode an X.509 time ASN.1 object
 * @_t: The time to fill in
 * @hdrlen: The length of the object header
 * @tag: The object tag
 * @value: The object value
 * @vlen: The size of the object value
 *
 * Decode an ASN.1 universal time or generalised time field into a struct the
 * kernel can handle and check it for validity.  The time is decoded thus:
 *
 *	[RFC5280 ¡ì4.1.2.5]
 *	CAs conforming to this profile MUST always encode certificate validity
 *	dates through the year 2049 as UTCTime; certificate validity dates in
 *	2050 or later MUST be encoded as GeneralizedTime.  Conforming
 *	applications MUST be able to process validity dates that are encoded in
 *	either UTCTime or GeneralizedTime.
 */
int
x509_decode_time(
    struct x509_certificate *cert,
    unsigned char isfrom,
    unsigned char issign,
    /*time64_t*/ long long *_t,
    size_t hdrlen,
    unsigned char tag,
    const unsigned char *value,
    size_t vlen)
{
    static const unsigned char month_lengths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    unsigned char *p = (unsigned char *)value;

    unsigned year, mon, day, hour, min, sec, mon_len;

    //#define dec2bin(X) ({ unsigned char y = (X) - '0'; if (y > 9) goto invalid_time;})
    //#define DD2bin(P) ({ unsigned x = dec2bin(P[0]) * 10 + dec2bin(P[1]); P += 2;})

    if (tag == ASN1_UNITIM)
    {
        /* UTCTime: YYMMDDHHMMSSZ */
        if (vlen != 13)
            goto unsupported_time;
        year = DD2bin(&p);
        if (year == -1)
            goto invalid_time;
        if (year >= 50)
            year += 1900;
        else
            year += 2000;
    }
    else if (tag == ASN1_GENTIM)
    {
        /* GenTime: YYYYMMDDHHMMSSZ */
        if (vlen != 15)
            goto unsupported_time;
        year = DD2bin(&p) * 100 + DD2bin(&p);
        if (year == -1)
            goto invalid_time;
        if (year >= 1950 && year <= 2049)
            goto invalid_time;
    }
    else
    {
        goto unsupported_time;
    }

    mon = DD2bin(&p);
    if (mon == -1)
        goto invalid_time;
    day = DD2bin(&p);
    if (day == -1)
        goto invalid_time;
    hour = DD2bin(&p);
    if (hour == -1)
        goto invalid_time;
    min = DD2bin(&p);
    if (min == -1)
        goto invalid_time;
    sec = DD2bin(&p);
    if (sec == -1)
        goto invalid_time;

    if (*p != 'Z')
        goto unsupported_time;

    if (year < 1970 || mon < 1 || mon > 12)
        goto invalid_time;

    mon_len = month_lengths[mon - 1];
    if (mon == 2)
    {
        if (year % 4 == 0)
        {
            mon_len = 29;
            if (year % 100 == 0)
            {
                mon_len = 28;
                if (year % 400 == 0)
                    mon_len = 29;
            }
        }
    }

    if (day < 1 || day > mon_len || hour > 24 || /* ISO 8601 permits 24:00:00 as midnight tomorrow */
        min > 59 || sec > 60)                    /* ISO 8601 permits leap seconds [X.680 46.3] */
        goto invalid_time;

    *_t = mktime64(year, mon, day, hour, min, sec);

    if (cert)
    {
        if (isfrom)
        {
            cert->valid_from_year = year;
            cert->valid_from_mon = mon;
            cert->valid_from_day = day;
            cert->valid_from_hour = hour;
            cert->valid_from_min = min;
        }
        else
        {
            cert->valid_to_year = year;
            cert->valid_to_mon = mon;
            cert->valid_to_day = day;
            cert->valid_to_hour = hour;
            cert->valid_to_min = min;
        }

        if (issign)
        {
            cert->sign_time = *_t;

            cert->sign_time_year = year;
            cert->sign_time_mon = mon;
            cert->sign_time_day = day;
            cert->sign_time_hour = hour;
            cert->sign_time_min = min;
        }
    }

    pr_debug("x509_decode_time:yead=%d,mon=%d,day=%d,hour=%d,min=%d,sec=%d\n", year, mon, day, hour, min, sec);
    return 0;

unsupported_time:
    pr_debug("Got unsupported time [tag %02x]: '%p'\n", tag, (int)vlen, value);
    return -EBADMSG;
invalid_time:
    pr_debug("Got invalid time [tag %02x]: '%p'\n", tag, (int)vlen, value);
    return -EBADMSG;
}
// EXPORT_SYMBOL_GPL(x509_decode_time);

int
x509_note_not_before(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    return x509_decode_time(ctx->cert, TRUE, FALSE, &ctx->cert->valid_from, hdrlen, tag, value, vlen);
}

int
x509_note_not_after(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    return x509_decode_time(ctx->cert, FALSE, FALSE, &ctx->cert->valid_to, hdrlen, tag, value, vlen);
}

/*
 * Note a key identifier-based AuthorityKeyIdentifier
 */
int
x509_akid_note_kid(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    struct asymmetric_key_id *kid;

    pr_debug("AKID: vlen:%d,keyid: %p\n", (int)vlen, value);

    if (ctx->cert->sig->auth_ids[1])
        return 0;

    kid = asymmetric_key_generate_id(value, vlen, "", 0);
    if (IS_ERR(PtrToUlong(kid)))
        return PTR_ERR(PtrToUlong(kid));
    pr_debug("len=%d,authkeyid %p\n", kid->len, kid->data);
    ctx->cert->sig->auth_ids[1] = kid;
    return 0;
}

/*
 * Note a directoryName in an AuthorityKeyIdentifier
 */
int
x509_akid_note_name(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;

    pr_debug("AKID: name: %p\n", (int)vlen, value);

    ctx->akid_raw_issuer = value;
    ctx->akid_raw_issuer_size = vlen;
    return 0;
}

/*
 * Note a serial number in an AuthorityKeyIdentifier
 */
int
x509_akid_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct x509_parse_context *ctx = context;
    struct asymmetric_key_id *kid;

    pr_debug("AKID: vlen=%d,serial: %p\n", (int)vlen, value);

    if (!ctx->akid_raw_issuer || ctx->cert->sig->auth_ids[0])
        return 0;

    kid = asymmetric_key_generate_id(value, vlen, ctx->akid_raw_issuer, ctx->akid_raw_issuer_size);
    if (IS_ERR(PtrToUlong(kid)))
        return PTR_ERR(PtrToUlong(kid));

    pr_debug("authkeyid len:%d,data=%p\n", kid->len, kid->data);
    ctx->cert->sig->auth_ids[0] = kid;
    return 0;
}
