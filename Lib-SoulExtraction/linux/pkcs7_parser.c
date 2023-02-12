/* PKCS#7 parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

//#define pr_fmt(fmt) "PKCS7: "fmt
//#include <linux/kernel.h>
//#include <linux/export.h>
//#include <linux/slab.h>
//#include <linux/err.h>
//#include <linux/oid_registry.h>
//#include <crypto/public_key.h>
//#include "pkcs7_parser.h"
//#include "pkcs7-asn1.h"

#include "pkcs7_parser.h"
#include "errno.h"
#include "asn1_ber_bytecode.h"
#include "asn1.h"
#include "asn1_decoder.h"
#include "config.h"

#include "../rewrite/Lib.SoulExtraction.rewrite.h"

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
// enum
//

enum pkcs7_actions
{
    ACT_pkcs7_check_content_type = 0,
    ACT_pkcs7_extract_cert = 1,
    ACT_pkcs7_note_OID = 2,
    ACT_pkcs7_note_certificate_list = 3,
    ACT_pkcs7_note_content = 4,
    ACT_pkcs7_note_data = 5,
    ACT_pkcs7_note_signed_info = 6,
    ACT_pkcs7_note_signeddata_version = 7,
    ACT_pkcs7_note_signerinfo_version = 8,
    ACT_pkcs7_sig_note_authenticated_attr = 9,
    ACT_pkcs7_sig_note_digest_algo = 10,
    ACT_pkcs7_sig_note_issuer = 11,
    ACT_pkcs7_sig_note_pkey_algo = 12,
    ACT_pkcs7_sig_note_serial = 13,
    ACT_pkcs7_sig_note_set_of_authattrs = 14,
    ACT_pkcs7_sig_note_signature = 15,
    ACT_pkcs7_sig_note_skid = 16,
    NR__pkcs7_actions = 17
};

//
// struct
//

struct pkcs7_parse_context
{
    struct pkcs7_message *msg;       /* Message being constructed */
    struct pkcs7_signed_info *sinfo; /* SignedInfo being constructed */
    struct pkcs7_signed_info **ppsinfo;
    struct x509_certificate *certs; /* Certificate cache */
    struct x509_certificate **ppcerts;
    unsigned long data; /* Start of data */
    enum OID last_oid;  /* Last OID encountered */
    unsigned x509_index;
    unsigned sinfo_index;
    const void *raw_serial;
    unsigned raw_serial_size;
    unsigned raw_issuer_size;
    const void *raw_issuer;
    const void *raw_skid;
    unsigned raw_skid_size;
    /*bool*/ unsigned char expect_skid;
};

// func decl

/*
 * We only support signed data [RFC2315 sec 9].
 */
int
pkcs7_check_content_type(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Extract a certificate and store it in the context.
 */
int
pkcs7_extract_cert(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int
pkcs7_note_OID(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Save the certificate list
 */
int
pkcs7_note_certificate_list(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the content type.
 */
int
pkcs7_note_content(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Extract the data from the message and store that and its content type OID in
 * the context.
 */
int
pkcs7_note_data(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note a signature information block
 */
int
pkcs7_note_signed_info(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the SignedData version
 */
int
pkcs7_note_signeddata_version(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the SignerInfo version
 */
int
pkcs7_note_signerinfo_version(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Parse authenticated attributes.
 */
int
pkcs7_sig_note_authenticated_attr(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the digest algorithm for the signature.
 */
int
pkcs7_sig_note_digest_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the issuer's name
 */
int
pkcs7_sig_note_issuer(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the public key algorithm for the signature.
 */
int
pkcs7_sig_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the issuing certificate serial number
 */
int
pkcs7_sig_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the set of auth attributes for digestion purposes [RFC2315 sec 9.3]
 */
int
pkcs7_sig_note_set_of_authattrs(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the signature data
 */
int
pkcs7_sig_note_signature(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

/*
 * Note the issuing cert's subjectKeyIdentifier
 */
int
pkcs7_sig_note_skid(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen);

//
// global
//

static const UCHAR pkcs7_machine[] = {
    // PKCS7ContentInfo
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // ContentType
    ASN1_OP_MATCH_ACT,
    _tag(UNIV, PRIM, OID),
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_ACT,
    _action(ACT_pkcs7_check_content_type),
    ASN1_OP_MATCH_JUMP_OR_SKIP, // content
    _tagn(CONT, CONS, 0),
    _jump_target(12),
    ASN1_OP_END_SEQ,
    ASN1_OP_COMPLETE,

    // SignedData
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // version
    _tag(UNIV, PRIM, INT),
    _action(ACT_pkcs7_note_signeddata_version),
    // DigestAlgorithmIdentifiers
    ASN1_OP_MATCH_JUMP_OR_SKIP, // daSet
    _tag(UNIV, CONS, SET),
    _jump_target(61),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // daSequence
    _tag(UNIV, CONS, SEQ),
    _jump_target(67),
    ASN1_OP_COND_FAIL,
    // ContentInfo
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    // ContentType
    ASN1_OP_MATCH_ACT,
    _tag(UNIV, PRIM, OID),
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_ACT,
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_MATCH_JUMP_OR_SKIP, // content
    _tagn(CONT, CONS, 0),
    _jump_target(73),
    ASN1_OP_END_SEQ,
    ASN1_OP_ACT,
    _action(ACT_pkcs7_note_content),
    // ExtendedCertificatesAndCertificates
    ASN1_OP_MATCH_JUMP_OR_SKIP, // certSet
    _tagn(CONT, CONS, 0),
    _jump_target(77), // --> ExtendedCertificatesAndCertificates
    // Certificates
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // certSequence
    _tagn(CONT, CONS, 2),
    _jump_target(85), // --> Certificates
    ASN1_OP_ACT,
    _action(ACT_pkcs7_note_certificate_list),
    // CertificateRevocationLists
    ASN1_OP_MATCH_JUMP_OR_SKIP, // crlSet
    _tagn(CONT, CONS, 1),
    _jump_target(90), // --> CertificateRevocationLists
    // CRLSequence
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // crlSequence
    _tagn(CONT, CONS, 3),
    _jump_target(96), // --> CRLSequence
    // SignerInfos
    ASN1_OP_MATCH_JUMP_OR_SKIP, // siSet
    _tag(UNIV, CONS, SET),
    _jump_target(102),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // siSequence
    _tag(UNIV, CONS, SEQ),
    _jump_target(108),
    ASN1_OP_COND_FAIL,
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // DigestAlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(114), // --> DigestAlgorithmIdentifier
    ASN1_OP_END_SET_OF,
    _jump_target(61),
    ASN1_OP_RETURN,

    // DigestAlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(114), // --> DigestAlgorithmIdentifier
    ASN1_OP_END_SEQ_OF,
    _jump_target(67),
    ASN1_OP_RETURN,

    // Data
    ASN1_OP_MATCH_ANY_ACT,
    _action(ACT_pkcs7_note_data),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // ExtendedCertificateOrCertificate
    // Certificate
    ASN1_OP_MATCH_ANY_ACT_OR_SKIP,
    _action(ACT_pkcs7_extract_cert),
    // ExtendedCertificate
    // Certificate
    ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP,
    _action(ACT_pkcs7_extract_cert),
    ASN1_OP_COND_FAIL,
    ASN1_OP_END_SET_OF,
    _jump_target(77),
    ASN1_OP_RETURN,

    // Certificate
    ASN1_OP_MATCH_ANY_ACT,
    _action(ACT_pkcs7_extract_cert),
    ASN1_OP_END_SEQ_OF,
    _jump_target(85),
    ASN1_OP_RETURN,

    // CertificateList
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(120), // --> CertificateList
    ASN1_OP_END_SET_OF,
    _jump_target(90),
    ASN1_OP_RETURN,

    // CertificateList
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(120), // --> CertificateList
    ASN1_OP_END_SEQ_OF,
    _jump_target(96),
    ASN1_OP_RETURN,

    // SignerInfo
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(125), // --> SignerInfo
    ASN1_OP_END_SET_OF,
    _jump_target(102),
    ASN1_OP_RETURN,

    // SignerInfo
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(125), // --> SignerInfo
    ASN1_OP_END_SEQ_OF,
    _jump_target(108),
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ACT, // algorithm
    _tag(UNIV, PRIM, OID),
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_MATCH_ANY_OR_SKIP, // parameters
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // Certificate
    ASN1_OP_MATCH_ANY_ACT,
    _action(ACT_pkcs7_extract_cert),
    ASN1_OP_END_SEQ_OF,
    _jump_target(120),
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ACT, // version
    _tag(UNIV, PRIM, INT),
    _action(ACT_pkcs7_note_signerinfo_version),
    // SignerIdentifier
    // IssuerAndSerialNumber
    ASN1_OP_MATCH_JUMP_OR_SKIP, // issuerAndSerialNumber
    _tag(UNIV, CONS, SEQ),
    _jump_target(169), // --> IssuerAndSerialNumber
    // SubjectKeyIdentifier
    ASN1_OP_COND_MATCH_ACT_OR_SKIP, // subjectKeyIdentifier
    _tagn(CONT, PRIM, 0),
    _action(ACT_pkcs7_sig_note_skid),
    ASN1_OP_COND_FAIL,
    // DigestAlgorithmIdentifier
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(114), // --> DigestAlgorithmIdentifier
    ASN1_OP_ACT,
    _action(ACT_pkcs7_sig_note_digest_algo),
    // SetOfAuthenticatedAttribute
    ASN1_OP_MATCH_JUMP_OR_SKIP, // aaSet
    _tagn(CONT, CONS, 0),
    _jump_target(192), // --> SetOfAuthenticatedAttribute
    ASN1_OP_MAYBE_ACT,
    _action(ACT_pkcs7_sig_note_set_of_authattrs),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // aaSequence
    _tagn(CONT, CONS, 2),
    _jump_target(198),
    // DigestEncryptionAlgorithmIdentifier
    ASN1_OP_MATCH,
    _tag(UNIV, CONS, SEQ),
    ASN1_OP_MATCH_ACT, // algorithm
    _tag(UNIV, PRIM, OID),
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_MATCH_ANY_OR_SKIP, // parameters
    ASN1_OP_END_SEQ,
    ASN1_OP_ACT,
    _action(ACT_pkcs7_sig_note_pkey_algo),
    // EncryptedDigest
    ASN1_OP_MATCH_ACT,
    _tag(UNIV, PRIM, OTS),
    _action(ACT_pkcs7_sig_note_signature),
    ASN1_OP_MATCH_JUMP_OR_SKIP, // uaSet
    _tagn(CONT, CONS, 1),
    _jump_target(207),
    ASN1_OP_COND_MATCH_JUMP_OR_SKIP, // uaSequence
    _tagn(CONT, CONS, 3),
    _jump_target(213),
    ASN1_OP_END_SEQ_ACT,
    _action(ACT_pkcs7_note_signed_info),
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
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_MATCH_ANY, // attributeValue
    ASN1_OP_END_SEQ,
    ASN1_OP_END_SET_OF,
    _jump_target(173),
    ASN1_OP_END_SEQ_OF,
    _jump_target(171),
    ASN1_OP_ACT,
    _action(ACT_pkcs7_sig_note_issuer),
    // CertificateSerialNumber
    ASN1_OP_MATCH,
    _tag(UNIV, PRIM, INT),
    ASN1_OP_ACT,
    _action(ACT_pkcs7_sig_note_serial),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // AuthenticatedAttribute
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(219), // --> AuthenticatedAttribute
    ASN1_OP_END_SET_OF,
    _jump_target(192),
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // aaSequence
    _tag(UNIV, CONS, SEQ),
    // AuthenticatedAttribute
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(219), // --> AuthenticatedAttribute
    ASN1_OP_END_SEQ_OF,
    _jump_target(200),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    // UnauthenticatedAttribute
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(230), // --> UnauthenticatedAttribute
    ASN1_OP_END_SET_OF,
    _jump_target(207),
    ASN1_OP_RETURN,

    // UnauthenticatedAttribute
    ASN1_OP_MATCH_JUMP,
    _tag(UNIV, CONS, SEQ),
    _jump_target(230), // --> UnauthenticatedAttribute
    ASN1_OP_END_SEQ_OF,
    _jump_target(213),
    ASN1_OP_RETURN,

    ASN1_OP_MATCH_ACT, // type
    _tag(UNIV, PRIM, OID),
    _action(ACT_pkcs7_note_OID),
    ASN1_OP_MATCH, // values
    _tag(UNIV, CONS, SET),
    ASN1_OP_MATCH_ANY_ACT,
    _action(ACT_pkcs7_sig_note_authenticated_attr),
    ASN1_OP_END_SET_OF,
    _jump_target(224),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,

    ASN1_OP_MATCH, // type
    _tag(UNIV, PRIM, OID),
    ASN1_OP_MATCH, // values
    _tag(UNIV, CONS, SET),
    ASN1_OP_MATCH_ANY,
    ASN1_OP_END_SET_OF,
    _jump_target(234),
    ASN1_OP_END_SEQ,
    ASN1_OP_RETURN,
};

static const asn1_action_t pkcs7_action_table[NR__pkcs7_actions] = {
    pkcs7_check_content_type,
    pkcs7_extract_cert,
    pkcs7_note_OID,
    pkcs7_note_certificate_list,
    pkcs7_note_content,
    pkcs7_note_data,
    pkcs7_note_signed_info,
    pkcs7_note_signeddata_version,
    pkcs7_note_signerinfo_version,
    pkcs7_sig_note_authenticated_attr,
    pkcs7_sig_note_digest_algo,
    pkcs7_sig_note_issuer,
    pkcs7_sig_note_pkey_algo,
    pkcs7_sig_note_serial,
    pkcs7_sig_note_set_of_authattrs,
    pkcs7_sig_note_signature,
    pkcs7_sig_note_skid,
};

struct asn1_decoder pkcs7_decoder = {
    pkcs7_machine,
    sizeof(pkcs7_machine),
    pkcs7_action_table,
};

/*
 * Free a signed information block.
 */
static void
pkcs7_free_signed_info(struct pkcs7_signed_info *sinfo)
{
    if (sinfo)
    {
        public_key_signature_free(sinfo->sig);
        kfree(sinfo);
    }
}

/**
 * pkcs7_free_message - Free a PKCS#7 message
 * @pkcs7: The PKCS#7 message to free
 */
void
pkcs7_free_message(struct pkcs7_message *pkcs7)
{
    struct x509_certificate *cert;
    struct pkcs7_signed_info *sinfo;

    if (pkcs7)
    {
        while (pkcs7->certs)
        {
            cert = pkcs7->certs;
            pkcs7->certs = cert->next;
            x509_free_certificate(cert);
        }
        while (pkcs7->crl)
        {
            cert = pkcs7->crl;
            pkcs7->crl = cert->next;
            x509_free_certificate(cert);
        }
        while (pkcs7->signed_infos)
        {
            sinfo = pkcs7->signed_infos;
            pkcs7->signed_infos = sinfo->next;
            pkcs7_free_signed_info(sinfo);
        }
        kfree(pkcs7);
    }
}
// EXPORT_SYMBOL_GPL(pkcs7_free_message);

/*
 * Check authenticatedAttributes are provided or not provided consistently.
 */
static int
pkcs7_check_authattrs(struct pkcs7_message *msg)
{
    struct pkcs7_signed_info *sinfo;
    /*bool*/ unsigned char want = /*false*/ FALSE;

    sinfo = msg->signed_infos;
    if (!sinfo)
        goto inconsistent;

    if (sinfo->authattrs)
    {
        want = /*true*/ TRUE;
        msg->have_authattrs = /*true*/ TRUE;
    }

    for (sinfo = sinfo->next; sinfo; sinfo = sinfo->next)
        if (!!sinfo->authattrs != want)
            goto inconsistent;
    return 0;

inconsistent:
    pr_warn("Inconsistently supplied authAttrs\n");
    return -EINVAL;
}

/**
 * pkcs7_parse_message - Parse a PKCS#7 message
 * @data: The raw binary ASN.1 encoded message to be parsed
 * @datalen: The size of the encoded message
 */
struct pkcs7_message *
pkcs7_parse_message(const void *data, size_t datalen)
{
    struct pkcs7_parse_context *ctx;
    struct pkcs7_message *msg = ERR_PTR(-ENOMEM);
    int ret;

    ctx = kzalloc(sizeof(struct pkcs7_parse_context), GFP_KERNEL);
    if (!ctx)
        goto out_no_ctx;
    ctx->msg = kzalloc(sizeof(struct pkcs7_message), GFP_KERNEL);
    if (!ctx->msg)
        goto out_no_msg;
    ctx->sinfo = kzalloc(sizeof(struct pkcs7_signed_info), GFP_KERNEL);
    if (!ctx->sinfo)
        goto out_no_sinfo;
    ctx->sinfo->sig = kzalloc(sizeof(struct public_key_signature), GFP_KERNEL);
    if (!ctx->sinfo->sig)
        goto out_no_sig;

    /*ctx->data = (unsigned long)data;*/
    ctx->data = PtrToUlong(data);
    ctx->ppcerts = &ctx->certs;
    ctx->ppsinfo = &ctx->msg->signed_infos;

    /* Attempt to decode the signature */
    ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
    if (ret < 0)
    {
        msg = ERR_PTR(ret);
        goto out;
    }

    ret = pkcs7_check_authattrs(ctx->msg);
    if (ret < 0)
        goto out;

    msg = ctx->msg;
    ctx->msg = NULL;

out:
    while (ctx->certs)
    {
        struct x509_certificate *cert = ctx->certs;
        ctx->certs = cert->next;
        x509_free_certificate(cert);
    }
out_no_sig:
    pkcs7_free_signed_info(ctx->sinfo);
out_no_sinfo:
    pkcs7_free_message(ctx->msg);
out_no_msg:
    kfree(ctx);
out_no_ctx:
    return msg;
}
// EXPORT_SYMBOL_GPL(pkcs7_parse_message);

/**
 * pkcs7_get_content_data - Get access to the PKCS#7 content
 * @pkcs7: The preparsed PKCS#7 message to access
 * @_data: Place to return a pointer to the data
 * @_data_len: Place to return the data length
 * @_headerlen: Size of ASN.1 header not included in _data
 *
 * Get access to the data content of the PKCS#7 message.  The size of the
 * header of the ASN.1 object that contains it is also provided and can be used
 * to adjust *_data and *_data_len to get the entire object.
 *
 * Returns -ENODATA if the data object was missing from the message.
 */
int
pkcs7_get_content_data(const struct pkcs7_message *pkcs7, const void **_data, size_t *_data_len, size_t *_headerlen)
{
    if (!pkcs7->data)
        return -ENODATA;

    *_data = pkcs7->data;
    *_data_len = pkcs7->data_len;
    if (_headerlen)
        *_headerlen = pkcs7->data_hdrlen;
    return 0;
}
// EXPORT_SYMBOL_GPL(pkcs7_get_content_data);

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int
pkcs7_note_OID(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    ctx->last_oid = look_up_OID(value, vlen);
    if (ctx->last_oid == OID__NR)
    {
        char buffer[50];
        sprint_oid(value, vlen, buffer, sizeof(buffer));
        /*printk("PKCS7: Unknown OID: [%lu] %s\n",
               (unsigned long)value - ctx->data, buffer);*/
    }
    return 0;
}

/*
 * Note the digest algorithm for the signature.
 */
int
pkcs7_sig_note_digest_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
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

    struct pkcs7_parse_context *ctx = context;

    switch (ctx->last_oid)
    {
    case OID_md4:
        ctx->sinfo->sig->hash_algo = tmp1;
        break;
    case OID_md5:
        ctx->sinfo->sig->hash_algo = tmp2;
        break;
    case OID_sha1:
        ctx->sinfo->sig->hash_algo = tmp3;
        break;
    case OID_sha256:
        ctx->sinfo->sig->hash_algo = tmp4;
        break;
    case OID_sha384:
        ctx->sinfo->sig->hash_algo = tmp5;
        break;
    case OID_sha512:
        ctx->sinfo->sig->hash_algo = tmp6;
        break;
    case OID_sha224:
        ctx->sinfo->sig->hash_algo = tmp7;
        break;
    default:
        printk("Unsupported digest algo: %u\n", ctx->last_oid);
        return -ENOPKG;
    }
    return 0;
}

/*
 * Note the public key algorithm for the signature.
 */
int
pkcs7_sig_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    // char tmp1[] = {
    //	's','a','r',0
    // };

    struct pkcs7_parse_context *ctx = context;

    switch (ctx->last_oid)
    {
    case OID_rsaEncryption:
        ctx->sinfo->sig->pkey_algo = "sar";
        break;
    default:
        printk("Unsupported pkey algo: %u\n", ctx->last_oid);
        return -ENOPKG;
    }
    return 0;
}

/*
 * We only support signed data [RFC2315 sec 9].
 */
int
pkcs7_check_content_type(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    if (ctx->last_oid != OID_signed_data)
    {
        pr_warn("Only support pkcs7_signedData type\n");
        return -EINVAL;
    }

    return 0;
}

/*
 * Note the SignedData version
 */
int
pkcs7_note_signeddata_version(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    unsigned version;

    if (vlen != 1)
        goto unsupported;

    ctx->msg->version = version = *(const /*u8*/ unsigned char *)value;
    switch (version)
    {
    case 1:
        /* PKCS#7 SignedData [RFC2315 sec 9.1]
         * CMS ver 1 SignedData [RFC5652 sec 5.1]
         */
        break;
    case 3:
        /* CMS ver 3 SignedData [RFC2315 sec 5.1] */
        break;
    default:
        goto unsupported;
    }

    return 0;

unsupported:
    pr_warn("Unsupported SignedData version\n");
    return -EINVAL;
}

/*
 * Note the SignerInfo version
 */
int
pkcs7_note_signerinfo_version(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    unsigned version;

    if (vlen != 1)
        goto unsupported;

    version = *(const /*u8*/ unsigned char *)value;
    switch (version)
    {
    case 1:
        /* PKCS#7 SignerInfo [RFC2315 sec 9.2]
         * CMS ver 1 SignerInfo [RFC5652 sec 5.3]
         */
        if (ctx->msg->version != 1)
            goto version_mismatch;
        ctx->expect_skid = /*false*/ FALSE;
        break;
    case 3:
        /* CMS ver 3 SignerInfo [RFC2315 sec 5.3] */
        if (ctx->msg->version == 1)
            goto version_mismatch;
        ctx->expect_skid = /*true*/ TRUE;
        break;
    default:
        goto unsupported;
    }

    return 0;

unsupported:
    pr_warn("Unsupported SignerInfo version\n");
    return -EINVAL;
version_mismatch:
    pr_warn("SignedData-SignerInfo version mismatch\n");
    return -EBADMSG;
}

/*
 * Extract a certificate and store it in the context.
 */
int
pkcs7_extract_cert(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    struct x509_certificate *x509;

    if (tag != ((ASN1_UNIV << 6) | ASN1_CONS_BIT | ASN1_SEQ))
    {
        pr_debug("Cert began with tag %02x at %p\n", tag, (ULONG_PTR)ctx - (ULONG_PTR)ctx->data);
        return -EBADMSG;
    }

    /* We have to correct for the header so that the X.509 parser can start
     * from the beginning.  Note that since X.509 stipulates DER, there
     * probably shouldn't be an EOC trailer - but it is in PKCS#7 (which
     * stipulates BER).
     */
    value = (void *)((unsigned char *)value - hdrlen);
    vlen += hdrlen;

    if (((unsigned char *)value)[1] == 0x80)
    {
        vlen += 2; /* Indefinite length - there should be an EOC */
        pr_debug("Indefinite length - there should be an EOC \n");
    }

    x509 = x509_cert_parse(value, vlen);
    if (IS_ERR(PtrToUlong(x509)))
        return PTR_ERR(PtrToUlong(x509));

    x509->index = ++ctx->x509_index;
    pr_debug("Got cert %u for %s,tag=%d\n", x509->index, x509->subject, tag);
    pr_debug("len=%d fingerprint %p\n", x509->id->len, x509->id->data);

    *ctx->ppcerts = x509;
    ctx->ppcerts = &x509->next;
    return 0;
}

/*
 * Save the certificate list
 */
int
pkcs7_note_certificate_list(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    pr_devel("Got cert list (0x%02x),subject=%s,ppcerts=%p\n", tag, ctx->certs->subject, (*(ctx->ppcerts)));

    *ctx->ppcerts = ctx->msg->certs;
    ctx->msg->certs = ctx->certs;
    ctx->certs = NULL;
    ctx->ppcerts = &ctx->certs;
    return 0;
}

/*
 * Note the content type.
 */
int
pkcs7_note_content(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    if (ctx->last_oid != OID_data && ctx->last_oid != OID_msIndirectData)
    {
        pr_warn("Unsupported data type %d\n", ctx->last_oid);
        return -EINVAL;
    }

    ctx->msg->data_type = ctx->last_oid;
    return 0;
}

/*
 * Extract the data from the message and store that and its content type OID in
 * the context.
 */
int
pkcs7_note_data(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    pr_debug("Got data\n");

    ctx->msg->data = value;
    ctx->msg->data_len = vlen;
    ctx->msg->data_hdrlen = hdrlen;
    return 0;
}

/*
 * Parse authenticated attributes.
 */
int
pkcs7_sig_note_authenticated_attr(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    struct pkcs7_signed_info *sinfo = ctx->sinfo;
    enum OID content_type;

    pr_devel(
        "AuthAttr: %02x %u [%p],last_oid=%d,sinfo->aa_set=%d,signing_time=%d\n",
        tag,
        vlen,
        value,
        ctx->last_oid,
        sinfo->aa_set,
        sinfo->signing_time);

    switch (ctx->last_oid)
    {
    case OID_contentType:
        if (__test_and_set_bit(sinfo_has_content_type, &sinfo->aa_set))
        {
            pr_debug("case OID_contentType:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

        content_type = look_up_OID(value, vlen);
        if (content_type != ctx->msg->data_type)
        {
            pr_warn(
                "Mismatch between global data type (%d) and sinfo %u (%d)\n",
                ctx->msg->data_type,
                sinfo->index,
                content_type);
            return -EBADMSG;
        }
        return 0;

    case OID_signingTime:
        if (__test_and_set_bit(sinfo_has_signing_time, &sinfo->aa_set))
        {
            pr_debug("case OID_signingTime:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

        /* Should we check that the signing time is consistent
         * with the signer's X.509 cert?
         */
        return x509_decode_time(ctx->msg->certs, FALSE, TRUE, &sinfo->signing_time, hdrlen, tag, value, vlen);

    case OID_messageDigest:
        if (__test_and_set_bit(sinfo_has_message_digest, &sinfo->aa_set))
        {
            pr_debug("case OID_messageDigest:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

        if (tag != ASN1_OTS)
            return -EBADMSG;
        sinfo->msgdigest = value;
        sinfo->msgdigest_len = vlen;
        pr_debug("case OID_messageDigest:sinfo->msgdigest=%p,msgdigest_len=%d\n", value, vlen);
        return 0;

    case OID_smimeCapabilites:
        if (__test_and_set_bit(sinfo_has_smime_caps, &sinfo->aa_set))
        {
            pr_debug("case OID_smimeCapabilites:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

        if (ctx->msg->data_type != OID_msIndirectData)
        {
            pr_warn("S/MIME Caps only allowed with Authenticode\n");
            return -EKEYREJECTED;
        }
        return 0;

        /* Microsoft SpOpusInfo seems to be contain cont[0] 16-bit BE
         * char URLs and cont[1] 8-bit char URLs.
         *
         * Microsoft StatementType seems to contain a list of OIDs that
         * are also used as extendedKeyUsage types in X.509 certs.
         */
    case OID_msSpOpusInfo:
        if (__test_and_set_bit(sinfo_has_ms_opus_info, &sinfo->aa_set))
        {
            pr_debug("case OID_smimeCapabilites:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

        goto authenticode_check;
    case OID_msStatementType:
        if (__test_and_set_bit(sinfo_has_ms_statement_type, &sinfo->aa_set))
        {
            pr_debug("case OID_smimeCapabilites:sinfo->aa_set=%d\n", sinfo->aa_set);
            goto repeated;
        }

    authenticode_check:
        if (ctx->msg->data_type != OID_msIndirectData)
        {
            pr_warn("Authenticode AuthAttrs only allowed with Authenticode\n");
            return -EKEYREJECTED;
        }
        /* I'm not sure how to validate these */
        return 0;
    default:
        return 0;
    }

repeated:
    /* We permit max one item per AuthenticatedAttribute and no repeats */
    pr_warn("Repeated/multivalue AuthAttrs not permitted\n");
    return -EKEYREJECTED;
}

/*
 * Note the set of auth attributes for digestion purposes [RFC2315 sec 9.3]
 */
int
pkcs7_sig_note_set_of_authattrs(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    struct pkcs7_signed_info *sinfo = ctx->sinfo;

    if (!test_bit(sinfo_has_content_type, &sinfo->aa_set) || !test_bit(sinfo_has_message_digest, &sinfo->aa_set))
    {
        pr_warn("Missing required AuthAttr\n");
        return -EBADMSG;
    }

    if (ctx->msg->data_type != OID_msIndirectData && test_bit(sinfo_has_ms_opus_info, &sinfo->aa_set))
    {
        pr_warn("Unexpected Authenticode AuthAttr\n");
        return -EBADMSG;
    }

    /* We need to switch the 'CONT 0' to a 'SET OF' when we digest */
    sinfo->authattrs = (void *)((unsigned char *)value - (hdrlen - 1));
    sinfo->authattrs_len = vlen + (hdrlen - 1);
    return 0;
}

/*
 * Note the issuing certificate serial number
 */
int
pkcs7_sig_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    ctx->raw_serial = value;
    ctx->raw_serial_size = vlen;
    return 0;
}

/*
 * Note the issuer's name
 */
int
pkcs7_sig_note_issuer(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    ctx->raw_issuer = value;
    ctx->raw_issuer_size = vlen;
    return 0;
}

/*
 * Note the issuing cert's subjectKeyIdentifier
 */
int
pkcs7_sig_note_skid(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    pr_devel("SKID: %02x %zu [%*ph]\n", tag, vlen, (unsigned)vlen, value);

    ctx->raw_skid = value;
    ctx->raw_skid_size = vlen;
    return 0;
}

/*
 * Note the signature data
 */
int
pkcs7_sig_note_signature(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;

    ctx->sinfo->sig->s = kmemdup(value, vlen, GFP_KERNEL);
    if (!ctx->sinfo->sig->s)
        return -ENOMEM;

    ctx->sinfo->sig->s_size = vlen;
    return 0;
}

/*
 * Note a signature information block
 */
int
pkcs7_note_signed_info(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
    struct pkcs7_parse_context *ctx = context;
    struct pkcs7_signed_info *sinfo = ctx->sinfo;
    struct asymmetric_key_id *kid;

    if (ctx->msg->data_type == OID_msIndirectData && !sinfo->authattrs)
    {
        pr_warn("Authenticode requires AuthAttrs\n");
        return -EBADMSG;
    }

    /* Generate cert issuer + serial number key ID */
    if (!ctx->expect_skid)
    {
        kid = asymmetric_key_generate_id(ctx->raw_serial, ctx->raw_serial_size, ctx->raw_issuer, ctx->raw_issuer_size);
    }
    else
    {
        kid = asymmetric_key_generate_id(ctx->raw_skid, ctx->raw_skid_size, "", 0);
    }
    if (IS_ERR(PtrToUlong(kid)))
        return PTR_ERR(PtrToUlong(kid));

    pr_devel("SINFO KID: %u [%p]\n", kid->len, kid->data);

    sinfo->sig->auth_ids[0] = kid;
    sinfo->index = ++ctx->sinfo_index;
    *ctx->ppsinfo = sinfo;
    ctx->ppsinfo = &sinfo->next;
    ctx->sinfo = kzalloc(sizeof(struct pkcs7_signed_info), GFP_KERNEL);
    if (!ctx->sinfo)
        return -ENOMEM;
    ctx->sinfo->sig = kzalloc(sizeof(struct public_key_signature), GFP_KERNEL);
    if (!ctx->sinfo->sig)
        return -ENOMEM;
    return 0;
}
