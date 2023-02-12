/* SPDX-License-Identifier: GPL-2.0-or-later */
/* X.509 certificate parser internal definitions
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#pragma once

#include "public_key.h"

struct x509_certificate
{
    struct x509_certificate *next;
    struct x509_certificate *signer;  /* Certificate that signed this one */
    struct public_key *pub;           /* Public key details */
    struct public_key_signature *sig; /* Signature parameters */
    char *issuer;                     /* Name of certificate issuer */
    unsigned long issuer_tag;         // Fix to 4 bytes by gmh
    char *subject;                    /* Name of certificate subject */
    unsigned long subject_tag;        // Fix to 4 bytes by gmh

    struct asymmetric_key_id *id;   /* Issuer + Serial number */
    struct asymmetric_key_id *skid; /* Subject + subjectKeyId (optional) */
    /*time64_t*/ long long valid_from;
    unsigned long valid_from_year;
    unsigned long valid_from_mon;
    unsigned long valid_from_day;
    unsigned long valid_from_hour;
    unsigned long valid_from_min;

    /*time64_t*/ long long valid_to;
    unsigned long valid_to_year;
    unsigned long valid_to_mon;
    unsigned long valid_to_day;
    unsigned long valid_to_hour;
    unsigned long valid_to_min;

    /*time64_t*/ long long sign_time;
    unsigned long sign_time_year;
    unsigned long sign_time_mon;
    unsigned long sign_time_day;
    unsigned long sign_time_hour;
    unsigned long sign_time_min;

    const void *tbs;        /* Signed data */
    unsigned tbs_size;      /* Size of signed data */
    unsigned raw_sig_size;  /* Size of sigature */
    const void *raw_sig;    /* Signature data */
    const void *raw_serial; /* Raw serial number in ASN.1 */
    unsigned raw_serial_size;
    unsigned raw_issuer_size;
    const void *raw_issuer;  /* Raw issuer name in ASN.1 */
    const void *raw_subject; /* Raw subject name in ASN.1 */
    unsigned raw_subject_size;
    unsigned raw_akid_size; // Fix to 4 bytes by gmh
    unsigned raw_skid_size;
    const void *raw_skid; /* Raw subjectKeyId in ASN.1 */
    unsigned index;
    unsigned char /*BOOLEAN*/ seen; /* Infinite recursion prevention */
    unsigned char /*BOOLEAN*/ verified;
    unsigned char /*BOOLEAN*/ self_signed;     /* T if self-signed (check unsupported_sig too) */
    unsigned char /*BOOLEAN*/ unsupported_key; /* T if key uses unsupported crypto */
    unsigned char /*BOOLEAN*/ unsupported_sig; /* T if signature uses unsupported crypto */
    unsigned char /*BOOLEAN*/ blacklisted;
};

struct x509_parse_context
{
    struct x509_certificate *cert;                    /* Certificate being constructed */
    /*unsigned long*/ void *data; /* Start of data */ // Fix to void* by gmh
    const void *cert_start;                           /* Start of cert content */
    const void *key;                                  /* Key data */
    size_t key_size;                                  /* Size of key data */
    enum OID last_oid;                                /* Last OID encountered */
    enum OID algo_oid;                                /* Algorithm OID */
    unsigned char nr_mpi;                             /* Number of MPIs stored */
    /*u8*/ unsigned char o_size;                      /* Size of organizationName (O) */
    /*u8*/ unsigned char cn_size;                     /* Size of commonName (CN) */
    /*u8*/ unsigned char email_size;                  /* Size of emailAddress */
    /*u16*/ unsigned short o_offset;                  /* Offset of organizationName (O) */
    /*u16*/ unsigned short cn_offset;                 /* Offset of commonName (CN) */
    /*u16*/ unsigned short email_offset;              /* Offset of emailAddress */
    unsigned raw_akid_size;
    const void *raw_akid;        /* Raw authorityKeyId in ASN.1 */
    const void *akid_raw_issuer; /* Raw directoryName in authorityKeyId */
    unsigned akid_raw_issuer_size;
};

/*
 * x509_cert_parser.c
 */
extern void
x509_free_certificate(struct x509_certificate *cert);
extern struct x509_certificate *
x509_cert_parse(const void *data, size_t datalen);
extern int
x509_decode_time(
    struct x509_certificate *cert,
    unsigned char isfrom,
    unsigned char issign,
    /*time64_t*/ long long *_t,
    size_t hdrlen,
    unsigned char tag,
    const unsigned char *value,
    size_t vlen);

/*
 * x509_public_key.c
 */
extern int
x509_get_sig_params(struct x509_certificate *cert);
extern int
x509_check_for_self_signed(struct x509_certificate *cert);
