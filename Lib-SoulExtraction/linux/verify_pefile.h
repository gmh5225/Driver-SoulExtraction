/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PE Binary parser bits
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

//#include <crypto/pkcs7.h>
//#include <crypto/hash_info.h>

#pragma once

#include <fltKernel.h>

#include "pkcs7.h"

//#include "pe.h"

struct section_header_x
{
    char name[8];                  /* name or "/12\0" string tbl offset */
    unsigned long virtual_size;    /* size of loaded section in ram */
    unsigned long virtual_address; /* relative virtual address */
    unsigned long raw_data_size;   /* size of the section */
    unsigned long data_addr;       /* file pointer to first page of sec */
    unsigned long relocs;          /* file pointer to relocation entries */
    unsigned long line_numbers;    /* line numbers! */
    unsigned long num_relocs;      /* number of relocations */
    unsigned long num_lin_numbers; /* srsly. */
    unsigned long flags;
};

struct pefile_context
{
    unsigned header_size;
    unsigned image_checksum_offset;
    unsigned cert_dirent_offset;
    unsigned n_data_dirents;
    unsigned n_sections;
    unsigned certs_size;
    unsigned sig_offset;
    unsigned sig_len;
    const struct section_header_x *secs;

    /* PKCS#7 MS Individual Code Signing content */
    const void *digest;      /* Digest */
    unsigned digest_len;     /* Digest length */
    const char *digest_algo; /* Digest algorithm */
};

//#define kenter(FMT, ...)					\
//	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
//#define kleave(FMT, ...) \
//	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

/*
 * Parse a PE binary.
 */
int
pefile_parse_binary(const void *pebuf, unsigned int pelen, struct pefile_context *ctx);

/*
 * Check and strip the PE wrapper from around the signature and check that the
 * remnant looks something like PKCS#7.
 */
int
pefile_strip_sig_wrapper(const void *pebuf, struct pefile_context *ctx);

/*
 * mscode_parser.c
 */
extern int
mscode_parse(void *_ctx, const void *content_data, size_t data_len, size_t asn1hdrlen);
