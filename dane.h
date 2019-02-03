/*
 * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_DANE_H_
#define	_DANE_H_

#include "unpack_dns.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define	T_TLSA	52

struct dane_session {
	uint64_t	reqid;
};

enum usage {
	PKIX_TA,
	PKIX_EE,
	DANE_TA,
	DANE_EE,
};

enum selector {
	ENTIRE_CERTIFICATE,
	PUBLIC_KEY,
};

enum matching_type {
	MATCH_CAD,
	MATCH_SHA256,
	MATCH_SHA512,
};

struct dane_rr {
	enum usage		 usage;
	enum selector		 selector;
	enum matching_type	 matching;
	const unsigned char	*data;
	size_t			 dlen;
};

struct dane_session	*dane_session(uint64_t);
void			 dane_free(struct dane_session *);
void			 dane_lookup(struct dane_session *, const char *);

static void	process_rr(struct asr_result *, void *);
static void	dns_rr_cname(struct dane_session *, struct dns_rr *);
static void	dns_rr_tlsa(struct dane_session *, struct dns_rr *);

#endif
