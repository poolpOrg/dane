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

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#include <asr.h>
#include <err.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dane.h"

int
main(int argc, char *argv[])
{
	const char *domain  = argv[1];
	const char *port  = argv[2];
	struct dane_session *dane;
	extern char	*__progname;
	char record[255];

	if (argc < 3)
		errx(1, "usage: %s domain port", __progname);

  	event_init();

	dane = dane_session(42);

	(void)snprintf(record, sizeof record, "_%s._tcp.%s", port, domain);
	printf("looking up TLSA for record \"%s\"\n", record);
	dane_lookup(dane, record);
	
  	event_dispatch();

	dane_free(dane);
	return 0;
}


struct dane_session *
dane_session(uint64_t reqid)
{
	struct dane_session	*dane;

	if ((dane = calloc(1, sizeof *dane)) == NULL)
		return NULL;

	dane->reqid = reqid;

	return dane;
}

void
dane_free(struct dane_session *dane)
{
	free(dane);
}

void
dane_lookup(struct dane_session *dane, const char *record)
{
	struct asr_query	*as;

	as = res_query_async(record, C_IN, T_ANY, NULL);
	if (as == NULL)
		err(1, "res_query_async");

	event_asr_run(as, process_rr, dane);
}

static void
process_rr(struct asr_result *ar, void *arg)
{
	struct dane_session *dane = arg;
	struct unpack pack;
	struct dns_header h;
	struct dns_query q;
	struct dns_rr rr;

	// best effort
	if (ar->ar_h_errno && ar->ar_h_errno != NO_DATA)
		return;

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	unpack_header(&pack, &h);
	unpack_query(&pack, &q);
	for (; h.ancount; h.ancount--) {
		unpack_rr(&pack, &rr);
		if (rr.rr_type == T_CNAME)
			dns_rr_cname(dane, &rr);
		else if (rr.rr_type == T_TLSA)
			dns_rr_tlsa(dane, &rr);
		else {
			printf("INVALID TLSA RECORD: %d\n", rr.rr_type);
		}

	}
}

static void
dns_rr_cname(struct dane_session *dane, struct dns_rr *rr)
{
	char	 buf[512];

	print_dname(rr->rr.cname.cname, buf, sizeof(buf));
	buf[strlen(buf) - 1] = '\0';
	if (buf[strlen(buf) - 1] == '.')
		buf[strlen(buf) - 1] = '\0';

	printf("+ record resolved to CNAME \"%s\"\n", buf);

	dane_lookup(dane, buf);
}

static void
dns_rr_tlsa(struct dane_session *dane, struct dns_rr *rr)
{
	struct dane_rr	 dane_rr;
	char		 buffer[512];
	const uint8_t  	*p;
	size_t		 i;
	const char	*usage;
	const char	*selector;
	const char	*matching;

	p = rr->rr.other.rdata;
	dane_rr.usage = *p++;
	dane_rr.selector = *p++;
	dane_rr.matching = *p++;
	dane_rr.data = p;
	dane_rr.dlen = rr->rr.other.rdlen - 3;

	switch (dane_rr.usage) {
	case PKIX_TA:
		usage = "PKIX-TA";
		break;
	case PKIX_EE:
		usage = "PKIX-EE";
		break;
	case DANE_TA:
		usage = "DANE-TA";
		break;
	case DANE_EE:
		usage = "DANE-EE";
		break;
	default:
		goto bogus;
	}

	switch (dane_rr.selector) {
	case ENTIRE_CERTIFICATE:
		selector = "entire";
		break;
	case PUBLIC_KEY:
		selector = "public-key";
		break;
	default:
		goto bogus;
	}

	switch (dane_rr.matching) {
	case MATCH_CAD:
		matching = "cad";
		break;
	case MATCH_SHA256:
		matching = "sha256";
		break;
	case MATCH_SHA512:
		matching = "sha512";
		break;
	default:
		goto bogus;
	}

	{
		unsigned char	x[] = "0123456789abcdef";
		size_t		j;
		for (i = j = 0; i < dane_rr.dlen*2; i++, j+=2) {
			buffer[j] = x[dane_rr.data[i] / 16];
			buffer[j+1] = x[dane_rr.data[i] % 16];
		}
		buffer[i] = 0;
	}

	printf("+ record resolved to TLSA: %s, %s, %s, %s\n", usage, selector, matching, buffer);
	return;
bogus:
	printf("+ invalid TLSA record\n");
}
