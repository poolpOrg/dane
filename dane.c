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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "dane.h"

extern char *__progname;

X509 *crt = NULL;
int check_cert(struct dane_rr *dane_rr, X509 *cert);
X509 *get_x509(const char *hostname, int port);

X509 *
get_x509(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	const SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	if ((host = gethostbyname(hostname)) == NULL)
		err(1, "gethostbyname");

	sd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long *)(host->h_addr);
	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		err(1, "connect");

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_client_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
		errx(1, "SSL_CTX_new");

	ssl = SSL_new(ctx);
	if (ssl == NULL)
		errx(1, "SSL_new");

	SSL_set_fd(ssl, sd);
	if (SSL_connect(ssl) != 1)
		errx(1, "SSL_connect");

	return SSL_get_peer_certificate(ssl);
}

int
main(int argc, char *argv[])
{
	struct dane_session *dane;
	const char *domain;
	const char *port;
	char record[255];

	if (argc != 3)
		errx(1, "usage: %s domain port", __progname);

	domain = argv[1];
	port = argv[2];

	crt = get_x509(domain, atoi(port));
	
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

	if (check_cert(&dane_rr, crt))
		printf("+ cert check success\n");
	else
		printf("+ cert check failure\n");

	return;

bogus:
	printf("+ invalid TLSA record\n");
}

int
check_cert(struct dane_rr *dane_rr, X509 *cert)
{
	EVP_PKEY	*pkey;
	EVP_MD_CTX	*md_ctx = NULL;
	unsigned char	*out = NULL;
	unsigned char	 md_value[EVP_MAX_MD_SIZE];
	const unsigned char	*mdp = NULL;
	int		 outlen;
	int		 md_len = 0;
	int		 i;
	int		 ret = 0;

	switch (dane_rr->selector) {
	case ENTIRE_CERTIFICATE:
		outlen = i2d_X509(cert, &out);
		break;
	case PUBLIC_KEY:
		pkey = X509_get_pubkey(cert);
		outlen = i2d_PUBKEY(pkey, &out);
		break;
	}

	switch (dane_rr->matching) {
	case MATCH_CAD:
		if ((size_t)outlen != dane_rr->dlen)
			break;

		mdp = out;
		md_len = outlen;
		break;

	case MATCH_SHA256:
		md_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(md_ctx, out, outlen);
		EVP_DigestFinal_ex(md_ctx, md_value, &md_len);
		EVP_MD_CTX_free(md_ctx);

		mdp = md_value;
		break;

	case MATCH_SHA512:
		md_ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
		EVP_DigestUpdate(md_ctx, out, outlen);
		EVP_DigestFinal_ex(md_ctx, md_value, &md_len);
		EVP_MD_CTX_free(md_ctx);

		mdp = md_value;
		break;
	}

	ret = 1;
	for (i = 0; i < md_len; ++i)
		if (dane_rr->data[i] != mdp[i])
			ret = 0;

	return ret;
}
