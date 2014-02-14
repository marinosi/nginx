/*-
 * Copyright (c) 2013 Ilias Marinos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_parse_internal.h>
#include <string.h>
#include <err.h>

#if !(NGX_NO_SANDBOX)
#include <sandbox.h>
/*#include <sandbox_rpc.h>*/
#endif

/* DPRINTF */
#define DEBUG
#ifdef DEBUG
#define DPRINTF(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n", 	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#if !(NGX_NO_SANDBOX)

#define GET_PTR_OFFSET(a, b, c)		\
	do { \
		if ((b) && (c))	\
			(a) = ((ngx_uint_t)((u_char *)(b) - (c)));	\
	} while (0)

#define SET_PTR(a, b, c)	\
	do {	\
		if(c)	\
			(a) = (b) + (c);	\
	} while (0)

struct sandbox_cb *pscb;

/* Sandbox-local data structs */
u_char *request_buffer;
ngx_http_request_t http_req;
ngx_buf_t http_buf;

static void http_parse_sandbox(void);
void
http_parse_sandbox_init(void)
{

	pscb = calloc(1, sizeof(struct sandbox_cb));
	if(!pscb) {
		DPRINTF("[XXX] pscb wasn't initialized!");
		exit(-1);
	}
	sandbox_create(pscb, &http_parse_sandbox);

}

void
ngx_http_parse_request_line_sandbox_wait(void)
{
	wait(&rv);
	DPRINTF("Sandbox's exit status is %d", WEXITSTATUS(rv));
}

ngx_int_t
ngx_http_parse_request_line_insandbox(ngx_http_request_t *r, ngx_buf_t *b)
{
	struct parse_req *req;
	struct parse_rep rep;
	struct iovec iov_req, iov_rep;
	size_t buflen, len;

	/* Allocate space for the buffer */
	buflen = b->end - b->pos + 1;
	req = calloc(1, sizeof(*req) + buflen - 1);
	if(!req)
		perror("malloc()");

	DPRINTF("==> IN ngx_http_parse_request_line_insandbox()");
	/* Update old position in buffer */
	b->old_pos = b->pos;

	/* Calculate all the offsets here */
	req->request_llen = buflen;
	req->state = r->state;
	req->last_ofs = b->last - b->old_pos;
	/*req->schema_end_ofs = r->schema_end_ofs; [> XXX IM: needed? <]*/
	memmove(&req->request_buf[0], b->pos, buflen); /* XXX IM: buflen +1? */
	/*ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "req->request_buf: %s", (char * ) req->request_buf);*/

	iov_req.iov_base = req;
	iov_req.iov_len = sizeof(*req) + buflen - 1; /* XXX IM: transfer BUFFER too */
	iov_rep.iov_base = &rep;
	iov_rep.iov_len = sizeof(rep);

	DPRINTF("parent sent len: %u", (unsigned) iov_req.iov_len);
	if (host_rpc(pscb, PROXIED_PARSE_REQ_LINE, &iov_req, 1,  &iov_rep, 1, &len) < 0)
		err(-1, "host_rpc");

	DPRINTF("parent received len: %u", (unsigned) len);
	if (len != sizeof(rep))
		err(-1, "host_rpc");

	/* Update pointers based on ptr offsets */
	DPRINTF("Parent received response!");
	r->state = rep.state;
	r->http_minor = rep.http_minor;
	r->http_major = rep.http_major;
	r->method = rep.method;
	r->complex_uri = rep.complex_uri;
	r->quoted_uri = rep.quoted_uri;
	r->plus_in_uri = rep.plus_in_uri;
	r->space_in_uri = rep.space_in_uri;

	SET_PTR(r->http_protocol.data, b->old_pos, rep.protocol_data_ofs);
	SET_PTR(r->uri_end, b->old_pos, rep.uri_end_ofs);
	SET_PTR(r->args_start, b->old_pos, rep.args_start_ofs);
	SET_PTR(r->uri_ext, b->old_pos, rep.uri_ext_ofs);
	SET_PTR(r->port_end, b->old_pos, rep.port_end_ofs);
	SET_PTR(r->uri_start, b->old_pos, rep.uri_start_ofs);
	SET_PTR(r->schema_start, b->old_pos, rep.schema_start_ofs);
	SET_PTR(r->request_end, b->old_pos, rep.request_end_ofs);
	SET_PTR(r->method_end, b->old_pos, rep.method_end_ofs);
	SET_PTR(b->pos, b->old_pos, rep.newpos_ofs);

	DPRINTF("http_protocol_data: %s", r->http_protocol.data);
	DPRINTF("uri_end: %s", r->uri_end);
	DPRINTF("args_start: %s", r->args_start);
	DPRINTF("uri_ext: %s", r->uri_ext);
	DPRINTF("port_end: %s", r->port_end);
	DPRINTF("uri_start: %s", r->uri_start);
	DPRINTF("schema_start: %s", r->schema_start);
	DPRINTF("request_end: %s", r->request_end);
	DPRINTF("method_end: %s", r->method_end);
	DPRINTF("b->pos: %s", b->pos);

	free(req);
	return (rep.retval);
}

/* Called in sandbox and wraps the actual parse http request line */
static void
sandbox_http_parse(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len)
{

	struct parse_req *req;
	struct parse_rep rep;
	struct iovec iov;

	if (len < sizeof(*req))
		errx(-1, "sandbox_http_parse: len %zu", len);

	/* Demangle data */
	req = (struct parse_req *) buffer;

	/* Update pointer to the request buffer */
	request_buffer = &req->request_buf[0];
	DPRINTF("Request buffer: %s", req->request_buf);

	/* Update all needed variables/pointers in order to parse the request */
	bzero(&http_req, sizeof(http_req));
	bzero(&http_buf, sizeof(http_buf));
	http_req.state = req->state;
	http_buf.pos = request_buffer;
	http_buf.old_pos = request_buffer;
	http_buf.last = request_buffer + req->last_ofs;
	http_req.schema_end = request_buffer + req->schema_end_ofs; /* XXX IM: check this */


	/* Parse the request */
	bzero(&rep, sizeof(rep));
	rep.retval = ngx_http_parse_request_line(&http_req, &http_buf);


	/* Prepare the reply */
	rep.state = http_req.state;
	rep.http_minor = http_req.http_minor;
	rep.http_major = http_req.http_major;
	rep.method = http_req.method;
	rep.complex_uri = http_req.complex_uri;
	rep.quoted_uri = http_req.quoted_uri;
	rep.plus_in_uri = http_req.plus_in_uri;
	rep.space_in_uri = http_req.space_in_uri;

	GET_PTR_OFFSET(rep.protocol_data_ofs, http_req.http_protocol.data, http_buf.old_pos);
	GET_PTR_OFFSET(rep.uri_end_ofs, http_req.uri_end, http_buf.old_pos);
	GET_PTR_OFFSET(rep.args_start_ofs, http_req.args_start, http_buf.old_pos);
	GET_PTR_OFFSET(rep.uri_ext_ofs, http_req.uri_ext, http_buf.old_pos);
	GET_PTR_OFFSET(rep.port_end_ofs, http_req.port_end, http_buf.old_pos);
	GET_PTR_OFFSET(rep.uri_start_ofs, http_req.uri_start, http_buf.old_pos);
	GET_PTR_OFFSET(rep.schema_start_ofs, http_req.schema_start, http_buf.old_pos);
	GET_PTR_OFFSET(rep.request_end_ofs, http_req.request_end, http_buf.old_pos);
	GET_PTR_OFFSET(rep.method_end_ofs, http_req.method_end, http_buf.old_pos);
	GET_PTR_OFFSET(rep.newpos_ofs, http_buf.pos, http_buf.old_pos);

	/*if (rep.retval == NGX_OK)*/
		/*DPRINTF("PARSE OK");*/
	/*else if (rep.retval == NGX_AGAIN)*/
		/*DPRINTF("PARSE NGX_AGAIN");*/

	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	DPRINTF("Sandbox sending %u", (unsigned) sizeof(rep));
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");
}

static void
http_parse_sandbox(void)
{
	uint32_t opno, seqno;
	u_char *buffer;
	size_t len;

	for ( ; ; ) {
		DPRINTF("===> In http_parse_sandbox()");

		/* Get the data required from parent */
		if (sandbox_recvrpc(pscb, &opno, &seqno, &buffer, &len) < 0) {
			if (errno == EPIPE) {
				DPRINTF("[XXX] EPIPE");
				exit(-1);
			}
			else {
				DPRINTF("[XXX] sandbox_recvrpc");
				err(-1, "sandbox_recvrpc");
			}
		}
		DPRINTF("len: %u", (unsigned) len);

		switch(opno) {
		case PROXIED_PARSE_REQ_LINE:
			DPRINTF("Calling sandbox_http_parse()");
			sandbox_http_parse(pscb, opno, seqno, (char *)buffer, len);
			break;
			/* For future expansion */
		default:
			errx(-1, "sandbox_main: unknown op %d", opno);
		}

		/* Free buffer */
		free(buffer);
	}

}

#endif /* NGX_NO_SANDBOX */

ngx_int_t
ngx_http_parse_request_line_wrapper(ngx_http_request_t *r, ngx_buf_t *b)
{
#if !(NGX_NO_SANDBOX)
	return (ngx_http_parse_request_line_insandbox(r, b));
#else
	return (ngx_http_parse_request_line(r, b));
#endif
}

