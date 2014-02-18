#ifndef _NGX_HTTP_PARSE_INTERNAL_H_
#define _NGX_HTTP_PARSE_INTERNAL_H_

#define USE_CAPSICUM

#define NO_OP 0x0000
#define PROXIED_PARSE_REQ_LINE 0x0001

struct parse_req {
    ngx_uint_t state;
	ngx_uint_t pos_ofs;
	ngx_uint_t last_ofs;
	ngx_uint_t schema_end_ofs;
	size_t	request_llen;
	u_char	request_buf[0];
} __packed;

struct parse_rep {
	ngx_int_t retval;
	ngx_uint_t state;
	ngx_uint_t method;
	uint16_t http_minor;
	uint16_t http_major;

	/*
	 * All offsets are calculated on top of the b->pos before going to sandbox
	 */
	ngx_uint_t protocol_data_ofs;
	ngx_uint_t uri_end_ofs;
	ngx_uint_t args_start_ofs;
	ngx_uint_t uri_ext_ofs;
	ngx_uint_t port_end_ofs;
	ngx_uint_t uri_start_ofs;
	ngx_uint_t schema_start_ofs;
	ngx_uint_t request_end_ofs;
	ngx_uint_t method_end_ofs;
	ngx_uint_t newpos_ofs;
    unsigned                          complex_uri:1;
    unsigned                          quoted_uri:1;
    unsigned                          plus_in_uri:1;
    unsigned                          space_in_uri:1;
	unsigned                          reserved:4;
} __packed;

/* Sandbox return value */
int rv;

/* Function prototypes */
void http_parse_sandbox_init(void);
void http_parse_sandbox_wait(void);
ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);
//ngx_int_t ngx_http_parse_uri(ngx_http_request_t *r);
//ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r,
    //ngx_uint_t merge_slashes);
//ngx_int_t ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b,
    //ngx_http_status_t *status);
//ngx_int_t ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
    //ngx_str_t *args, ngx_uint_t *flags);
//ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b,
    //ngx_uint_t allow_underscores);
//ngx_int_t ngx_http_parse_multi_header_lines(ngx_array_t *headers,
    //ngx_str_t *name, ngx_str_t *value);
//ngx_int_t ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len,
    //ngx_str_t *value);
//void ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri,
    //ngx_str_t *args);
//ngx_int_t ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
    //ngx_http_chunked_t *ctx);

#endif /* _NGX_HTTP_PARSE_INTERNAL_H_ */
