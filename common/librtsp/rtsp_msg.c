/*************************************************************************
	> File Name: rtsp_msg.c
	> Author: bxq
	> Mail: 544177215@qq.com
	> Created Time: Friday, December 11, 2015 AM05:02:48 CST
 ************************************************************************/

 #define _GNU_SOURCE // TODO: strcasestr() is GNU GCC extension function, need porting for another toolchain

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__unix__) || defined(__APPLE__)
#include <arpa/inet.h>
#endif

#include "comm.h"
#include "rtsp_msg.h"

// A safer allocation wrapper using calloc (zero-initialized memory).
void *rtsp_mem_alloc(size_t size)
{
	if (size > 0)
		return calloc(1, size);
	return NULL;
}

void rtsp_mem_free(void *ptr)
{
	if (ptr)
		free(ptr);
}

// A safer memory duplication function.
void *rtsp_mem_dup(const void *ptr, size_t size)
{
	if (!ptr || size == 0)
		return NULL;
	void *ptr1 = malloc(size); // No need for calloc, as we overwrite immediately.
	if (ptr1)
		memcpy(ptr1, ptr, size);
	return ptr1;
}

// A safer string duplication function.
char *rtsp_str_dup(const char *str)
{
	if (!str)
		return NULL;
	size_t len = strlen(str);
	char *str1 = (char *)malloc(len + 1);
	if (str1) {
		memcpy(str1, str, len);
		str1[len] = '\0';
	}
	return str1;
}


#define ARRAY_SIZE(_arr) (sizeof(_arr)/sizeof(_arr[0]))

typedef struct __rtsp_msg_int2str_tbl_s
{
	int intval;
	size_t strsiz;
	const char *strval;
} rtsp_msg_int2str_tbl_s;

static const char *rtsp_msg_int2str(const rtsp_msg_int2str_tbl_s *tbl, size_t num, int intval)
{
	for (size_t i = 0; i < num; i++) {
		if (intval == tbl[i].intval)
			return tbl[i].strval;
	}
	return tbl[num - 1].strval; // Return default/butt value
}

static int rtsp_msg_str2int(const rtsp_msg_int2str_tbl_s *tbl, size_t num, const char *str)
{
	for (size_t i = 0; i < num; i++) {
		if (tbl[i].strsiz > 0 && strncmp(tbl[i].strval, str, tbl[i].strsiz) == 0)
			return tbl[i].intval;
	}
	return tbl[num - 1].intval; // Return default/butt value
}

static const rtsp_msg_int2str_tbl_s rtsp_msg_method_tbl[] = {
	{ RTSP_MSG_METHOD_OPTIONS, 7, "OPTIONS", },
	{ RTSP_MSG_METHOD_DESCRIBE, 8, "DESCRIBE", },
	{ RTSP_MSG_METHOD_SETUP, 5, "SETUP", },
	{ RTSP_MSG_METHOD_PLAY, 4, "PLAY", },
	{ RTSP_MSG_METHOD_RECORD, 6, "RECORD", },
	{ RTSP_MSG_METHOD_PAUSE, 5, "PAUSE", },
	{ RTSP_MSG_METHOD_TEARDOWN, 8, "TEARDOWN", },
	{ RTSP_MSG_METHOD_ANNOUNCE, 8, "ANNOUNCE", },
	{ RTSP_MSG_METHOD_SET_PARAMETER, 13, "SET_PARAMETER", },
	{ RTSP_MSG_METHOD_GET_PARAMETER, 13, "GET_PARAMETER", },
	{ RTSP_MSG_METHOD_REDIRECT, 8, "REDIRECT", },
	{ RTSP_MSG_METHOD_BUTT, 0, "", },
};

static const rtsp_msg_int2str_tbl_s rtsp_msg_uri_scheme_tbl[] = {
	{RTSP_MSG_URI_SCHEME_RTSPU, 6, "rtspu:"},
	{RTSP_MSG_URI_SCHEME_RTSP, 5, "rtsp:"},
	{RTSP_MSG_URI_SCHEME_BUTT, 0, ""},
};

static const rtsp_msg_int2str_tbl_s rtsp_msg_version_tbl[] = {
	{RTSP_MSG_VERSION_1_0, 8, "RTSP/1.0"},
	{RTSP_MSG_VERSION_BUTT, 0, ""},
};

static const rtsp_msg_int2str_tbl_s rtsp_msg_status_code_tbl[] = {
	{100, 8, "Continue"}, {200, 2, "OK"}, {201, 7, "Created"},
	{250, 22, "Low on Storage Space"}, {300, 16, "Multiple Choices"},
	{301, 17, "Moved Permanently"}, {302, 17, "Moved Temporarily"},
	{303, 9, "See Other"}, {305, 9, "Use Proxy"}, {400, 11, "Bad Request"},
	{401, 12, "Unauthorized"}, {402, 16, "Payment Required"},
	{403, 9, "Forbidden"}, {404, 9, "Not Found"},
	{405, 18, "Method Not Allowed"}, {406, 14, "Not Acceptable"},
	{407, 27, "Proxy Authentication Required"}, {408, 15, "Request Timeout"},
	{410, 4, "Gone"}, {411, 15, "Length Required"},
	{412, 19, "Precondition Failed"}, {413, 24, "Request Entity Too Large"},
	{414, 20, "Request-URI Too Long"}, {415, 22, "Unsupported Media Type"},
	{451, 17, "Invalid parameter"}, {452, 29, "Illegal Conference Identifier"},
	{453, 21, "Not Enough Bandwidth"}, {454, 17, "Session Not Found"},
	{455, 29, "Method Not Valid In This State"}, {456, 24, "Header Field Not Valid"},
	{457, 13, "Invalid Range"}, {458, 24, "Parameter Is Read-Only"},
	{459, 31, "Aggregate Operation Not Allowed"},
	{460, 31, "Only Aggregate Operation Allowed"},
	{461, 21, "Unsupported Transport"}, {462, 25, "Destination Unreachable"},
	{500, 21, "Internal Server Error"}, {501, 15, "Not Implemented"},
	{502, 11, "Bad Gateway"}, {503, 19, "Service Unavailable"},
	{504, 15, "Gateway Timeout"}, {505, 26, "RTSP Version Not Supported"},
	{551, 20, "Option not support"},
};

static const rtsp_msg_int2str_tbl_s rtsp_msg_transport_type_tbl[] = {
	{RTSP_MSG_TRANSPORT_TYPE_RTP_AVP_TCP, 11, "RTP/AVP/TCP"},
	{RTSP_MSG_TRANSPORT_TYPE_RTP_AVP, 7, "RTP/AVP"},
	{RTSP_MSG_TRANSPORT_TYPE_BUTT, 0, ""},
};

static const rtsp_msg_int2str_tbl_s rtsp_msg_content_type_tbl[] = {
	{RTSP_MSG_CONTENT_TYPE_SDP, 15, "application/sdp"},
	{RTSP_MSG_CONTENT_TYPE_RTSL, 16, "application/rtsl"},
	{RTSP_MSG_CONTENT_TYPE_MHEG, 16, "application/mheg"},
	{RTSP_MSG_CONTENT_TYPE_BUTT, 0, ""},
};

// Safely parse URI from a line. Returns characters consumed or -1 on failure.
static int rtsp_msg_parse_uri(const char *line, rtsp_msg_uri_s *uri)
{
	const char *p = line;
	const char *q;

	uri->scheme = (rtsp_msg_uri_scheme_e)rtsp_msg_str2int(rtsp_msg_uri_scheme_tbl,
			ARRAY_SIZE(rtsp_msg_uri_scheme_tbl), line);
	if (uri->scheme == RTSP_MSG_URI_SCHEME_BUTT) {
		err("parse scheme failed. line: %s\n", line);
		return -1;
	}
	uri->port = 0; // default
	uri->ipaddr[0] = '\0';
	uri->abspath[0] = '\0';

	// Move past "rtsp://" or "rtspu://"
	p = strstr(line, "://");
	if (!p) {
		err("invalid URI format. line: %s\n", line);
		return -1;
	}
	p += 3;

	q = p;
	// Find end of authority part (host:port)
	while (isgraph(*q) && *q != '/') q++;

	const char *port_delim = strchr(p, ':');
	const char *path_delim = strchr(p, '/');

	ptrdiff_t host_len;
	if (port_delim && (path_delim == NULL || port_delim < path_delim)) {
		// Host and port present
		host_len = port_delim - p;
		char *endptr;
		long port_val = strtol(port_delim + 1, &endptr, 10);
		if (port_val <= 0 || port_val > 65535 || (*endptr != '/' && *endptr != '\0' && !isspace(*endptr))) {
			err("parse uri port failed. line: %s\n", line);
			return -1;
		}
		uri->port = (uint16_t)port_val;
	} else {
		// Host only
		host_len = (path_delim) ? (path_delim - p) : (q - p);
	}

	if (host_len >= sizeof(uri->ipaddr)) {
		err("ip address in URI is too long. line: %s\n", line);
		return -1;
	}
	memcpy(uri->ipaddr, p, host_len);
	uri->ipaddr[host_len] = '\0';

	// Parse abspath
	const char *abs_path_start = strchr(p, '/');
	if (abs_path_start) {
		const char *abs_path_end = abs_path_start;
		while (isgraph(*abs_path_end)) abs_path_end++;
		ptrdiff_t path_len = abs_path_end - abs_path_start;
		if (path_len >= sizeof(uri->abspath)) {
			err("absolute path in URI is too long. line: %s\n", line);
			return -1;
		}
		memcpy(uri->abspath, abs_path_start, path_len);
		uri->abspath[path_len] = '\0';
		q = abs_path_end;
	}

	return (q - line);
}


static int rtsp_msg_build_uri(const rtsp_msg_uri_s *uri, char *line, size_t size)
{
	if (uri->port > 0) {
		return snprintf(line, size, "%s//%s:%u%s",
				rtsp_msg_int2str(rtsp_msg_uri_scheme_tbl, ARRAY_SIZE(rtsp_msg_uri_scheme_tbl), uri->scheme),
				uri->ipaddr, uri->port, uri->abspath);
	}
	return snprintf(line, size, "%s//%s%s",
			rtsp_msg_int2str(rtsp_msg_uri_scheme_tbl, ARRAY_SIZE(rtsp_msg_uri_scheme_tbl), uri->scheme),
			uri->ipaddr, uri->abspath);
}

//return 0. if success
static int rtsp_msg_parse_startline(rtsp_msg_s *msg, const char *line)
{
	const char *p = line;
	int ret = rtsp_msg_str2int(rtsp_msg_method_tbl, ARRAY_SIZE(rtsp_msg_method_tbl), p);

	if (ret != RTSP_MSG_METHOD_BUTT) {
		msg->type = RTSP_MSG_TYPE_REQUEST;
		msg->hdrs.startline.reqline.method = (rtsp_msg_method_e)ret;

		while (isgraph(*p)) p++;
		while (isspace(*p)) p++;

		ret = rtsp_msg_parse_uri(p, &msg->hdrs.startline.reqline.uri);
		if (ret <= 0) return -1;
		p += ret;

		while (isspace(*p)) p++;

		ret = rtsp_msg_str2int(rtsp_msg_version_tbl, ARRAY_SIZE(rtsp_msg_version_tbl), p);
		if (ret == RTSP_MSG_VERSION_BUTT) {
			err("parse version failed. line: %s\n", line);
			return -1;
		}
		msg->hdrs.startline.reqline.version = (rtsp_msg_version_e)ret;
		return 0;
	}

	ret = rtsp_msg_str2int(rtsp_msg_version_tbl, ARRAY_SIZE(rtsp_msg_version_tbl), p);
	if (ret != RTSP_MSG_VERSION_BUTT) {
		msg->type = RTSP_MSG_TYPE_RESPONSE;
		msg->hdrs.startline.resline.version = (rtsp_msg_version_e)ret;

		while (isgraph(*p)) p++;
		while (isspace(*p)) p++;

		char *endptr;
		long status_code = strtol(p, &endptr, 10);
		if (p == endptr || status_code < 100 || status_code > 599) {
			err("parse status-code failed. line: %s\n", line);
			return -1;
		}
		msg->hdrs.startline.resline.status_code = (int)status_code;
		return 0;
	}

	// Interleaved is handled in rtsp_msg_parse_from_array
	err("parse startline failed, not a request or response: %s\n", line);
	return -1;
}

static int rtsp_msg_build_startline(const rtsp_msg_s *msg, char *line, size_t size)
{
	if (msg->type == RTSP_MSG_TYPE_REQUEST) {
		char uri_buf[256];
		rtsp_msg_build_uri(&msg->hdrs.startline.reqline.uri, uri_buf, sizeof(uri_buf));
		return snprintf(line, size, "%s %s %s\r\n",
				rtsp_msg_int2str(rtsp_msg_method_tbl, ARRAY_SIZE(rtsp_msg_method_tbl), msg->hdrs.startline.reqline.method),
				uri_buf,
				rtsp_msg_int2str(rtsp_msg_version_tbl, ARRAY_SIZE(rtsp_msg_version_tbl), msg->hdrs.startline.reqline.version));
	}

	if (msg->type == RTSP_MSG_TYPE_RESPONSE) {
		return snprintf(line, size, "%s %u %s\r\n",
				rtsp_msg_int2str(rtsp_msg_version_tbl, ARRAY_SIZE(rtsp_msg_version_tbl), msg->hdrs.startline.resline.version),
				msg->hdrs.startline.resline.status_code,
				rtsp_msg_int2str(rtsp_msg_status_code_tbl, ARRAY_SIZE(rtsp_msg_status_code_tbl), msg->hdrs.startline.resline.status_code));
	}

	return 0;
}

// Helper to safely parse unsigned int from a substring like "key=value"
static bool safe_parse_uint(const char *line, const char *key, unsigned int *out_val)
{
	const char *p = strstr(line, key);
	if (!p) return false;
	p += strlen(key);
	char *endptr;
	*out_val = (unsigned int)strtoul(p, &endptr, 10);
	return (p != endptr);
}

// Helper to safely parse hex from a substring like "key=value"
static bool safe_parse_hex(const char *line, const char *key, unsigned int *out_val)
{
	const char *p = strstr(line, key);
	if (!p) return false;
	p += strlen(key);
	char *endptr;
	*out_val = (unsigned int)strtoul(p, &endptr, 16);
	return (p != endptr);
}


//Transport
static int rtsp_msg_parse_transport(rtsp_msg_s *msg, const char *line)
{
	rtsp_msg_hdr_s *hdrs = &msg->hdrs;
	unsigned int tmp;

	rtsp_mem_free(hdrs->transport);
	hdrs->transport = (rtsp_msg_transport_s *)rtsp_mem_alloc(sizeof(rtsp_msg_transport_s));
	if (!hdrs->transport) {
		err("rtsp_mem_alloc for %s failed\n", "rtsp_msg_transport_s");
		return -1;
	}

	const char *p = strstr(line, "RTP/AVP");
	if (!p) {
		err("parse transport failed. line: %s\n", line);
		goto fail;
	}
	hdrs->transport->type = (rtsp_msg_transport_type_e)rtsp_msg_str2int(
			rtsp_msg_transport_type_tbl, ARRAY_SIZE(rtsp_msg_transport_type_tbl), p);

	if (safe_parse_hex(line, "ssrc=", &tmp)) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_SSRC;
		hdrs->transport->ssrc = tmp;
	}

	if (strstr(line, "unicast")) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_UNICAST;
	}
	if (strstr(line, "multicast")) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_MULTICAST;
	}

	if (safe_parse_uint(line, "client_port=", &tmp)) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_CLIENT_PORT;
		hdrs->transport->client_port = tmp;
	}

	if (safe_parse_uint(line, "server_port=", &tmp)) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_SERVER_PORT;
		hdrs->transport->server_port = tmp;
	}

	if (safe_parse_uint(line, "interleaved=", &tmp)) {
		hdrs->transport->flags |= RTSP_MSG_TRANSPORT_FLAG_INTERLEAVED;
		hdrs->transport->interleaved = tmp;
	}
	return 0;

fail:
	rtsp_mem_free(hdrs->transport);
	hdrs->transport = NULL;
	return -1;
}

static int rtsp_msg_build_transport(const rtsp_msg_s *msg, char *line, size_t size)
{
	const rtsp_msg_hdr_s *hdrs = &msg->hdrs;
	if (!hdrs->transport) return 0;

	char *p = line;
	char *const end = line + size;
	int written;

	written = snprintf(p, end - p, "Transport: %s", rtsp_msg_int2str(rtsp_msg_transport_type_tbl,
				ARRAY_SIZE(rtsp_msg_transport_type_tbl), hdrs->transport->type));
	p += written;
	if (p >= end -1) return (line + size - p);


	if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_MULTICAST) {
		written = snprintf(p, end - p, ";multicast");
		p += written;
		if (p >= end -1) return (line + size - p);
	} else if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_UNICAST) {
		written = snprintf(p, end - p, ";unicast");
		p += written;
		if (p >= end -1) return (line + size - p);
	}

	if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_CLIENT_PORT) {
		written = snprintf(p, end - p, ";client_port=%u-%u",
				hdrs->transport->client_port,
				hdrs->transport->client_port + 1);
		p += written;
		if (p >= end -1) return (line + size - p);
	}

	if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_SERVER_PORT) {
		written = snprintf(p, end - p, ";server_port=%u-%u",
				hdrs->transport->server_port,
				hdrs->transport->server_port + 1);
		p += written;
		if (p >= end -1) return (line + size - p);
	}

	if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_INTERLEAVED) {
		written = snprintf(p, end - p, ";interleaved=%u-%u",
				hdrs->transport->interleaved,
				hdrs->transport->interleaved + 1);
		p += written;
		if (p >= end -1) return (line + size - p);
	}

	if (hdrs->transport->flags & RTSP_MSG_TRANSPORT_FLAG_SSRC) {
		written = snprintf(p, end - p, ";ssrc=%08X", hdrs->transport->ssrc);
		p += written;
		if (p >= end -1) return (line + size - p);
	}

	snprintf(p, end - p, "\r\n");
	return strlen(line);
}

//Range
static int rtsp_msg_parse_range(rtsp_msg_s *msg, const char *line)
{
	return 0;//TODO
}

static int rtsp_msg_build_range(const rtsp_msg_s *msg, char *line, size_t size)
{
	return 0;//TODO
}

//Authorization
static int rtsp_msg_parse_auth(rtsp_msg_s *msg, const char *line)
{
	rtsp_msg_hdr_s *hdrs = &msg->hdrs;
	const char *p = strchr(line, ':');
	if (!p) goto fail;
	p++;
	while (*p == ' ') p++;

	rtsp_mem_free(hdrs->auth);
	hdrs->auth = (rtsp_msg_auth_s *)rtsp_mem_alloc(sizeof(rtsp_msg_auth_s));
	if (!hdrs->auth) {
		err("rtsp_mem_alloc for %s failed\n", "rtsp_msg_auth_s");
		return -1;
	}

	if (strncmp(p, "Basic ", 6) == 0) {
		hdrs->auth->type = RTSP_MSG_AUTH_TYPE_BASIC;
		p += 6;
		// Safely copy base64 part
		snprintf(hdrs->auth->basic_b64, sizeof(hdrs->auth->basic_b64), "%s", p);
	} else if (strncmp(p, "Digest ", 7) == 0) {
		hdrs->auth->type = RTSP_MSG_AUTH_TYPE_DIGEST;
		//TODO: Parse digest attributes
	} else {
		goto fail;
	}
	return 0;

fail:
	rtsp_mem_free(hdrs->auth);
	hdrs->auth = NULL;
	err("parse %s failed. line: %s\n", "rtsp_msg_auth_s", line);
	return -1;
}

static int rtsp_msg_build_auth(const rtsp_msg_s *msg, char *line, size_t size)
{
	return 0;//TODO
}

//WWW-Authorization
static int rtsp_msg_parse_www_auth(rtsp_msg_s *msg, const char *line)
{
	return 0;//TODO
}

static int rtsp_msg_build_www_auth(const rtsp_msg_s *msg, char *line, size_t size)
{
	if (msg->hdrs.www_auth) {
		if (msg->hdrs.www_auth->type == RTSP_MSG_AUTH_TYPE_BASIC) {
			return snprintf(line, size, "WWW-Authenticate: Basic realm=\"%s\"\r\n",
					msg->hdrs.www_auth->realm);
		}
		//TODO: Digest
	}
	return 0;
}

//RTP-Info
static int rtsp_msg_parse_rtp_info(rtsp_msg_s *msg, const char *line)
{
	return 0;//TODO
}

static int rtsp_msg_build_rtp_info(const rtsp_msg_s *msg, char *line, size_t size)
{
	return 0;//TODO
}

// Generic parser for headers with a single unsigned integer value (e.g., CSeq, Content-Length)
#define DEFINE_PARSE_BUILD_LIKE_CSEQ(_name, _type, _param, _fmt, _base) \
static int rtsp_msg_parse_##_name(rtsp_msg_s *msg, const char *line) \
{ \
	rtsp_msg_hdr_s *hdrs = &msg->hdrs; \
	const char *p = strchr(line, ':'); \
	if (!p) goto fail; \
	p++; \
	char *endptr; \
	uint32_t val = 0; \
	if (_base == 16) { \
	  val = strtoul(p, &endptr, _base); \
	} else { \
	  long t = strtol(p, &endptr, _base); \
	  if (t < 0 ) goto fail; \
	  val = (uint32_t)t; \
	} \
	if (p == endptr ) goto fail; \
	rtsp_mem_free(hdrs->_name); \
	hdrs->_name = (_type*)rtsp_mem_alloc(sizeof(_type)); \
	if (!hdrs->_name) { \
		err("rtsp_mem_alloc for %s failed\n", #_type); \
		return -1; \
	} \
	hdrs->_name->_param = val; \
	return 0; \
fail: \
	err("parse %s failed. line: %s\n", #_name, line); \
	return -1; \
} \
static int rtsp_msg_build_##_name(const rtsp_msg_s *msg, char *line, size_t size) \
{ \
	if (msg->hdrs._name) { \
		return snprintf(line, size, _fmt "\r\n", msg->hdrs._name->_param); \
	} \
	return 0; \
}

#if 0 // for kunyi debugging
static int rtsp_msg_parse_session(rtsp_msg_s *msg, const char *line)
{
	rtsp_msg_hdr_s *hdrs = &msg->hdrs;
	const char *p = strchr(line, ':');;

	if (!p) goto fail;
	p++;
	char *endptr;
	uint32_t val = strtoul(p, &endptr, 16);
	if (p == endptr) goto fail;

	rtsp_mem_free(hdrs->session);
	hdrs->session = (rtsp_msg_session_s*)rtsp_mem_alloc(sizeof(rtsp_msg_session_s));
	if (!hdrs->session) {
		err("rtsp_mem_alloc for %s failed\n", "rtsp_msg_session_s");
		return -1;
	}
	hdrs->session->session = val;
	return 0;
fail:
	err("parse %s failed. line: %s\n", "rtsp_msg_session_s", line);
	return -1;
}

static int rtsp_msg_build_session(const rtsp_msg_s *msg, char *line, size_t size)
{
	if (msg->hdrs.session) {
		return snprintf(line, size, "Session: %08X\r\n", msg->hdrs.session->session); \
	}
	return 0;
}
#endif

DEFINE_PARSE_BUILD_LIKE_CSEQ(cseq, rtsp_msg_cseq_s, cseq, "CSeq: %u", 10)
DEFINE_PARSE_BUILD_LIKE_CSEQ(session, rtsp_msg_session_s, session, "Session: %08X", 16)
DEFINE_PARSE_BUILD_LIKE_CSEQ(content_length, rtsp_msg_content_length_s, length, "Content-Length: %u", 10)
DEFINE_PARSE_BUILD_LIKE_CSEQ(x_accept_dynamic_rate, rtsp_msg_x_accept_dynamic_rate, x_accept_dynamic_rate, "x-accept-dynamic-Rate: %u", 10)
DEFINE_PARSE_BUILD_LIKE_CSEQ(x_dynamic_rate, rtsp_msg_x_dynamic_rate, x_dynamic_rate, "x-dynamic-rate: %u", 10)

// Generic parser for headers with a string value (e.g., Server, User-Agent)
#define DEFINE_PARSE_BUILD_LIKE_SERVER(_name, _type, _param, _fmt) \
static int rtsp_msg_parse_##_name(rtsp_msg_s *msg, const char *line) \
{ \
	rtsp_msg_hdr_s *hdrs = &msg->hdrs; \
	const char *p = strchr(line, ':'); \
	if (!p) goto fail; \
	p++; \
	while (*p == ' ') p++; \
	rtsp_mem_free(hdrs->_name); \
	hdrs->_name = (_type*)rtsp_mem_alloc(sizeof(_type)); \
	if (!hdrs->_name) { \
		err("rtsp_mem_alloc for %s failed\n", #_type); \
		return -1; \
	} \
	/* Safely copy the string value, removing trailing whitespace */ \
	const char *end = p + strlen(p); \
	while (end > p && isspace(*(end - 1))) end--; \
	size_t len = end - p; \
	if (len >= sizeof(hdrs->_name->_param)) { \
		len = sizeof(hdrs->_name->_param) - 1; \
	} \
	memcpy(hdrs->_name->_param, p, len); \
	hdrs->_name->_param[len] = '\0'; \
	return 0; \
fail: \
	err("parse %s failed. line: %s\n", #_name, line); \
	return -1; \
} \
static int rtsp_msg_build_##_name(const rtsp_msg_s *msg, char *line, size_t size) \
{ \
	if (msg->hdrs._name) { \
		return snprintf(line, size, _fmt "\r\n", msg->hdrs._name->_param); \
	} \
	return 0; \
}

DEFINE_PARSE_BUILD_LIKE_SERVER(server, rtsp_msg_server_s, server, "Server: %s")
DEFINE_PARSE_BUILD_LIKE_SERVER(user_agent, rtsp_msg_user_agent_s, user_agent, "User-Agent: %s")
DEFINE_PARSE_BUILD_LIKE_SERVER(date, rtsp_msg_date_s, http_date, "Date: %s")

// Generic parser for headers with an enum value (e.g., Content-Type)
#define DEFINE_PARSE_BUILD_LIKE_CONTENT_TYPE(_name, _type, _param, _fmt, _tbl) \
static int rtsp_msg_parse_##_name(rtsp_msg_s *msg, const char *line) \
{ \
	rtsp_msg_hdr_s *hdrs = &msg->hdrs; \
	const char *p = strchr(line, ':'); \
	if (!p) goto fail; \
	p++; \
	while (*p == ' ') p++; \
	for (size_t i = 0; i < ARRAY_SIZE(_tbl); i++) { \
		if (_tbl[i].strsiz > 0 && strstr(p, _tbl[i].strval)) { \
			rtsp_mem_free(hdrs->_name); \
			hdrs->_name = (_type*)rtsp_mem_alloc(sizeof(_type)); \
			if (!hdrs->_name) { \
				err("rtsp_mem_alloc for %s failed\n", #_type); \
				return -1; \
			} \
			*((int*)&hdrs->_name->_param) = _tbl[i].intval; \
			return 0; \
		} \
	} \
fail: \
	err("parse %s failed. line: %s\n", #_name, line); \
	return -1; \
} \
static int rtsp_msg_build_##_name(const rtsp_msg_s *msg, char *line, size_t size) \
{ \
	if (msg->hdrs._name) { \
		const char *strval = rtsp_msg_int2str(_tbl, ARRAY_SIZE(_tbl), msg->hdrs._name->_param); \
		if (strval && strval[0] != '\0') { \
			return snprintf(line, size, _fmt "\r\n", strval); \
		} \
	} \
	return 0; \
}

DEFINE_PARSE_BUILD_LIKE_CONTENT_TYPE(content_type, rtsp_msg_content_type_s, type, "Content-Type: %s", rtsp_msg_content_type_tbl)

// Generic parser for headers with a bitmask value (e.g., Public, Accept)
#define DEFINE_PARSE_BUILD_LIKE_PUBLIC(_name, _type, _param, _fmt, _tbl) \
static int rtsp_msg_parse_##_name(rtsp_msg_s *msg, const char *line) \
{ \
	rtsp_msg_hdr_s *hdrs = &msg->hdrs; \
	const char *p = strchr(line, ':'); \
	if (!p) goto fail; \
	p++; \
	rtsp_mem_free(hdrs->_name); \
	hdrs->_name = (_type*)rtsp_mem_alloc(sizeof(_type)); \
	if (!hdrs->_name) { \
		err("rtsp_mem_alloc for %s failed\n", #_type); \
		return -1; \
	} \
	hdrs->_name->_param = 0; \
	for (size_t i = 0; i < ARRAY_SIZE(_tbl); i++) { \
		if (_tbl[i].strsiz > 0 && strstr(p, _tbl[i].strval)) \
			hdrs->_name->_param |= (1 << _tbl[i].intval); \
	} \
	return 0; \
fail: \
	err("parse %s failed. line: %s\n", #_name, line); \
	return -1; \
} \
static int rtsp_msg_build_##_name(const rtsp_msg_s *msg, char *line, size_t size) \
{ \
	if (msg->hdrs._name) { \
		char *p = line; \
		char * const end = line + size; \
		int written = snprintf(p, end - p, _fmt, ""); \
		p += written; \
		bool first = true; \
		for (size_t i = 0; i < ARRAY_SIZE(_tbl); i++) { \
			if (msg->hdrs._name->_param & (1 << _tbl[i].intval)) { \
				written = snprintf(p, end - p, "%s%s", first ? "" : ", ", _tbl[i].strval); \
				p += written; \
				if (p >= end - 1) break; \
				first = false; \
			} \
		} \
		snprintf(p, end - p, "\r\n"); \
		return strlen(line); \
	} \
	return 0; \
}

DEFINE_PARSE_BUILD_LIKE_PUBLIC(public_, rtsp_msg_public_s, public_, "Public: %s", rtsp_msg_method_tbl)
DEFINE_PARSE_BUILD_LIKE_PUBLIC(accept, rtsp_msg_accept_s, accept, "Accept: %s", rtsp_msg_content_type_tbl)

typedef int (*rtsp_msg_line_parser)(rtsp_msg_s *msg, const char *line);
typedef struct __rtsp_msg_str2parser_tbl_s
{
	size_t strsiz;
	const char *strval;
	rtsp_msg_line_parser parser;
} rtsp_msg_str2parser_tbl_s;

static const rtsp_msg_str2parser_tbl_s rtsp_msg_hdr_line_parse_tbl[] = {
	{5, "CSeq:", rtsp_msg_parse_cseq},
	{5, "Date:", rtsp_msg_parse_date},
	{8, "Session:", rtsp_msg_parse_session},
	{10, "Transport:", rtsp_msg_parse_transport},
	{6, "Range:", rtsp_msg_parse_range},
	{7, "Accept:", rtsp_msg_parse_accept},
	{14, "Authorization:", rtsp_msg_parse_auth},
	{18, "WWW-Authorization:", rtsp_msg_parse_www_auth},
	{11, "User-Agent:", rtsp_msg_parse_user_agent},
	{7, "Public:", rtsp_msg_parse_public_},
	{9, "RTP-Info:", rtsp_msg_parse_rtp_info},
	{7, "Server:", rtsp_msg_parse_server},
	{13, "Content-Type:", rtsp_msg_parse_content_type},
	{15, "Content-Length:", rtsp_msg_parse_content_length},
	{22, "x-accept-dynamic-rate:", rtsp_msg_parse_x_accept_dynamic_rate},
	{14, "x-dynamic-rate:", rtsp_msg_parse_x_dynamic_rate},
};

static rtsp_msg_line_parser rtsp_msg_str2parser(const char *line)
{
	for (size_t i = 0; i < ARRAY_SIZE(rtsp_msg_hdr_line_parse_tbl); i++) {
		if (strncasecmp(rtsp_msg_hdr_line_parse_tbl[i].strval, line, rtsp_msg_hdr_line_parse_tbl[i].strsiz) == 0)
			return rtsp_msg_hdr_line_parse_tbl[i].parser;
	}
	return NULL;
}

// Safely gets the next line from a buffer.
// Returns a pointer to the start of the next line, or NULL if no complete line is found.
// The extracted line in `line_buf` is always null-terminated.
static const char *rtsp_msg_hdr_next_line(const char *start, char *line_buf, size_t maxlen)
{
	const char *p = start;
	const char *line_start = p;
	while (*p && *p != '\r') p++;
	if (*p != '\r' || *(p + 1) != '\n') return NULL;

	if (line_buf && maxlen > 0) {
		size_t line_len = p - line_start;
		size_t copy_len = (line_len < maxlen - 1) ? line_len : maxlen - 1;
		memcpy(line_buf, line_start, copy_len);
		line_buf[copy_len] = '\0';
	}
	return p + 2;
#if 0
	const char *p = start;
	const char *end_of_line = strstr(p, "\r\n");
	if (!end_of_line) {
		return NULL;
	}

	if (line_buf && maxlen > 0) {
		ptrdiff_t line_len = end_of_line - p;
		size_t copy_len = (line_len < maxlen - 1) ? line_len : maxlen - 1;
		memcpy(line_buf, p, copy_len);
		line_buf[copy_len] = '\0';
	}

	return end_of_line + 2;
#endif
}

int rtsp_msg_init(rtsp_msg_s *msg)
{
	if (msg)
		memset(msg, 0, sizeof(rtsp_msg_s));
	return 0;
}

void rtsp_msg_free(rtsp_msg_s *msg)
{
	if (!msg) return;
	rtsp_mem_free(msg->hdrs.cseq);
	rtsp_mem_free(msg->hdrs.date);
	rtsp_mem_free(msg->hdrs.session);
	rtsp_mem_free(msg->hdrs.transport);
	rtsp_mem_free(msg->hdrs.range);
	rtsp_mem_free(msg->hdrs.x_accept_dynamic_rate);
	rtsp_mem_free(msg->hdrs.x_dynamic_rate);

	rtsp_mem_free(msg->hdrs.accept);
	rtsp_mem_free(msg->hdrs.auth);
	rtsp_mem_free(msg->hdrs.www_auth);
	rtsp_mem_free(msg->hdrs.user_agent);

	rtsp_mem_free(msg->hdrs.public_);
	//TODO free rtp-info
	rtsp_mem_free(msg->hdrs.server);

	rtsp_mem_free(msg->hdrs.content_type);
	rtsp_mem_free(msg->hdrs.content_length);

	rtsp_mem_free(msg->body.body);

	memset(msg, 0, sizeof(rtsp_msg_s));
}

// Generates a more random session ID. Not thread-safe.
// The caller should seed the random number generator (e.g., srand(time(NULL))) at application startup.
uint32_t rtsp_msg_gen_session_id(void)
{
	#ifdef __LINUX__
	#include <sys/fcntl.h>
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		uint32_t id;
		read(fd, &id, sizeof(id));
		close(fd);
		return id;
	}
	#endif

	static bool seeded = false;
	if (!seeded) {
		srand((unsigned int)time(NULL));
		seeded = true;
	}
	return (uint32_t)rand();
}

// return frame real size. when frame is completed
// return 0. when frame size is not enough
// return -1. when frame is invalid
int rtsp_msg_frame_size(const void *data, int size)
{
	const char *frame = (const char *)data;
	int hdrlen = 0, content_len = 0;

	// Check for interleaved frame
	if (size >= 4 && frame[0] == '$') {
		uint16_t interlen;
		memcpy(&interlen, frame + 2, sizeof(interlen)); // Avoid alignment issues
		interlen = ntohs(interlen);
		if (size < 4 + interlen) return 0;
		return 4 + interlen;
	}

	// Check for RTSP message
	const char *body_start = strstr(frame, "\r\n\r\n");
	if (!body_start) {
		if (size > 2048) return -1; // Header too large
		return 0;
	}
	hdrlen = (body_start - frame) + 4;

	// Get content-length
	const char *cl_header = strcasestr(frame, "Content-Length:");
	if (cl_header && cl_header < body_start) {
		char *endptr;
		long len = strtol(cl_header + 15, &endptr, 10);
		if (cl_header + 15 != endptr && len >= 0) {
			content_len = (int)len;
		} else {
			err("parse Content-Length failed.\n");
			return -1;
		}
	}

	if (size < hdrlen + content_len) return 0;
	return (hdrlen + content_len);
}

// return data's bytes which is parsed. when success
// return 0. when data is not enough
// return -1. when data is invalid
int rtsp_msg_parse_from_array(rtsp_msg_s *msg, const void *data, int size)
{
	const char *frame = (const char *)data;
	const char *p = frame;
	// Increased buffer size to reduce risk of overflow from a single long header line.
	char line[1024];

	int frame_len = rtsp_msg_frame_size(data, size);
	if (frame_len <= 0) return frame_len;

	memset(msg, 0, sizeof(rtsp_msg_s));

	//interleaved frame
	if (frame[0] == '$') {
		uint16_t interlen;
		memcpy(&interlen, p + 2, sizeof(uint16_t)); // Safe copy to avoid alignment issues
		interlen = ntohs(interlen);

		msg->type = RTSP_MSG_TYPE_INTERLEAVED;
		msg->hdrs.startline.interline.channel = *((uint8_t*)(p + 1));
		msg->hdrs.startline.interline.length = interlen;
		msg->body.body = rtsp_mem_dup((const char*)data + 4, interlen);
		return frame_len;
	}

	dbg("\n%s", frame);

	p = rtsp_msg_hdr_next_line(p, line, sizeof(line));
	if (!p) return -1;

	if (rtsp_msg_parse_startline(msg, line) < 0) {
		rtsp_msg_free(msg);
		return -1;
	}

	while ((p = rtsp_msg_hdr_next_line(p, line, sizeof(line)))) {
		if (line[0] == '\0') break; // End of headers

		rtsp_msg_line_parser parser = rtsp_msg_str2parser(line);
		if (!parser) {
			warn("unknown line: %s\n", line);
			continue;
		}

		if ((*parser)(msg, line) < 0) {
			err("parse failed. line: %s\n", line);
			rtsp_msg_free(msg);
			return -1;
		}
	}
	if (!p) { // Should not happen if frame_size was correct
		rtsp_msg_free(msg);
		return -1;
	}

	if (msg->hdrs.content_length && msg->hdrs.content_length->length > 0) {
		msg->body.body = rtsp_mem_dup(p, msg->hdrs.content_length->length);
		if (!msg->body.body) {
			err("set body failed\n");
			rtsp_msg_free(msg);
			return -1;
		}
	}

	return frame_len;
}

// return data's bytes which is used. when success
// return -1. when failed
int rtsp_msg_build_to_array(const rtsp_msg_s *msg, void *data, int size)
{
	char *frame = (char *)data;
	char *p = frame;
	char * const end = frame + size;
	int len;

	if (msg->type == RTSP_MSG_TYPE_INTERLEAVED) {
		if (size < 4) return -1;
		uint16_t interlen = msg->hdrs.startline.interline.length;
		frame[0] = '$';
		frame[1] = msg->hdrs.startline.interline.channel;
		uint16_t net_len = htons(interlen);
		memcpy(frame + 2, &net_len, sizeof(net_len));
		if (msg->body.body && interlen > 0) {
			size_t copy_len = (interlen < size - 4) ? interlen : (size_t)(size - 4);
			memcpy(frame + 4, msg->body.body, copy_len);
			return 4 + copy_len;
		}
		return 4;
	}

#define MSG_BUILD_STEP() \
	do { \
		if (len < 0 || p + len >= end) return -1; \
		p += len; \
	} while(0)

	len = rtsp_msg_build_startline(msg, p, end - p);
	MSG_BUILD_STEP();

#define MSG_BUILD_LINE(_name) \
	do { \
		len = rtsp_msg_build_##_name(msg, p, end - p); \
		MSG_BUILD_STEP(); \
	} while(0)

	MSG_BUILD_LINE(cseq);
	MSG_BUILD_LINE(date);
	MSG_BUILD_LINE(session);
	MSG_BUILD_LINE(transport);
	MSG_BUILD_LINE(range);
	MSG_BUILD_LINE(x_accept_dynamic_rate);
	MSG_BUILD_LINE(x_dynamic_rate);
	MSG_BUILD_LINE(accept);
	MSG_BUILD_LINE(auth);
	MSG_BUILD_LINE(www_auth);
	MSG_BUILD_LINE(user_agent);

	MSG_BUILD_LINE(public_);
	MSG_BUILD_LINE(rtp_info);
	MSG_BUILD_LINE(server);

	MSG_BUILD_LINE(content_type);
	MSG_BUILD_LINE(content_length);

	len = snprintf(p, end - p, "\r\n");
	MSG_BUILD_STEP();

	if (msg->hdrs.content_length && msg->hdrs.content_length->length > 0) {
		len = msg->hdrs.content_length->length;
		if (len > end - p) len = end - p;
		memcpy(p, msg->body.body, len);
		p += len;
	}

	dbg("\n%s", frame);
	return (p - frame);
}

int rtsp_msg_set_request(rtsp_msg_s *msg, rtsp_msg_method_e mt, const char *ipaddr, const char *abspath)
{
	msg->type = RTSP_MSG_TYPE_REQUEST;
	msg->hdrs.startline.reqline.method = mt;
	msg->hdrs.startline.reqline.uri.scheme = RTSP_MSG_URI_SCHEME_RTSP;
	snprintf(msg->hdrs.startline.reqline.uri.ipaddr, sizeof(msg->hdrs.startline.reqline.uri.ipaddr), "%s", ipaddr);
	snprintf(msg->hdrs.startline.reqline.uri.abspath, sizeof(msg->hdrs.startline.reqline.uri.abspath), "%s", abspath);
	msg->hdrs.startline.reqline.version = RTSP_MSG_VERSION_1_0;
	return 0;
}

int rtsp_msg_set_response(rtsp_msg_s *msg, int status_code)
{
	msg->type = RTSP_MSG_TYPE_RESPONSE;
	msg->hdrs.startline.resline.version = RTSP_MSG_VERSION_1_0;
	msg->hdrs.startline.resline.status_code = status_code;
	return 0;
}

int rtsp_msg_get_cseq(const rtsp_msg_s *msg, uint32_t *cseq)
{
	if (!msg->hdrs.cseq) return -1;
	if (cseq) *cseq = msg->hdrs.cseq->cseq;
	return 0;
}

int rtsp_msg_set_cseq(rtsp_msg_s *msg, uint32_t cseq)
{
	if (!msg->hdrs.cseq)
		msg->hdrs.cseq = (rtsp_msg_cseq_s*)rtsp_mem_alloc(sizeof(rtsp_msg_cseq_s));
	if (!msg->hdrs.cseq) return -1;
	msg->hdrs.cseq->cseq = cseq;
	return 0;
}

int rtsp_msg_get_session(const rtsp_msg_s *msg, uint32_t *session)
{
	if (!msg->hdrs.session) return -1;
	if (session) *session = msg->hdrs.session->session;
	return 0;
}

int rtsp_msg_set_session(rtsp_msg_s *msg, uint32_t session)
{
	if (!msg->hdrs.session)
		msg->hdrs.session = (rtsp_msg_session_s*)rtsp_mem_alloc(sizeof(rtsp_msg_session_s));
	if (!msg->hdrs.session) return -1;
	msg->hdrs.session->session = session;
	return 0;
}

int rtsp_msg_get_date(const rtsp_msg_s *msg, char *date, int len)
{
	if (!msg->hdrs.date || len <= 0) return -1;
	if (date) {
		strncpy(date, msg->hdrs.date->http_date, len - 1);
		date[len - 1] = '\0';
	}
	return 0;
}

int rtsp_msg_set_date(rtsp_msg_s *msg, const char *date)
{
	if (!msg->hdrs.date)
		msg->hdrs.date = (rtsp_msg_date_s*)rtsp_mem_alloc(sizeof(rtsp_msg_date_s));
	if (!msg->hdrs.date) return -1;

	if (date) {
		snprintf(msg->hdrs.date->http_date, sizeof(msg->hdrs.date->http_date), "%s", date);
	} else {
		time_t tt = time(NULL);
		strftime(msg->hdrs.date->http_date, sizeof(msg->hdrs.date->http_date),
 				"%a, %b %d %Y %H:%M:%S GMT", gmtime(&tt));
	}
	return 0;
}

int rtsp_msg_set_transport_udp(rtsp_msg_s *msg, uint32_t ssrc, int client_port, int server_port)
{
	if (!msg->hdrs.transport)
		msg->hdrs.transport = (rtsp_msg_transport_s*)rtsp_mem_alloc(sizeof(rtsp_msg_transport_s));
	if (!msg->hdrs.transport) return -1;

	msg->hdrs.transport->type = RTSP_MSG_TRANSPORT_TYPE_RTP_AVP;
	msg->hdrs.transport->flags |= RTSP_MSG_TRANSPORT_FLAG_SSRC | RTSP_MSG_TRANSPORT_FLAG_UNICAST;
	msg->hdrs.transport->ssrc = ssrc;
	if (client_port >= 0) {
		msg->hdrs.transport->flags |= RTSP_MSG_TRANSPORT_FLAG_CLIENT_PORT;
		msg->hdrs.transport->client_port = client_port;
	}
	if (server_port >= 0) {
		msg->hdrs.transport->flags |= RTSP_MSG_TRANSPORT_FLAG_SERVER_PORT;
		msg->hdrs.transport->server_port = server_port;
	}
	return 0;
}

int rtsp_msg_set_transport_tcp(rtsp_msg_s *msg, uint32_t ssrc, int interleaved)
{
	if (!msg->hdrs.transport)
		msg->hdrs.transport = (rtsp_msg_transport_s*)rtsp_mem_alloc(sizeof(rtsp_msg_transport_s));
	if (!msg->hdrs.transport) return -1;

	msg->hdrs.transport->type = RTSP_MSG_TRANSPORT_TYPE_RTP_AVP_TCP;
	msg->hdrs.transport->flags |= RTSP_MSG_TRANSPORT_FLAG_SSRC;
	msg->hdrs.transport->ssrc = ssrc;
	if (interleaved >= 0) {
		msg->hdrs.transport->flags |= RTSP_MSG_TRANSPORT_FLAG_INTERLEAVED;
		msg->hdrs.transport->interleaved = interleaved;
	}
	return 0;
}

int rtsp_msg_get_accept(const rtsp_msg_s *msg, uint32_t *accept)
{
	if (!msg->hdrs.accept) return -1;
	if (accept) *accept = msg->hdrs.accept->accept;
	return 0;
}

int rtsp_msg_set_accept(rtsp_msg_s *msg, uint32_t accept)
{
	if (!msg->hdrs.accept)
		msg->hdrs.accept = (rtsp_msg_accept_s*)rtsp_mem_alloc(sizeof(rtsp_msg_accept_s));
	if (!msg->hdrs.accept) return -1;
	msg->hdrs.accept->accept = accept;
	return 0;
}

int rtsp_msg_get_user_agent(const rtsp_msg_s *msg, char *user_agent, int len)
{
	if (!msg->hdrs.user_agent || len <= 0) return -1;
	if (user_agent) {
		strncpy(user_agent, msg->hdrs.user_agent->user_agent, len - 1);
		user_agent[len - 1] = '\0';
	}
	return 0;
}

int rtsp_msg_set_user_agent(rtsp_msg_s *msg, const char *user_agent)
{
	if (!msg->hdrs.user_agent)
		msg->hdrs.user_agent = (rtsp_msg_user_agent_s*)rtsp_mem_alloc(sizeof(rtsp_msg_user_agent_s));
	if (!msg->hdrs.user_agent) return -1;

	const char *ua = user_agent ? user_agent : "rtsp_msg_user_agent";
	snprintf(msg->hdrs.user_agent->user_agent, sizeof(msg->hdrs.user_agent->user_agent), "%s", ua);
	return 0;
}

int rtsp_msg_get_public(const rtsp_msg_s *msg, uint32_t *public_)
{
	if (!msg->hdrs.public_) return -1;
	if (public_) *public_ = msg->hdrs.public_->public_;
	return 0;
}

int rtsp_msg_set_public(rtsp_msg_s *msg, uint32_t public_)
{
	if (!msg->hdrs.public_)
		msg->hdrs.public_ = (rtsp_msg_public_s*)rtsp_mem_alloc(sizeof(rtsp_msg_public_s));
	if (!msg->hdrs.public_) return -1;
	msg->hdrs.public_->public_ = public_;
	return 0;
}

int rtsp_msg_get_server(const rtsp_msg_s *msg, char *server, int len)
{
	if (!msg->hdrs.server || len <= 0) return -1;
	if (server) {
		strncpy(server, msg->hdrs.server->server, len - 1);
		server[len - 1] = '\0';
	}
	return 0;
}

int rtsp_msg_set_server(rtsp_msg_s *msg, const char *server)
{
	if (!msg->hdrs.server)
		msg->hdrs.server = (rtsp_msg_server_s*)rtsp_mem_alloc(sizeof(rtsp_msg_server_s));
	if (!msg->hdrs.server) return -1;

	const char *srv = server ? server : "rtsp_msg_server";
	snprintf(msg->hdrs.server->server, sizeof(msg->hdrs.server->server), "%s", srv);
	return 0;
}

int rtsp_msg_get_content_type(const rtsp_msg_s *msg, int *type)
{
	if (!msg->hdrs.content_type) return -1;
	if (type) *type = msg->hdrs.content_type->type;
	return 0;
}

int rtsp_msg_set_content_type(rtsp_msg_s *msg, int type)
{
	if (!msg->hdrs.content_type)
		msg->hdrs.content_type = (rtsp_msg_content_type_s*)rtsp_mem_alloc(sizeof(rtsp_msg_content_type_s));
	if (!msg->hdrs.content_type) return -1;
	msg->hdrs.content_type->type = (rtsp_msg_content_type_e)type;
	return 0;
}

int rtsp_msg_get_content_length(const rtsp_msg_s *msg, int *length)
{
	if (!msg->hdrs.content_length) return -1;
	if (length) *length = msg->hdrs.content_length->length;
	return 0;
}

int rtsp_msg_set_content_length(rtsp_msg_s *msg, int length)
{
	if (!msg->hdrs.content_length)
		msg->hdrs.content_length = (rtsp_msg_content_length_s*)rtsp_mem_alloc(sizeof(rtsp_msg_content_length_s));
	if (!msg->hdrs.content_length) return -1;
	msg->hdrs.content_length->length = length;
	return 0;
}

int rtsp_msg_get_auth_basic(const rtsp_msg_s *msg, char *basic_b64, int len)
{
	if (!msg->hdrs.auth || msg->hdrs.auth->type != RTSP_MSG_AUTH_TYPE_BASIC || len <= 0)
		return -1;
	if (basic_b64) {
		strncpy(basic_b64, msg->hdrs.auth->basic_b64, len - 1);
		basic_b64[len - 1] = '\0';
	}
	return 0;
}

int rtsp_msg_set_www_auth_basic(rtsp_msg_s *msg, const char *realm)
{
	if (!msg->hdrs.www_auth)
		msg->hdrs.www_auth = (rtsp_msg_www_auth_s*)rtsp_mem_alloc(sizeof(rtsp_msg_www_auth_s));
	if (!msg->hdrs.www_auth) return -1;

	msg->hdrs.www_auth->type = RTSP_MSG_AUTH_TYPE_BASIC;
	snprintf(msg->hdrs.www_auth->realm, sizeof(msg->hdrs.www_auth->realm), "%s", realm);
	return 0;
}

int rtsp_msg_set_x_accept_dynamic_rate(rtsp_msg_s *msg, uint32_t x_accept_dynamic_rate)
{
	if (!msg->hdrs.x_accept_dynamic_rate)
		msg->hdrs.x_accept_dynamic_rate = (rtsp_msg_x_accept_dynamic_rate*)rtsp_mem_alloc(sizeof(rtsp_msg_x_accept_dynamic_rate));
	if (!msg->hdrs.x_accept_dynamic_rate) return -1;
	msg->hdrs.x_accept_dynamic_rate->x_accept_dynamic_rate = x_accept_dynamic_rate;
	return 0;
}

int rtsp_msg_get_x_dynamic_rate(const rtsp_msg_s *msg, uint32_t *x_dynamic_rate)
{
	if (!msg->hdrs.x_dynamic_rate) return -1;
	if (x_dynamic_rate) *x_dynamic_rate = msg->hdrs.x_dynamic_rate->x_dynamic_rate;
	return 0;
}

int rtsp_msg_set_x_dynamic_rate(rtsp_msg_s *msg, uint32_t x_dynamic_rate)
{
	if (!msg->hdrs.x_dynamic_rate)
		msg->hdrs.x_dynamic_rate = (rtsp_msg_x_dynamic_rate*)rtsp_mem_alloc(sizeof(rtsp_msg_x_dynamic_rate));
	if (!msg->hdrs.x_dynamic_rate) return -1;
	msg->hdrs.x_dynamic_rate->x_dynamic_rate = x_dynamic_rate;
	return 0;
}

#if 0
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const char *file = "rtsp.log";
	int fd;
	char srcbuf[4096];
	char dstbuf[4096];
	ssize_t srclen = 0;
	int ret;
	rtsp_msg_s msg;

	rtsp_msg_init(&msg);

	if (argc > 1)
		file = argv[1];

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open failed");
		return -1;
	}

	do {
		ret = rtsp_msg_parse_from_array(&msg, srcbuf, srclen);
		if (ret < 0) {
			printf(">>>>>>>>>> PARSE FAILED\n");
			break;
		}
		if (ret == 0) {
			ssize_t readlen = read(fd, srcbuf + srclen, sizeof(srcbuf) - srclen);
			if (readlen <= 0) {
				printf(">>>>>>>>>>> EOF or read error\n");
				break;
			}
			srclen += readlen;
			continue;
		}

		printf("Parsed %d bytes\n", ret);
		if (srclen > ret) {
			memmove(srcbuf, srcbuf + ret, srclen - ret);
		}
		srclen -= ret;

		int build_len = rtsp_msg_build_to_array(&msg, dstbuf, sizeof(dstbuf));
		if (build_len <= 0) {
			printf(">>>>>>>>>> BUILD FAILED\n");
			break;
		}
		printf("Built %d bytes\n", build_len);
		fwrite(dstbuf, build_len, 1, stderr);
		rtsp_msg_free(&msg);
	} while (srclen > 0);

	if (srclen > 0) {
		srcbuf[srclen] = 0;
		printf("Remaining srclen = %zd\n%s\n", srclen, srcbuf);
	}

	close(fd);
	return 0;
}
#endif
