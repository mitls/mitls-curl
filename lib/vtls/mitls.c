/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2010 - 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all miTLS specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_MITLS

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "mitls.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "warnless.h"
#include "curl_printf.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Functions exported from libmitls.dll */
#include <mitlsffi.h>

/* ssl_connect_state usage
   This enum is initialized to 0/ssl_connect_1 ahead of calling
   Curl_mitls_connect*().  It is not interpreted
   by libcurl and so the TLS provider can use it to store state any way it
   chooses.  For miTLS:

  0:  ssl_connect_1           - initial state.  Initializes and configures
                                miTLS, then sets mitls_connect_state to
                                mitls_ClientHello
  1:  ssl_connect_2           - connect to the remote server
  2:  ssl_connect_2_reading   - unused
  3:  ssl_connect_2_writing   - unused
  4:  ssl_connect_3           - unused
  5:  ssl_connect_done        - set when the entire connection state machine
                                has finished successfully
*/

/* From miTLS TLSInfo.fst: */
#define max_TLSPlaintext_fragment_length    16384
#define max_TLSCompressed_fragment_length   \
  ((max_TLSPlaintext_fragment_length) + 1024)
#define max_TLSCiphertext_fragment_length   \
  ((max_TLSPlaintext_fragment_length) + 2048)

const char *mitls_TLS_V12 = "1.2";
const char *mitls_TLS_V13 = "1.3";

typedef struct {
  struct _FFI_mitls_callbacks cb;
  struct connectdata *conn;
  int sockindex;
} mitls_callback_context;

/* This is miTLS-specific state, stored inside the ssl_connect_data */
typedef struct {
  mitls_state * mitls_config;
  mitls_callback_context callback;
} mitls_context;

CURLcode Curl_mitls_connect_common(struct connectdata *conn,
                                   int sockindex,
                                   bool *done);
ssize_t Curl_mitls_send(struct connectdata *conn,
                        int sockindex,
                        const void *mem,
                        size_t len,
                        CURLcode *curlcode);
ssize_t Curl_mitls_recv(struct connectdata *conn,
                        int num,
                        char *buf,
                        size_t buffersize,
                        CURLcode *curlcode);
CURLcode Curl_mitls_connect_step_1(struct connectdata *conn,
                                   int sockindex);
CURLcode Curl_mitls_connect_step_2(struct connectdata *conn,
                                   int sockindex);
void Curl_mitls_process_messages(struct Curl_easy *data,
                                 char *outmsg, char *errmsg);
int MITLS_CALLCONV Curl_mitls_send_callback(struct _FFI_mitls_callbacks *callbacks,
                             const void *buffer,
                             size_t buffer_size);
int MITLS_CALLCONV Curl_mitls_recv_callback(struct _FFI_mitls_callbacks *callbacks,
                             void *buffer,
                             size_t buffer_size);

/* Called by CURL */
int  Curl_mitls_init(void)
{
  int retval;

  retval = FFI_mitls_init();
  return retval;
}

/* Called by CURL */
void Curl_mitls_cleanup(void)
{
  FFI_mitls_cleanup();
}

void Curl_mitls_process_messages(struct Curl_easy *data,
                                 char *outmsg,
                                 char *errmsg)
{
  if(outmsg) {
    infof(data, "mitls: %s", outmsg);
    FFI_mitls_free_msg(outmsg);
  }
  if(errmsg) {
    failf(data, "mitls: %s", errmsg);
    FFI_mitls_free_msg(errmsg);
  }
}

/* Called by CURL */
ssize_t Curl_mitls_send(struct connectdata *conn,
                        int sockindex,
                        const void *mem,
                        size_t len,
                        CURLcode *curlcode)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  mitls_context *connmitls = (mitls_context*)connssl->mitls_ctx;
  int result;
  char *outmsg = NULL;
  char *errmsg = NULL;

  result = FFI_mitls_send(connmitls->mitls_config, mem, len, &outmsg, &errmsg);
  Curl_mitls_process_messages(data, outmsg, errmsg);
  if(result == 0) {
    failf(data, "Failed FFI_mitls_prepare_send\n");
    *curlcode = CURLE_SEND_ERROR;
    return (ssize_t)-1;
  }
  *curlcode = CURLE_OK;
  return (ssize_t)len;
}

/* Called by CURL */
ssize_t Curl_mitls_recv(struct connectdata *conn,
                        int sockindex,
                        char *buf,
                        size_t buffersize,
                        CURLcode *curlcode)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  mitls_context *connmitls = (mitls_context*)connssl->mitls_ctx;
  char *outmsg = NULL;
  char *errmsg = NULL;
  size_t packet_size = 0;
  void *packet;

retry:
  packet = FFI_mitls_receive(connmitls->mitls_config,
             &packet_size,
             &outmsg, &errmsg);
  Curl_mitls_process_messages(data, outmsg, errmsg);
  if(packet == NULL) {
    *curlcode = CURLE_RECV_ERROR;
    failf(data, "Leaving Curl_mitls_recv -1 after failed FFI\n");
    return -1;
  }
  infof(data, "Curl_mitls_recv got %d bytes.  Caller asked for %d bytes.\n",
        (int)packet_size, (int)buffersize);
  if(packet_size == 0) {
    goto retry;
  }
  if(packet_size > buffersize) {
    packet_size = buffersize;
  }
  memcpy(buf, packet, packet_size);
  FFI_mitls_free_packet(packet);
  *curlcode = CURLE_OK;
  return packet_size;
}


/* Initializes and configures miTLS */
CURLcode Curl_mitls_connect_step_1(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  mitls_context *connmitls = NULL;
  void *ssl_sessionid;
  char *outmsg = NULL;
  char *errmsg = NULL;
  int result;
  CURLcode ret = CURLE_SSL_CONNECT_ERROR;
  const char *tls_version = NULL;
  char *ciphers;

  const long int ssl_version = SSL_CONN_CONFIG(version);
#ifdef USE_TLS_SRP
  const enum CURL_TLSAUTH ssl_authtype = SSL_SET_OPTION(authtype);
#endif
  char * const ssl_cert = SSL_SET_OPTION(cert);
  const char * const ssl_cert_type = SSL_SET_OPTION(cert_type);
  const char * const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const char * const ssl_capath = SSL_CONN_CONFIG(CApath);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char * const ssl_crlfile = SSL_SET_OPTION(CRLfile);
  const char * const ssl_key = SSL_SET_OPTION(key);
  const char * const ssl_key_type = SSL_SET_OPTION(key_type);

  if(connssl->mitls_ctx) {
    free(connssl->mitls_ctx);
    connssl->mitls_ctx = NULL;
  }
  connmitls = (mitls_context*)malloc(sizeof(mitls_context));
  if(!connmitls) {
    return CURLE_OUT_OF_MEMORY;
  }
  memset(connmitls, 0, sizeof(*connmitls));
  connssl->mitls_ctx = connmitls;
  switch(ssl_version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1_2:
    tls_version = mitls_TLS_V12;
    break;
  case CURL_SSLVERSION_TLSv1_3:
    tls_version = mitls_TLS_V13;
    break;
  default:
    failf(data, "Unsupported SSL protocol version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(ssl_cert_type) {
    infof(data, "WARNING: SSL: cert_type is ignored by miTLS.\n");
  }
  if(ssl_capath) {
    infof(data, "WARNING: SSL: CApath is ignored by miTLS.\n");
  }
  if(verifypeer) {
    infof(data, "WARNING: SSL: verifypeer is ignored by miTLS.\n");
  }
  if(ssl_crlfile) {
    infof(data, "WARNING: SSL: CRTfile is ignored by miTLS.\n");
  }
  if(ssl_key_type) {
    infof(data, "WARNING: SSL: key_type is ignored by miTLS.\n");
  }

  /* Check if there's a cached ID we can/should use here! */
  if(SSL_SET_OPTION(primary.sessionid)) {
    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL, sockindex)) {
      /* we got a session id, use it! */

      /* bugbug: use it for something.
         SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len); */

      Curl_ssl_sessionid_unlock(conn);
      /* Informational message */
     infof(data, "SSL re-using session ID\n");
    }
  }

  /* Create a miTLS-side config object representing the TLS connection
     settings */
  result = FFI_mitls_configure(&connmitls->mitls_config,
                               tls_version,
                               conn->host.name,
                               &outmsg,
                               &errmsg);
  Curl_mitls_process_messages(data, outmsg, errmsg);
  if(result == 0) {
	failf(data, "FFI_mitls_configure failed\n");
	return ret;
  }
  if(ssl_cafile) {
	result = FFI_mitls_configure_ca_file(connmitls->mitls_config, ssl_cafile);
	if (result == 0) {
	  failf(data, "FFI_mitls_configure_ca_file failed\n");
	  return ret;
	}
  }
  if(ssl_cert) {
	result = FFI_mitls_configure_cert_chain_file(connmitls->mitls_config, ssl_cert);
	if (result == 0) {
	  failf(data, "FFI_mitls_configure_cert_chain_file failed\n");
	  return ret;
	}
  }
  if(ssl_key) {
	result = FFI_mitls_configure_private_key_file(connmitls->mitls_config, ssl_key);
	if (result == 0) {
	  failf(data, "FFI_mitls_configure_private_key_file failed\n");
	  return ret;
	}
  }
  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {
	result = FFI_mitls_configure_cipher_suites(connmitls->mitls_config, ciphers);
	if (result == 0) {
	  failf(data, "FFI_mitls_configure_cipher_suites failed\n");
	  return ret;
	}
  }
  /* bugbug: signature algorithm and named groups are not supported by curl */

  if(conn->bits.tls_enable_alpn) {
    char alpn_buffer[128];
    int cur;
    unsigned short* list_len;

    list_len = (unsigned short*)&alpn_buffer[0];
    cur = sizeof(unsigned short);

#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      memcpy(&alpn_buffer[cur], NGHTTP2_PROTO_ALPN, NGHTTP2_PROTO_ALPN_LEN);
      cur += NGHTTP2_PROTO_ALPN_LEN;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }
#endif

    alpn_buffer[cur++] = ALPN_HTTP_1_1_LENGTH;
    memcpy(&alpn_buffer[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
    cur += ALPN_HTTP_1_1_LENGTH;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    *list_len = curlx_uitous(cur);
    result = FFI_mitls_configure_alpn(connmitls->mitls_config, alpn_buffer);
	if (result == 0) {
	  failf(data, "FFI_mitls_configure_alpn failed\n");
	  return ret;
	}
  }
  /* Configuration succeeded. Begin connecting */
  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

/* This is called by miTLS within FFI_mitls_connect() */
int MITLS_CALLCONV Curl_mitls_send_callback(struct _FFI_mitls_callbacks *callbacks,
                             const void *buffer,
                             size_t buffer_size)
{
  mitls_callback_context *ctx = (mitls_callback_context*)callbacks;
  struct Curl_easy *data = ctx->conn->data;
  ssize_t Remaining = (ssize_t)buffer_size;
  ssize_t SendResult;
  const char *RemainingBuffer = (const char*)buffer;

  while (Remaining) {
    if(Curl_timeleft(data, NULL, TRUE) < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection send() timeout");
      return -1;
    }
    SendResult = send(ctx->conn->sock[ctx->sockindex], RemainingBuffer, Remaining, 0);
    if (SendResult < 0) {
      int e = errno;
      if(e == EAGAIN || e == EWOULDBLOCK) {
        infof(data, "Curl_mitls_send_callback():  EAGAIN or EWOULDBLOCK."
                    "  Trying again\n");
         Curl_wait_ms(1);
      }
      else {
        char msg[128];
        strerror_r(e, msg, sizeof(msg));
        infof(data, "Curl_mitls_send_callback():  Unknown errno %d - %s\n",
                    e, msg);
		return -1;
      }
    }
    else {
	  Remaining -= SendResult;
	  RemainingBuffer += SendResult;
    }
  }

  return (int)buffer_size;
}

/* This is called by miTLS within FFI_mitls_connect() */
int MITLS_CALLCONV Curl_mitls_recv_callback(struct _FFI_mitls_callbacks *callbacks,
                             void *buffer,
                             size_t buffer_size)
{
  mitls_callback_context *ctx = (mitls_callback_context*)callbacks;
  struct Curl_easy *data = ctx->conn->data;
  ssize_t RecvResult;
  ssize_t Remaining = buffer_size;
  char *RecvBuffer = (char*)buffer;

  while (Remaining) {
    if(Curl_timeleft(data, NULL, TRUE) < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection recv() timeout");
      return -1;
    }

    RecvResult = recv(ctx->conn->sock[ctx->sockindex],
                      RecvBuffer, Remaining,
                      0);
    if(RecvResult < 0) {
      int e = errno;
      if(e == EAGAIN || e == EWOULDBLOCK) {
        infof(data,
             "Curl_mitls_recv_callback():  EAGAIN or EWOULDBLOCK\n");
        Curl_wait_ms(1);
      }
      else {
        char msg[128];
        strerror_r(e, msg, sizeof(msg));
        infof(data, "Curl_mitls_recv_callback():  Unknown errno %d - %s\n",
              e, msg);
	    return -1;
      }
	} else {
		Remaining -= RecvResult;
		RecvBuffer += RecvResult;
	}
  }

  return (int)buffer_size;
}


CURLcode Curl_mitls_connect_step_2(struct connectdata *conn,
                                   int sockindex)
{
  struct Curl_easy *data = conn->data;
  mitls_context *connmitls = (mitls_context*)conn->ssl[sockindex].mitls_ctx;
  int ret;
  CURLcode result = CURLE_FAILED_INIT;
  char *outmsg;
  char *errmsg;

  connmitls->callback.cb.send = Curl_mitls_send_callback;
  connmitls->callback.cb.recv = Curl_mitls_recv_callback;
  connmitls->callback.conn = conn;
  connmitls->callback.sockindex = sockindex;

  ret = FFI_mitls_connect(&connmitls->callback.cb,
                          connmitls->mitls_config,
                          &outmsg, &errmsg);
  Curl_mitls_process_messages(data, outmsg, errmsg);

  if(ret == 0) {
    failf(data, "FFI_mitls_connect failed");
    result = CURLE_FAILED_INIT;
  }
  else {
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    infof(data, "FFI_mitls_connect succeeded.  Connection complete.");
    connssl->connecting_state = ssl_connect_done;

    if(SSL_SET_OPTION(primary.sessionid)) {
      bool incache;
      void *our_ssl_sessionid;
      void *old_ssl_sessionid = NULL;

      our_ssl_sessionid = NULL; /* bugbug: fetch from miTLS */

      Curl_ssl_sessionid_lock(conn);
      incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL,
                                        sockindex));
      if(incache) {
        if(old_ssl_sessionid != our_ssl_sessionid) {
          infof(data, "old SSL session ID is stale, removing\n");
          Curl_ssl_delsessionid(conn, old_ssl_sessionid);
          incache = FALSE;
        }
      }

      if(!incache) {
        result = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                        0 /* unknown size */, sockindex);
        if(result) {
          Curl_ssl_sessionid_unlock(conn);
          failf(data, "failed to store ssl session");
          return result;
        }
    }
    else {
      /* Session was incache, so refcount already incremented earlier.
        */
      ; /* bugbug: implement */
    }
    Curl_ssl_sessionid_unlock(conn);
  }

    result = CURLE_OK;
  }

  return result;
}

CURLcode Curl_mitls_connect_common(struct connectdata *conn,
                                   int sockindex,
                                   bool *done)
{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  /* Uncomment this line in order to enable infof() to log to stderr in host
     apps that don't support verbose logging, such as git. */
  /* data->set.verbose = 1; */

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(Curl_timeleft(data, NULL, TRUE) < 0) {
    /* no need to continue if time already is up */
    failf(data, "SSL connection timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  switch(connssl->connecting_state) {
  case ssl_connect_1:
    result = Curl_mitls_connect_step_1(conn, sockindex);
    return result;
  case ssl_connect_2:
    result = Curl_mitls_connect_step_2(conn, sockindex);
    return result;
  case ssl_connect_done:
    connssl->connecting_state = ssl_connect_1;
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = Curl_mitls_recv;
    conn->send[sockindex] = Curl_mitls_send;
    *done = TRUE;
    return CURLE_OK;
  default:
    failf(data, "Invalid connecting_state");
    return CURLE_FAILED_INIT;
  }

  failf(data, "Unexpected exit from Curl_mitls_connect_common");
  return CURLE_FAILED_INIT;
}

/* Called by CURL */
CURLcode Curl_mitls_connect(struct connectdata *conn, int sockindex)
{
  bool done = FALSE;
  CURLcode retval;

  retval = Curl_mitls_connect_common(conn, sockindex, &done);
  return retval;
}

/* Called by CURL */
CURLcode Curl_mitls_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done)
{
  CURLcode retval;

  retval = Curl_mitls_connect_common(conn, sockindex, done);
  return retval;
}

void Curl_mitls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->mitls_ctx) {
    mitls_context *connmitls =
           (mitls_context*)connssl->mitls_ctx;

    FFI_mitls_close(connmitls->mitls_config);
    connmitls->mitls_config = NULL;
    free(connssl->mitls_ctx);
    connssl->mitls_ctx = NULL;
  }
}

void Curl_mitls_session_free(void *ptr)
{
  (void)ptr;
}

size_t Curl_mitls_version(char *buffer, size_t size)
{
  const unsigned int version = 0x00000101;

  return snprintf(buffer, size, "%s/%d.%d.%d",
                  "miTLS",
                  version>>24, (version>>16)&0xff, (version>>8)&0xff);
}
int Curl_mitls_shutdown(struct connectdata *conn, int sockindex)
{
  (void)conn;
  (void)sockindex;
  return 0; /* success */
}

void Curl_mitls_sha256sum(const unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *sha256sum /* output */,
                      size_t unused)
{
  (void)tmp;
  (void)tmplen;
  (void)sha256sum;
  (void)unused;
}

#endif /* USE_MITLS */
