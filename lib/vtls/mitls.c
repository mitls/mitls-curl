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
#include "strerror.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Functions exported from libmitls.dll */
#include <mitlsffi.h>
#include <mipki.h>

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

/* This is miTLS-specific state, stored inside the ssl_connect_data->backend field */
struct ssl_backend_data {
  mitls_state * mitls_config;
  struct connectdata *conn;
  int sockindex;

  unsigned char *PendingRecv; /* Tail of data leftover from FFI_mitls_receive() */
  size_t PendingRecvOffset; /* Number of bytes consumed already from PendingRecv */
  size_t PendingRecvLength; /* Total byte count in PendingRecv */

  mipki_state *pki;
};

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
int MITLS_CALLCONV Curl_mitls_send_callback(
                             void *context,
                             const unsigned char *buffer,
                             size_t buffer_size);
int MITLS_CALLCONV Curl_mitls_recv_callback(
                             void *context,
                             unsigned char *buffer,
                             size_t buffer_size);

__thread struct Curl_easy *Curl_mitls_data;
void MITLS_CALLCONV Curl_mitls_process_messages(const char *msg);

/* Called by CURL */
int  Curl_mitls_init(void)
{
  int retval;

  FFI_mitls_set_trace_callback(Curl_mitls_process_messages);
  retval = FFI_mitls_init();
  return retval;
}

/* Called by CURL */
void Curl_mitls_cleanup(void)
{
  FFI_mitls_cleanup();
}

/* miTLS callback, to print debug messages.  miTLS doesn't pass
   a context pointer through, so we use a per-thread variable,
   Curl_mitls_data. */
void MITLS_CALLCONV Curl_mitls_process_messages(const char *msg)
{
  infof(Curl_mitls_data, "mitls: %s\n", msg);
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
  struct ssl_backend_data *connmitls = connssl->backend;
  int result;

  Curl_mitls_data = data;
  result = FFI_mitls_send(connmitls->mitls_config, mem, len);
  Curl_mitls_data = NULL;
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
  struct ssl_backend_data *connmitls = connssl->backend;
  size_t packet_size = 0;
  unsigned char *packet;

  if(connmitls->PendingRecv) {
      /* There is leftover data from a previous FFI_mitls_receive() */
      packet_size = connmitls->PendingRecvLength - connmitls->PendingRecvOffset;
      if(packet_size > buffersize) {
        packet_size = buffersize;
      }
      infof(data, "Curl_mitls_recv has extra %d bytes.  Caller asked for %d bytes.\n",
            (int)packet_size, (int)buffersize);
      memcpy(buf, connmitls->PendingRecv + connmitls->PendingRecvOffset, packet_size);
      connmitls->PendingRecvOffset += packet_size;
      if(connmitls->PendingRecvOffset == connmitls->PendingRecvLength) {
          FFI_mitls_free(connmitls->mitls_config, connmitls->PendingRecv);
          connmitls->PendingRecv = NULL;
          connmitls->PendingRecvLength = 0;
          connmitls->PendingRecvOffset = 0;
      }
  } else {
      do {
        Curl_mitls_data = data;
        packet = FFI_mitls_receive(connmitls->mitls_config, &packet_size);
        Curl_mitls_data = NULL;
        if(packet == NULL) {
          *curlcode = CURLE_RECV_ERROR;
          failf(data, "Leaving Curl_mitls_recv -1 after failed FFI\n");
          return -1;
        }
        infof(data, "Curl_mitls_recv got %d bytes from miTLS.  Caller asked for %d bytes.\n",
              (int)packet_size, (int)buffersize);
      } while (packet_size == 0);
      if(packet_size > buffersize) {
        connmitls->PendingRecv = packet;
        connmitls->PendingRecvLength = packet_size;
        connmitls->PendingRecvOffset = buffersize;
        packet_size = buffersize;
      }
      memcpy(buf, packet, packet_size);
      if (!connmitls->PendingRecv) {
        /* All of the packet was consumed.  Free it now.  Otherwise,
           it remains buffered, ready for the next recv call. */
        FFI_mitls_free(connmitls->mitls_config, packet);
      }
  }
  *curlcode = CURLE_OK;
  return packet_size;
}

/* mipki callback function */
void* Curl_mitls_certificate_select(void *cbs, mitls_version ver, const unsigned char *sni, size_t sni_len, const unsigned char *alpn, size_t alpn_len, const mitls_signature_scheme *sigalgs, size_t sigalgs_len, mitls_signature_scheme *selected)
{
  struct ssl_backend_data *connmitls = (struct ssl_backend_data*)cbs;
  mipki_chain r = mipki_select_certificate(connmitls->pki, (char*)sni, sni_len, sigalgs, sigalgs_len, selected);
  return (void*)r;
}

/* mipki callback function */
size_t Curl_mitls_certificate_format(void *cbs, const void *cert_ptr, unsigned char *buffer)
{
  struct ssl_backend_data *connmitls = (struct ssl_backend_data*)cbs;
  mipki_chain chain = (mipki_chain)cert_ptr;
  return mipki_format_chain(connmitls->pki, chain, (char*)buffer, MAX_CHAIN_LEN);
}

/* mipki callback function */
size_t Curl_mitls_certificate_sign(void *cbs, const void *cert_ptr, const mitls_signature_scheme sigalg, const unsigned char *tbs, size_t tbs_len, unsigned char *sig)
{
  struct ssl_backend_data *connmitls = (struct ssl_backend_data*)cbs;
  size_t ret = MAX_SIGNATURE_LEN;

  if(mipki_sign_verify(connmitls->pki, cert_ptr, sigalg, (char*)tbs, tbs_len, (char*)sig, &ret, MIPKI_SIGN))
    return ret;

  return 0;
}

/* mipki callback function */
int Curl_mitls_certificate_verify(void *cbs, const unsigned char* chain_bytes, size_t chain_len, const mitls_signature_scheme sigalg, const unsigned char *tbs, size_t tbs_len, const unsigned char *sig, size_t sig_len)
{
  struct ssl_backend_data *connmitls = (struct ssl_backend_data*)cbs;
  struct Curl_easy *data = connmitls->conn->data;
  
  mipki_chain chain = mipki_parse_chain(connmitls->pki, (char*)chain_bytes, chain_len);

  if(chain == NULL)
  {
    failf(data, "ERROR: failed to parse certificate chain");
    return 0;
  }

  // We don't validate hostname, but could with the callback state
  if(!mipki_validate_chain(connmitls->pki, chain, connmitls->conn->host.name))
  {
    infof(data, "WARNING: chain validation failed, ignoring.\n");
    return 0;
  }

  size_t slen = sig_len;
  int r = mipki_sign_verify(connmitls->pki, chain, sigalg, (char*)tbs, tbs_len, (char*)sig, &slen, MIPKI_VERIFY);
  mipki_free_chain(connmitls->pki, chain);
  return r;
}

/* Initializes and configures miTLS */
CURLcode Curl_mitls_connect_step_1(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *connmitls = NULL;
  void *ssl_sessionid;
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
  const char * ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const char * const ssl_capath = SSL_CONN_CONFIG(CApath);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char * const ssl_crlfile = SSL_SET_OPTION(CRLfile);
  const char * const ssl_key = SSL_SET_OPTION(key);
  const char * const ssl_key_type = SSL_SET_OPTION(key_type);

  if(connssl->backend) {
    free(connssl->backend);
    connssl->backend = NULL;
  }
  connmitls = (struct ssl_backend_data*)malloc(sizeof(struct ssl_backend_data));
  if(!connmitls) {
    return CURLE_OUT_OF_MEMORY;
  }
  memset(connmitls, 0, sizeof(*connmitls));
  connssl->backend = connmitls;
  connmitls->conn = conn;
  connmitls->sockindex = sockindex;
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
  Curl_mitls_data = data;
  result = FFI_mitls_configure(&connmitls->mitls_config,
                               tls_version,
                               conn->host.name);
  Curl_mitls_data = NULL;
  if(result == 0) {
    failf(data, "FFI_mitls_configure failed\n");
    return ret;
  }
  
  int erridx;
  mipki_state *pki = mipki_init(NULL, 0, NULL, &erridx);
  if(!pki) {
      failf(data, "mipki_init failed\n");
      return ret;
  }
  connmitls->pki = pki;
  mitls_cert_cb cert_callbacks;
  cert_callbacks.select = Curl_mitls_certificate_select;
  cert_callbacks.format = Curl_mitls_certificate_format;
  cert_callbacks.sign = Curl_mitls_certificate_sign;
  cert_callbacks.verify = Curl_mitls_certificate_verify;
  result = FFI_mitls_configure_cert_callbacks(connmitls->mitls_config, connmitls, &cert_callbacks);
  if(result == 0) {
    failf(data, "FFI_mitls_configure_cert_callbacks failed\n");
    return ret;
  }

  if(!ssl_cafile) {
    ssl_cafile = "./CAFile.pem";
  }
  if(!mipki_add_root_file_or_path(pki, ssl_cafile)) {
    failf(data, "Failed to load CAFile %s\n", ssl_cafile);
    return ret;
  }

  if(ssl_cert) {
    failf(data, "Cert Chain File is not supported\n");
  }
  if(ssl_key) {
    failf(data, "Private Key File is not supported\n");
  }
  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {
    result = FFI_mitls_configure_cipher_suites(connmitls->mitls_config,
                                               ciphers);
    if(result == 0) {
      failf(data, "FFI_mitls_configure_cipher_suites failed\n");
      return ret;
    }
  }
  /* bugbug: signature algorithm and named groups are not supported by curl */

  if(conn->bits.tls_enable_alpn) {
    size_t alpn_count = 0;
    mitls_alpn alpn[2];

#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      alpn[alpn_count].alpn = NGHTTP2_PROTO_ALPN;
      alpn[alpn_count].alpn_len = NGHTTP2_PROTO_ALPN_LEN;
      alpn_count++;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_ALPN);
    }
#endif

    alpn[alpn_count].alpn = ALPN_HTTP_1_1;
    alpn[alpn_count].alpn_len = ALPN_HTTP_1_1_LENGTH;
    alpn_count++;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    Curl_mitls_data = data;
    result = FFI_mitls_configure_alpn(connmitls->mitls_config, alpn, alpn_count);
    Curl_mitls_data = NULL;
    if(result == 0) {
      failf(data, "FFI_mitls_configure_alpn failed\n");
      return ret;
    }
  }
  /* Configuration succeeded. Begin connecting */
  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

/* This is called by miTLS when it has data to send */
int MITLS_CALLCONV Curl_mitls_send_callback(
  void *context,
  const unsigned char *buffer,
  size_t buffer_size)
{
  struct ssl_backend_data *ctx = (struct ssl_backend_data *)context;
  struct connectdata *conn = ctx->conn;
  struct Curl_easy *data = conn->data;
  ssize_t Remaining = (ssize_t)buffer_size;
  ssize_t SendResult;
  const char *RemainingBuffer = (const char *)buffer;
  int IsWritable;
  time_t TimeRemaining;
  ssize_t BytesWritten;

  while(Remaining) {
    TimeRemaining = Curl_timeleft(data, NULL, TRUE);
    if (TimeRemaining < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection send() timeout");
      return -1;
    }
    IsWritable = SOCKET_WRITABLE(conn->sock[ctx->sockindex], TimeRemaining);
    if(IsWritable < 0) {
      failf(data, "Curl_mitls_send_callback - socket isn't writable.\n");
      return -1;
    } else if (IsWritable == 0) {
      failf(data, "Curl_mitls_send_callback - timed out sending data.\n");
      return -1;
    }

    SendResult = Curl_write_plain(conn, conn->sock[ctx->sockindex],
                      RemainingBuffer, Remaining, &BytesWritten);
    if(SendResult == CURLE_AGAIN) {
      infof(data, "Curl_mitls_send_callback():  CURLE_AGAIN."
                "  Trying again\n");
       Curl_wait_ms(1);
    } else if(SendResult != CURLE_OK) {
       infof(data, "Curl_mitls_send_callback():  CURLE_ error %d\n", SendResult);
       return -1;
    }
    else {
      Remaining -= BytesWritten;
      RemainingBuffer += BytesWritten;
    }
  }

  infof(data, "Curl_mitls_send_callback returning %d\n", (int)buffer_size);

  return (int)buffer_size;
}

/* This is called by miTLS when it wants more data */
int MITLS_CALLCONV Curl_mitls_recv_callback(
  void *context,
  unsigned char *buffer,
  size_t buffer_size)
{
  struct ssl_backend_data *ctx = (struct ssl_backend_data *)context;
  struct connectdata *conn = ctx->conn;
  struct Curl_easy *data = conn->data;
  CURLcode RecvResult;
  ssize_t Remaining = buffer_size;
  char *RecvBuffer = (char *)buffer;
  ssize_t BytesReceived;
  int IsReadable;
  time_t TimeRemaining;

  while(Remaining) {
    TimeRemaining = Curl_timeleft(data, NULL, TRUE);
    if(TimeRemaining < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection recv() timeout");
      return -1;
    }
    IsReadable = SOCKET_READABLE(conn->sock[ctx->sockindex], TimeRemaining);
    if(IsReadable < 0) {
      failf(data, "Curl_mitls_recv_callback - socket isn't readable.\n");
      return -1;
    } else if (IsReadable == 0) {
      failf(data, "Curl_mitls_recv_callback - timed out sending data.\n");
      return -1;
    }

    RecvResult = Curl_read_plain(conn->sock[ctx->sockindex],
                                 RecvBuffer, Remaining,
                                 &BytesReceived);
    if(RecvResult == CURLE_AGAIN) {
      infof(data,
           "Curl_mitls_recv_callback():  CURLE_AGAIN\n");
      Curl_wait_ms(1);
    } else if(RecvResult != CURLE_OK) {
      infof(data, "Curl_mitls_recv_callback():  CURLE_ error %d\n", RecvResult);
      return -1;
    } else {
      Remaining -= BytesReceived;
      RecvBuffer += BytesReceived;
    }
  }

  infof(data, "Curl_mitls_recv_callback returning %d\n", (int)buffer_size);
  return (int)buffer_size;
}


CURLcode Curl_mitls_connect_step_2(struct connectdata *conn,
                                   int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_backend_data *connmitls = conn->ssl[sockindex].backend;
  int ret;
  CURLcode result = CURLE_FAILED_INIT;

  Curl_mitls_data = data;
  ret = FFI_mitls_connect(connmitls,
                          Curl_mitls_send_callback,
                          Curl_mitls_recv_callback,
                          connmitls->mitls_config);

  Curl_mitls_data = NULL;
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
  if(conn->ssl[sockindex].use) {
    /* if the SSL/TLS channel hasn't been shut down yet, do that now. */
    Curl_ssl_shutdown(conn, sockindex);
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
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->backend) {
    struct ssl_backend_data *connmitls = connssl->backend;
    struct Curl_easy *data = conn->data;

    Curl_mitls_data = data;
    FFI_mitls_close(connmitls->mitls_config);
    Curl_mitls_data = NULL;

    mipki_free(connmitls->pki);
    connmitls->pki = NULL;
    
    connmitls->mitls_config = NULL;

    free(connmitls->PendingRecv);
    connmitls->PendingRecv = NULL;

    free(connssl->backend);
    connssl->backend = NULL;
  }
  return CURLE_OK;
}

bool Curl_mitls_data_pending(const struct connectdata *conn,
                             int sockindex)
{
  struct Curl_easy *data = conn->data;
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  const struct ssl_backend_data *connmitls = connssl->backend;

  return connmitls->PendingRecv != NULL;
}

void *Curl_mitls_get_internals(struct ssl_connect_data *connssl,
                               CURLINFO info UNUSED_PARAM)
{
  (void)info;
  const struct ssl_backend_data *connmitls = connssl->backend;
  return connmitls->mitls_config;
}

const struct Curl_ssl Curl_ssl_mitls = {
  { CURLSSLBACKEND_MITLS, "mitls" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CERTINFO |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_SSL_CTX |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_HTTPS_PROXY,

  sizeof(struct ssl_backend_data),

  Curl_mitls_init,                /* init */
  Curl_mitls_cleanup,             /* cleanup */
  Curl_mitls_version,             /* version */
  Curl_none_check_cxn,            /* check_cxn */
  Curl_mitls_shutdown,            /* shutdown */
  Curl_mitls_data_pending,        /* data_pending */
  Curl_none_random,               /* random */
  Curl_none_cert_status_request,  /* cert_status_request */
  Curl_mitls_connect,             /* connect */
  Curl_mitls_connect_nonblocking, /* connect_nonblocking */
  Curl_mitls_get_internals,       /* get_internals */
  Curl_mitls_close,               /* close_one */
  Curl_none_close_all,            /* close_all */
  Curl_mitls_session_free,        /* session_free */
  Curl_none_set_engine,           /* set_engine */
  Curl_none_set_engine_default,   /* set_engine_default */
  Curl_none_engines_list,         /* engines_list */
  Curl_none_false_start,          /* false_start */
  Curl_none_md5sum,               /* md5sum */
  NULL                            /* sha256sum */
};


#endif /* USE_MITLS */
