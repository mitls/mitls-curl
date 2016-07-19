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
#include "rawstr.h"
#include "curl_printf.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

// Functions exported from libmitls.dll:
#include <mitlsffi.h>

// bugbug: temporarily Suppress some warnings enabled in the debug curl build
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wpedantic" // for uses of __FUNCTION__ in C code
#pragma GCC diagnostic ignored "-Wunused-parameter"

// ssl_connect_state usage
//   This enum is initialized to 0/ssl_connect_1 ahead of calling Curl_mitls_connect*().  It is not interpreted
//   by libcurl and so the TLS provider can use it to store state any way it chooses.  For miTLS:
//
//  0:  ssl_connect_1           - initial state.  Initializes and configures miTLS, then sets mitls_connect_state to mitls_ClientHello
//  1:  ssl_connect_2           - connect to the remote server
//  2:  ssl_connect_2_reading   - unused
//  3:  ssl_connect_2_writing   - unused
//  4:  ssl_connect_3           - unused
//  5:  ssl_connect_done        - set when the entire connection state machine has finished successfully

// From miTLS TLSInfo.fst:
#define max_TLSPlaintext_fragment_length    16384 
#define max_TLSCompressed_fragment_length   ((max_TLSPlaintext_fragment_length) + 1024)
#define max_TLSCiphertext_fragment_length   ((max_TLSPlaintext_fragment_length) + 2048)

const char *mitls_TLS_V12 = "1.2";
const char *mitls_TLS_V13 = "1.3";

typedef struct {
    struct _FFI_mitls_callbacks cb;
    struct connectdata *conn;
    int sockindex;
} mitls_callback_context;

// This is miTLS-specific state, stored inside the ssl_connect_data
typedef struct {
    mitls_state * mitls_config;
    
    ssize_t record_length;      // actual # of bytes in record[]
    char header[5];             // 5-byte header for TLS records
    char record[65536];         // the remainder of the TLS record (max of max_TLSCiphertext_fragment_length during TLS negotiation, but longer for recv() later
    
    mitls_callback_context callback;
} mitls_connect_context;

CURLcode Curl_mitls_connect_common(struct connectdata *conn, int sockindex, bool blocking, bool *done);
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
CURLcode Curl_mitls_connect_step_1(struct connectdata *conn, int sockindex);
CURLcode Curl_mitls_connect_step_2(struct connectdata *conn, int sockindex, bool blocking);
CURLcode Curl_mitls_RecvRecord(struct SessionHandle *data, mitls_connect_context *connmitls, curl_socket_t sockfd, bool blocking);

// Called by CURL
int  Curl_mitls_init(void)
{
    int retval;
    
    retval = FFI_mitls_init();
    return retval;
}

// Called by CURL
void Curl_mitls_cleanup(void)
{
    FFI_mitls_cleanup();
}

void Curl_mitls_process_messages(struct SessionHandle *data, char *outmsg, char *errmsg)
{
    if (outmsg) {
        infof(data, "mitls: %s", outmsg);
        FFI_mitls_free_msg(outmsg);
    }
    if (errmsg) {
        failf(data, "mitls: %s", errmsg);
        FFI_mitls_free_msg(errmsg);
    }   
}

// Called by CURL
ssize_t Curl_mitls_send(struct connectdata *conn,
                        int sockindex,
                        const void *mem,
                        size_t len,
                        CURLcode *curlcode)
{
    struct SessionHandle *data = conn->data;
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    mitls_connect_context *connmitls = (mitls_connect_context*)connssl->mitls_ctx;
    int result;
    char *outmsg = NULL;
    char *errmsg = NULL;
      
    result = FFI_mitls_send(connmitls->mitls_config, mem, len, &outmsg, &errmsg); 
    Curl_mitls_process_messages(data, outmsg, errmsg);
    if (result == 0) {
        failf(data, "Failed FFI_mitls_prepare_send\n");
        *curlcode = CURLE_SEND_ERROR;
        return (ssize_t)-1; 
    }
    *curlcode = CURLE_OK;
    return (ssize_t)len;
}

// Called by CURL
ssize_t Curl_mitls_recv(struct connectdata *conn,
                        int sockindex,
                        char *buf,
                        size_t buffersize,
                        CURLcode *curlcode)
{
    struct SessionHandle *data = conn->data;
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    mitls_connect_context *connmitls = (mitls_connect_context*)connssl->mitls_ctx;
    char *outmsg = NULL;
    char *errmsg = NULL;
    size_t packet_size = 0;
    void *packet;
    
    packet = FFI_mitls_receive(connmitls->mitls_config,
               &packet_size,
               &outmsg, &errmsg);
    Curl_mitls_process_messages(data, outmsg, errmsg);
    if (packet == NULL) {
        *curlcode = CURLE_RECV_ERROR;
        failf(data, "Leaving %s -1 after failed FFI\n", __FUNCTION__);
        return -1;
    }
    infof(data, "Curl_mitls_recv got %d bytes.  Caller asked for %d bytes.\n", (int)packet_size, (int)buffersize);
    if (packet_size > buffersize) {
        packet_size = buffersize;
    }
    memcpy(buf, packet, packet_size);
    FFI_mitls_free_packet(packet);
    *curlcode = CURLE_OK;
    return packet_size;
}


// Initializes and configures miTLS
CURLcode Curl_mitls_connect_step_1(struct connectdata *conn, int sockindex)
{
    struct SessionHandle *data = conn->data;
    curl_socket_t sockfd = conn->sock[sockindex];
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    mitls_connect_context *connmitls = NULL;
    char *ssl_sessionid;
    size_t ssl_sessionid_len;
    char *outmsg = NULL;
    char *errmsg = NULL;
    int result;
    CURLcode ret = CURLE_SSL_CONNECT_ERROR;
    const char *tls_version = NULL;
    
    if (connssl->mitls_ctx) {
        free(connssl->mitls_ctx);
        connssl->mitls_ctx = NULL;
    }
    connmitls = (mitls_connect_context*)malloc(sizeof(mitls_connect_context));
    if (!connmitls) {
        return CURLE_OUT_OF_MEMORY;
    }
    memset(connmitls, 0, sizeof(*connmitls));
    connssl->mitls_ctx = connmitls;
    switch(data->set.ssl.version) {
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
  
    if (data->set.str[STRING_KEY]) {
        infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by miTLS.  "
                    "The private key must be in the Keychain.\n");
    }  
    if (data->set.str[STRING_CERT]) {
        infof(data, "WARNING: SSL: STRING_CERT is ignored by miTLS.\n");
    }
    if (data->set.ssl.verifypeer) {
        infof(data, "WARNING: SSL: verifypeer is ignored by miTLS.\n");
    } 
    if (data->set.str[STRING_SSL_CAFILE]) {
        infof(data, "WARNING: SSL: STRING_SSL_CAFILE is ignored by miTLS.\n");
    }
    if (data->set.ssl.verifyhost) {
        infof(data, "WARNING: SSL: verifyhost is ignored by miTLS.\n");
    }
    
    /* Check if there's a cached ID we can/should use here! */
    Curl_ssl_sessionid_lock(conn);
    if (!Curl_ssl_getsessionid(conn, (void **)&ssl_sessionid, &ssl_sessionid_len)) {
        /* we got a session id, use it! */
        
        // bugbug: use it for something.  SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
        
        Curl_ssl_sessionid_unlock(conn);
        /* Informational message */
        infof(data, "SSL re-using session ID %*s\n", ssl_sessionid_len, ssl_sessionid);
    } else {
        /* If there isn't one, then let's make one up! This has to be done prior
         to starting the handshake. */
        CURLcode result;
        ssl_sessionid =
          aprintf("%s:%d:%d:%s:%hu", data->set.str[STRING_SSL_CAFILE],
                  data->set.ssl.verifypeer, data->set.ssl.verifyhost,
                  conn->host.name, conn->remote_port);
        ssl_sessionid_len = strlen(ssl_sessionid);

        // bugbug: use it for something.  SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);

        result = Curl_ssl_addsessionid(conn, ssl_sessionid, ssl_sessionid_len);
        Curl_ssl_sessionid_unlock(conn);
        if (result) {
            failf(data, "failed to store ssl session\n");
            return result;
        }
    }    
    
    // Create a miTLS-side config object representing the TLS connection settings
    result = FFI_mitls_configure(&connmitls->mitls_config, tls_version, conn->host.name, &outmsg, &errmsg);
    Curl_mitls_process_messages(data, outmsg, errmsg);
    if (result != 0) {
        // Configuration succeeded. Begin connecting
        connssl->connecting_state = ssl_connect_2;
        ret = CURLE_OK;
    }
    return ret;
}

CURLcode Curl_mitls_RecvRecord(struct SessionHandle *data, mitls_connect_context *connmitls, curl_socket_t sockfd, bool blocking)
{
    ssize_t RecvResult;
    ssize_t RecordLength;
    size_t i;
    
    connmitls->record_length = 0;
    
    // Read in the 5-byte record header
    RecvResult = recv(sockfd, connmitls->header, sizeof(connmitls->header), 0);
    if (RecvResult != sizeof(connmitls->header)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return CURLE_AGAIN;
        }
        failf(data, "Header recv failed %p %d", RecvResult, errno);
        return CURLE_RECV_ERROR;
    }
    if (RecvResult != sizeof(connmitls->header)) {
        failf(data, "Header too small\n");
        return CURLE_RECV_ERROR;
    }
    // RecordLength is big-endian in the header.
    RecordLength = (((ushort)(unsigned char)connmitls->header[3] << 8)) + (ushort)(unsigned char)connmitls->header[4];
    if (RecordLength > (ssize_t)sizeof(connmitls->record)) {
        // The record length is much too long
        return CURLE_SSL_CONNECT_ERROR;
    }
    
    if (!blocking) {
        // Set the socket to blocking
        curlx_nonblock(sockfd, FALSE);
    }
    
    // Read in the record data
    RecvResult = recv(sockfd, connmitls->record, RecordLength, 0);
    if (RecvResult != RecordLength) {
        failf(data, "Record recv failed %p %d", RecvResult, errno);
        return CURLE_RECV_ERROR;
    }
    
    if (!blocking) {
        // Reset it back to nonblocking
        curlx_nonblock(sockfd, TRUE);
    }
    connmitls->record_length = RecordLength;
    return CURLE_OK;
}

// This is called by miTLS within FFI_mitls_connect()
int Curl_mitls_send_callback(struct _FFI_mitls_callbacks *callbacks, const void *buffer, size_t buffer_size)
{
    mitls_callback_context *ctx = (mitls_callback_context*)callbacks;
    ssize_t SendResult;
    
    SendResult = send(ctx->conn->sock[ctx->sockindex], buffer, buffer_size, 0);
    if (SendResult != buffer_size) {
        struct SessionHandle *data = ctx->conn->data;
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) {
            infof(data, "Curl_mitls_send_callback():  EAGAIN or EWOULDBLOCK\n");
        } else {
            char msg[128];
            strerror_r(e, msg, sizeof(msg));
            infof(data, "Curl_mitls_send_callback():  Unknown errno %d - %s\n", e, msg);
        }
    }
    
    return (int)SendResult;
}

// This is called by miTLS within FFI_mitls_connect()
int Curl_mitls_recv_callback(struct _FFI_mitls_callbacks *callbacks, void *buffer, size_t buffer_size)
{
    mitls_callback_context *ctx = (mitls_callback_context*)callbacks;
    struct SessionHandle *data = ctx->conn->data;
    ssize_t RecvResult;
    
    if (Curl_timeleft(data, NULL, TRUE) < 0) {
        // no need to continue if time already is up
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
    }
    
    RecvResult = recv(ctx->conn->sock[ctx->sockindex], buffer, buffer_size, 0);
    if (RecvResult != buffer_size) {
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) {
            infof(data, "Curl_mitls_recv_callback():  EAGAIN or EWOULDBLOCK\n");
        } else {
            char msg[128];
            strerror_r(e, msg, sizeof(msg));
            infof(data, "Curl_mitls_recv_callback():  Unknown errno %d - %s\n", e, msg);
        }
    }
    
    return (int)RecvResult;
}


CURLcode Curl_mitls_connect_step_2(struct connectdata *conn, int sockindex, bool blocking)
{
    struct SessionHandle *data = conn->data;
    mitls_connect_context *connmitls = (mitls_connect_context*)conn->ssl[sockindex].mitls_ctx;
    int ret;
    curl_socket_t sockfd = conn->sock[sockindex];
    CURLcode result = CURLE_FAILED_INIT;
    char *outmsg;
    char *errmsg;
    
    connmitls->callback.cb.send = Curl_mitls_send_callback;
    connmitls->callback.cb.recv = Curl_mitls_recv_callback;
    connmitls->callback.conn = conn;
    connmitls->callback.sockindex = sockindex;
    
    if (!blocking) {
        // Set the socket to blocking
        curlx_nonblock(sockfd, FALSE);
    }  
    
    ret = FFI_mitls_connect(&connmitls->callback.cb, connmitls->mitls_config, &outmsg, &errmsg);
    Curl_mitls_process_messages(data, outmsg, errmsg);
    
    if (ret == 0) {
        failf(data, "FFI_mitls_connect failed");
        result = CURLE_FAILED_INIT;
    } else {
        infof(data, "FFI_mitls_connect succeeded.  Connection complete.");
        struct ssl_connect_data *connssl = &conn->ssl[sockindex];
        connssl->connecting_state = ssl_connect_done;
        result = CURLE_OK;
    }
    
    if (!blocking) {
        // Set the socket back to nonblocking
        curlx_nonblock(sockfd, TRUE);
    }  
    
    return result;
}

CURLcode Curl_mitls_connect_common(struct connectdata *conn, int sockindex, bool blocking, bool *done)
{
    CURLcode result;
    struct SessionHandle *data = conn->data;
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    
    // check if the connection has already been established
    if (ssl_connection_complete == connssl->state) {
        *done = TRUE;
        return CURLE_OK;
    }    

    if (Curl_timeleft(data, NULL, TRUE) < 0) {
        // no need to continue if time already is up
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
    }
        
    switch (connssl->connecting_state) {
    case ssl_connect_1:
        result = Curl_mitls_connect_step_1(conn, sockindex);
        return result;
    case ssl_connect_2: 
        result = Curl_mitls_connect_step_2(conn, sockindex, blocking);
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

    failf(data, "Unexpected exit from %s", __FUNCTION__);
    return CURLE_FAILED_INIT;
}

// Called by CURL
CURLcode Curl_mitls_connect(struct connectdata *conn, int sockindex)
{
    bool done = FALSE;
    CURLcode retval;
   
    retval = Curl_mitls_connect_common(conn, sockindex, TRUE, &done);
    return retval;
}

// Called by CURL
CURLcode Curl_mitls_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done)
{
    CURLcode retval;
    
    retval = Curl_mitls_connect_common(conn, sockindex, FALSE, done);
    return retval;
}

void Curl_mitls_close(struct connectdata *conn, int sockindex)
{
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    
    if (connssl->mitls_ctx) {
        mitls_connect_context *connmitls = (mitls_connect_context*)connssl->mitls_ctx;
        
        FFI_mitls_close(connmitls->mitls_config);
        connmitls->mitls_config = NULL;
        free(connssl->mitls_ctx);
        connssl->mitls_ctx = NULL;
    }
}

void Curl_mitls_session_free(void *ptr)
{
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
    return 0; // success
}

void Curl_mitls_sha256sum(const unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *sha256sum /* output */,
                      size_t unused)
{
}

#endif /* USE_MITLS */
