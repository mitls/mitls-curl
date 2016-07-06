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
//  1:  ssl_connect_2           - TLS 1.2 implementation
//  2:  ssl_connect_2_reading   - unused
//  3:  ssl_connect_2_writing   - unused
//  4:  ssl_connect_3           - TLS 1.3 implementation
//  5:  ssl_connect_done        - set when the entire connection state machine has finished successfully

typedef enum {
    mitls_ClientHello,          // Send ClientHello
    mitls_ServerHello,          // Receive and process ServerHello
    mitls_CertificateVerify,    // Receive and process CertificateVerify
    mitls_ServerKeyExchange,    // Recieve and process ServerKeyExchange
    mitls_ServerHelloDone,      // Recieve and process ServerHelloDone
    mitls_PrepareClientKeyExchange, // Send ClientKeyExchange
    mitls_PrepareChangeCipherSpec, // Send Change_cipher_spec
    mitls_PrepareHandshake,     // Send Handshake
    mitls_RecieveChangeCipherSpec, // Receive Change Cipher Spec (CCC)
    mitls_RecieveServerFinished, // Receive and process Finished
    mitls_ClientFinished,        // Send Client Finished (TLS 1.3 only)
    mitls_CompletedState,        // Completed all steps
    mitls_ErrorState
} mitls_connect_state;

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
    mitls_connect_state state;
    const char *tls_version;
    size_t mitls_config;        // gc handle to a mitls TLSInfo.config object
    
    // TLS 1.2 fields
    ssize_t record_length;      // actual # of bytes in record[]
    char header[5];             // 5-byte header for TLS records
    char record[65536];         // the remainder of the TLS record (max of max_TLSCiphertext_fragment_length during TLS negotiation, but longer for recv() later
    
    // TLS 1.3 fields
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
CURLcode Curl_mitls_connect_step1(struct connectdata *conn, int sockindex);
CURLcode Curl_mitls_RecvRecord(struct SessionHandle *data, mitls_connect_context *connmitls, curl_socket_t sockfd, bool blocking);
CURLcode Curl_mitls_connect_step_12(struct connectdata *conn, int sockindex, bool blocking);
CURLcode Curl_mitls_connect_step_13(struct connectdata *conn, int sockindex, bool blocking);

typedef int (*FFI_mitls_recieve_step_function)(/* in out */ size_t *state, char* header, size_t header_size, char *record, size_t record_size);
CURLcode Curl_mitls_execute_recieve_step(struct connectdata *conn, int sockindex, bool blocking, FFI_mitls_recieve_step_function, mitls_connect_state next);

typedef void* (*FFI_mitls_prepare_step_function)(/* in out */ size_t *config, /* out */ size_t *packet_size);
CURLcode Curl_mitls_execute_send_step(struct connectdata *conn, int sockindex, bool blocking, FFI_mitls_prepare_step_function, mitls_connect_state next);

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
    void *packet;
    size_t packet_size;
    ssize_t SendResult;
      
    if (connmitls->tls_version == mitls_TLS_V12) {
        packet = FFI_mitls_prepare_send(&connmitls->mitls_config, mem, len, &packet_size); 
    } else {
        packet = FFI_mitls_prepare_send13(&connmitls->mitls_config, mem, len, &packet_size); 
    }
    if (packet == NULL) {
        failf(data, "Failed FFI_mitls_prepare_send\n");
        *curlcode = CURLE_SEND_ERROR;
        return (ssize_t)-1; 
    }
    SendResult = send(conn->sock[sockindex], packet, packet_size, 0);
    FFI_mitls_free_packet(packet);
    if (SendResult != (ssize_t)packet_size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            failf(data, "send() failed with EAGAIN or WOULDBLOCK.  Try again\n");
            *curlcode = CURLE_AGAIN;
            return 0;
        }
        failf(data, "send() failed with errno=%d\n", errno);
        *curlcode = CURLE_SEND_ERROR;
        return -1;
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
    CURLcode code;
    
    code = Curl_mitls_RecvRecord(data, connmitls, conn->sock[sockindex], FALSE);
    if (code == CURLE_OK) {
        void *packet;
        size_t packet_size;
        
        if (connmitls->tls_version == mitls_TLS_V12) {
            packet = FFI_mitls_handle_receive(&connmitls->mitls_config,
                       connmitls->header, sizeof(connmitls->header), 
                       connmitls->record, connmitls->record_length,
                       &packet_size);
        } else {
            packet = FFI_mitls_handle_receive13(&connmitls->mitls_config,
                       connmitls->header, sizeof(connmitls->header), 
                       connmitls->record, connmitls->record_length,
                       &packet_size);
        }
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
    } else {
        *curlcode = code;
        failf(data, "Leaving %s -1 code=%d\n", __FUNCTION__, code);
        return -1;
    }
}


// Initializes and configures miTLS
CURLcode Curl_mitls_connect_step1(struct connectdata *conn, int sockindex)
{
    struct SessionHandle *data = conn->data;
    curl_socket_t sockfd = conn->sock[sockindex];
    struct ssl_connect_data *connssl = &conn->ssl[sockindex];
    mitls_connect_context *connmitls = NULL;
    char *ssl_sessionid;
    size_t ssl_sessionid_len;
    
    if (connssl->mitls_ctx) {
        free(connssl->mitls_ctx);
        connssl->mitls_ctx = NULL;
    }
    connmitls = (mitls_connect_context*)malloc(sizeof(mitls_connect_context));
    if (!connmitls) {
        return CURLE_OUT_OF_MEMORY;
    }
    memset(connmitls, 0, sizeof(*connmitls));
    connmitls->state = mitls_ClientHello;
    connssl->mitls_ctx = connmitls;
    switch(data->set.ssl.version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1_2:
        connmitls->tls_version = mitls_TLS_V12;
        break;
    case CURL_SSLVERSION_TLSv1_3:
        connmitls->tls_version = mitls_TLS_V13;
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
    FFI_mitls_config(&connmitls->mitls_config, connmitls->tls_version, conn->host.name);
    
    connssl->connecting_state = (connmitls->tls_version == mitls_TLS_V13) ? ssl_connect_3 : ssl_connect_2;
    return CURLE_OK;    
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

CURLcode Curl_mitls_execute_recieve_step(struct connectdata *conn, int sockindex, bool blocking, FFI_mitls_recieve_step_function fn, mitls_connect_state next)
{
    struct SessionHandle *data = conn->data;
    mitls_connect_context *connmitls = (mitls_connect_context*)conn->ssl[sockindex].mitls_ctx;
    CURLcode code;
    
    // Receive a full TLS record from the server
    code = Curl_mitls_RecvRecord(data, connmitls, conn->sock[sockindex], blocking);
    if (code == CURLE_AGAIN) {
        // Return CURLE_OK... CURLE_AGAIN is considered an error
        // and aborts the connection attempt.  The state machine
        // in mitls.c supports retrying mitls_ServerHello from this
        // point.
        return CURLE_OK;
    } else if (code != CURLE_OK) {
        return code;
    }
    
    if (!(*fn)(&connmitls->mitls_config, 
               connmitls->header, sizeof(connmitls->header), 
               connmitls->record, connmitls->record_length)) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    
    connmitls->state = next;
    return CURLE_OK;
    
}

CURLcode Curl_mitls_execute_send_step(struct connectdata *conn, int sockindex, bool blocking, FFI_mitls_prepare_step_function fn, mitls_connect_state next)
{
    mitls_connect_context *connmitls = (mitls_connect_context*)conn->ssl[sockindex].mitls_ctx;
    ssize_t SendResult;
    int i;
    // bugbug: for size, pre-allocate a packet buffer on the stack or in mitls_connect_context, large enough to hold this message
    //         or change the API to return a pinned pointer into the OCaml GC heap, with FFI_mitls_free_packet unpinning it, for
    //         a zero-copy implementation.
    size_t packet_size;
    void* packet = (*fn)(&connmitls->mitls_config, &packet_size);
    if (!packet) {
        return CURLE_SSL_CONNECT_ERROR;
    }
    
    SendResult = send(conn->sock[sockindex], packet, packet_size, 0);
    FFI_mitls_free_packet(packet);
    if (SendResult != (ssize_t)packet_size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return CURLE_AGAIN;
        }
        return CURLE_SEND_ERROR;
    }
    
    connmitls->state = next;
    return CURLE_OK;
}

// Core of TLS 1.2
CURLcode Curl_mitls_connect_step_12(struct connectdata *conn, int sockindex, bool blocking)
{
    struct SessionHandle *data = conn->data;
    mitls_connect_context *connmitls = (mitls_connect_context*)conn->ssl[sockindex].mitls_ctx;
    
    switch (connmitls->state) {
    case mitls_ClientHello:
        return Curl_mitls_execute_send_step(conn, sockindex, blocking, FFI_mitls_prepare_client_hello, mitls_ServerHello);
    case mitls_ServerHello:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_server_hello, mitls_CertificateVerify);
    case mitls_CertificateVerify:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_certificate_verify12, mitls_ServerKeyExchange);
    case mitls_ServerKeyExchange:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_server_key_exchange, mitls_ServerHelloDone);
    case mitls_ServerHelloDone:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_server_hello_done, mitls_PrepareClientKeyExchange);
   case mitls_PrepareClientKeyExchange:
        return Curl_mitls_execute_send_step(conn, sockindex, blocking, FFI_mitls_prepare_client_key_exchange, mitls_PrepareChangeCipherSpec);
   case mitls_PrepareChangeCipherSpec:
        return Curl_mitls_execute_send_step(conn, sockindex, blocking, FFI_mitls_prepare_change_cipher_spec, mitls_PrepareHandshake);
   case mitls_PrepareHandshake:
        return Curl_mitls_execute_send_step(conn, sockindex, blocking, FFI_mitls_prepare_handshake, mitls_RecieveChangeCipherSpec);
   case mitls_RecieveChangeCipherSpec:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_change_cipher_spec, mitls_RecieveServerFinished);
   case mitls_RecieveServerFinished:
        return Curl_mitls_execute_recieve_step(conn, sockindex, blocking, FFI_mitls_handle_server_finished, mitls_CompletedState);
   case mitls_CompletedState:
   {
        struct ssl_connect_data *connssl = &conn->ssl[sockindex];
        connssl->connecting_state = ssl_connect_done;
        return CURLE_OK;
   }
   default:
        failf(data, "Invalid mitls_connect_state %d");
        return CURLE_FAILED_INIT;
    }
   
    failf(data, "Unexpected exit from %s", __FUNCTION__);
    return CURLE_FAILED_INIT;
}

// This is called by miTLS within FFI_mitls_connect13()
int Curl_mitls_send_callback13(struct _FFI_mitls_callbacks *callbacks, const void *buffer, size_t buffer_size)
{
    mitls_callback_context *ctx = (mitls_callback_context*)callbacks;
    ssize_t SendResult;
    
    SendResult = send(ctx->conn->sock[ctx->sockindex], buffer, buffer_size, 0);
    if (SendResult != buffer_size) {
        struct SessionHandle *data = ctx->conn->data;
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) {
            infof(data, "Curl_mitls_send_callback13():  EAGAIN or EWOULDBLOCK\n");
        } else {
            char msg[128];
            strerror_r(e, msg, sizeof(msg));
            infof(data, "Curl_mitls_send_callback13():  Unknown errno %d - %s\n", e, msg);
        }
    }
    
    return (int)SendResult;
}

// This is called by miTLS within FFI_mitls_connect13()
int Curl_mitls_recv_callback13(struct _FFI_mitls_callbacks *callbacks, void *buffer, size_t buffer_size)
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
            infof(data, "Curl_mitls_recv_callback13():  EAGAIN or EWOULDBLOCK\n");
        } else {
            char msg[128];
            strerror_r(e, msg, sizeof(msg));
            infof(data, "Curl_mitls_recv_callback13():  Unknown errno %d - %s\n", e, msg);
        }
    }
    
    return (int)RecvResult;
}


// Core of TLS 1.3
CURLcode Curl_mitls_connect_step_13(struct connectdata *conn, int sockindex, bool blocking)
{
    struct SessionHandle *data = conn->data;
    mitls_connect_context *connmitls = (mitls_connect_context*)conn->ssl[sockindex].mitls_ctx;
    int ret;
    curl_socket_t sockfd = conn->sock[sockindex];
    CURLcode result = CURLE_FAILED_INIT;
    
    connmitls->callback.cb.send = Curl_mitls_send_callback13;
    connmitls->callback.cb.recv = Curl_mitls_recv_callback13;
    connmitls->callback.conn = conn;
    connmitls->callback.sockindex = sockindex;
    
    if (!blocking) {
        // Set the socket to blocking
        curlx_nonblock(sockfd, FALSE);
    }  
    
    ret = FFI_mitls_connect13(&connmitls->callback.cb, &connmitls->mitls_config);
    if (ret == 0) {
        failf(data, "FFI_mitls_connect13 failed");
        result = CURLE_FAILED_INIT;
    } else {
        infof(data, "FFI_mitls_connect13 succeeded.  Connection complete.");
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
        result = Curl_mitls_connect_step1(conn, sockindex);
        return result;
    case ssl_connect_2: // for TLS 1.2
        result = Curl_mitls_connect_step_12(conn, sockindex, blocking);
        return result;
    case ssl_connect_3: // for TLS 1.3
        result = Curl_mitls_connect_step_13(conn, sockindex, blocking);
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
        
        FFI_mitls_release_value(&connmitls->mitls_config);
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
