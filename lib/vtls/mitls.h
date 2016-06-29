#ifndef HEADER_CURL_MITLS_H
#define HEADER_CURL_MITLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2010, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
#include "curl_setup.h"

#ifdef USE_MITLS


/* Called on first use miTLS, setup threading if supported */
int  Curl_mitls_init(void);
void Curl_mitls_cleanup(void);

CURLcode Curl_mitls_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_mitls_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

 /* close a SSL connection */
void Curl_mitls_close(struct connectdata *conn, int sockindex);

void Curl_mitls_session_free(void *ptr);
size_t Curl_mitls_version(char *buffer, size_t size);
int Curl_mitls_shutdown(struct connectdata *conn, int sockindex);

void Curl_mitls_sha256sum(const unsigned char *tmp, /* input */
                      size_t tmplen,
                      unsigned char *sha256sum /* output */,
                      size_t unused);


/* Set the API backend definition to miTLS */
#define CURL_SSL_BACKEND CURLSSLBACKEND_MITLS

/* this backend supports the CAPATH option */
//#define have_curlssl_ca_path 1

/* this backends supports CURLOPT_PINNEDPUBLICKEY */
//#define have_curlssl_pinnedpubkey 1

/* API setup for miTLS */
#define curlssl_init() Curl_mitls_init()
#define curlssl_cleanup() Curl_mitls_cleanup()
#define curlssl_connect Curl_mitls_connect
#define curlssl_connect_nonblocking Curl_mitls_connect_nonblocking
#define curlssl_session_free(x)  Curl_mitls_session_free(x)
#define curlssl_close_all(x) ((void)x)
#define curlssl_close Curl_mitls_close
#define curlssl_shutdown(x,y) 0
#define curlssl_set_engine(x,y) ((void)x, (void)y, CURLE_NOT_BUILT_IN)
#define curlssl_set_engine_default(x) ((void)x, CURLE_NOT_BUILT_IN)
#define curlssl_engines_list(x) ((void)x, (struct curl_slist *)NULL)
#define curlssl_version Curl_mitls_version
#define curlssl_check_cxn(x) ((void)x, -1)
#define curlssl_data_pending(x,y) ((void)x, (void)y, 0)
#define curlssl_sha256sum(a,b,c,d) Curl_mitls_sha256sum(a,b,c,0)

/* This might cause libcurl to use a weeker random!
*/
#define curlssl_random(x,y,z) ((void)x, (void)y, (void)z, CURLE_NOT_BUILT_IN)

#endif /* USE_MITLS */
#endif /* HEADER_CURL_mitls_H */
