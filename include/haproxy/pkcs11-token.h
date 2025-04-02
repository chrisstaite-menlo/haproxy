/*
 * include/haproxy/pkcs11-token.h
 * PKCS#11 token communication.
 *
 * Copyright (C) 2025 Chris Staite - christopher.staite@menlosecurity.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_PKCS11_TOKEN_H
#define _HAPROXY_PKCS11_TOKEN_H

#include <stddef.h>
#include <stdint.h>

struct pkcs11_token;
struct pkcs11_notify;
struct pkcs11_uri;

/* initialise the PKCS#11 token communication library with the given number of
 * worker threads to perform synchronous actions on
 */
int pkcs11_token_init(int threads);

/* shutdown the worker threads */
void pkcs11_token_deinit(void);

/* attempt to communicate with a given PKCS#11 URI and obtain a reference to
 * it which can be re-used, returns NULL on failure.  this method is blocking
 */
struct pkcs11_token *pkcs11_token_load(struct pkcs11_uri *uri, char **err);

/* loads the SSL preferences for a given token into the prefs array, this must
 * be able to contain all of the SSL prefs available (i.e. max_prefs).  this
 * method is blocking and uses the session created in pkcs11_token_load and
 * must therefore only be called when there are no other calls to pkcs11_token_*
 * functions on this pkcs11_token.
 */
int pkcs11_token_get_prefs(struct pkcs11_token *token,
                           uint16_t *prefs, int *num_prefs, int max_prefs);

/* start an asynchronous signing action and complete this with a pkcs11_notify */
int pkcs11_token_sign(struct pkcs11_token *token, struct pkcs11_notify *notify,
                      int signature_algorithm, const uint8_t *in, size_t in_len);

/* start an asynchronous decryption action and complete this with a pkcs11_notify */
int pkcs11_token_decrypt(struct pkcs11_token *token, struct pkcs11_notify *notify,
                         const uint8_t *in, size_t in_len);

/* release a reference on a given token */
void pkcs11_token_free(struct pkcs11_token *token);

/* obtain another reference to a given token */
struct pkcs11_token *pkcs11_token_dup(struct pkcs11_token *token);

#endif /* _HAPROXY_PKCS11_TOKEN_H */
