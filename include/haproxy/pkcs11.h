/*
 * include/haproxy/pkcs11.h
 * PKCS11 module forwarding.
 *
 * Copyright (C) 2025 Menlo Security, Inc. - christopher.staite@menlosecurity.com
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

#ifndef _HAPROXY_PKCS11_H
#define _HAPROXY_PKCS11_H
#ifdef USE_OPENSSL

/* the information required to add a private key to an SSL_CTX, defined even
 * without support to allow a NULL ptr
 */
struct pkcs11_data;

#ifdef USE_PKCS11

#include <haproxy/openssl-compat.h>
#include <haproxy/task-t.h>

/* attempt to parse a BIO as a PEM which contains a PKCS#11 PROVIDER URI and
 * then return an pkcs11_data which points to the given provider.
 * If there is no valid PKCS#11 provider in the BIO, or any error occurs then
 * NULL is returned.
 */
struct pkcs11_data *pkcs11_parse_pem(BIO *pem, char **err);

/* set up PKCS11 on the SSL_CTX, the key_method must not be NULL */
int pkcs11_set_private_key(SSL_CTX *ctx, struct pkcs11_data *key_method);

/* check that a PKCS11 key matches a given certificate */
int pkcs11_check_private_key(X509 *cert, struct pkcs11_data *key_method);

/* schedule a wake up of the tasklet when the current PKCS#11 operation is
 * complete for the given SSL connection.
 */
void pkcs11_schedule_wakeup(SSL *ssl, struct wait_event *wait_event);

/* duplicate an pkcs11_data provided by parse_pkcs11_pem, this may
 * be through reference counting or memory allocation.
 */
struct pkcs11_data *pkcs11_dup(struct pkcs11_data *key_method);

/* free an pkcs11_data provided by parse_pkcs11_pem, this may simply
 * be decrementing a reference count.
 */
void pkcs11_free(struct pkcs11_data *key_method);

#endif   /* USE_PKCS11 */
#endif  /* USE_OPENSSL */
#endif  /* _HAPROXY_PKCS11_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
