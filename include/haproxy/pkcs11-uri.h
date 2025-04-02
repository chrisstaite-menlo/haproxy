/*
 * include/haproxy/pkcs11-uri.h
 * PKCS#11 URI parsing per RFC7512.
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

#ifndef _HAPROXY_PKCS11_URI_H
#define _HAPROXY_PKCS11_URI_H

#include <stddef.h>

struct pkcs11_uri;

/* parse a UTF-8 string into a struct pkcs11_uri, returns NULL on failure */
struct pkcs11_uri *pkcs11_uri_parse(const unsigned char *utf8_uri, int len,
                                    const char *default_module);

/* free a pkcs11_uri structure */
void pkcs11_uri_free(struct pkcs11_uri *uri);

#endif /* _HAPROXY_PKCS11_URI_H */
