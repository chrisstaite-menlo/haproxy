/*
 * include/haproxy/pkcs11-token.h
 * PKCS#11 asynchronous task management.
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

#ifndef _HAPROXY_PKCS11_NOTIFY_H
#define _HAPROXY_PKCS11_NOTIFY_H

#include <stddef.h>
#include <stdint.h>

struct pkcs11_notify;
struct wait_event;

/* create an empty pkcs11_notify */
struct pkcs11_notify *pkcs11_notify_new(void);

/* ready a notify structure to take a new pending output */
int pkcs11_notify_alloc(struct pkcs11_notify *notify, size_t max_out);

/* get the current buffer for a pending action */
uint8_t *pkcs11_notify_buffer(struct pkcs11_notify *notify);

/* get the size of the buffer for a pending action */
size_t pkcs11_notify_size(struct pkcs11_notify *notify);

/* complete a pending action */
void pkcs11_notify_complete(struct pkcs11_notify *notify, size_t len);

/* read a pending action and clear the notify, returns 0 on failure, -1 on
 * pending and 1 on success
 */
int pkcs11_notify_clear(struct pkcs11_notify *notify,
                        uint8_t *out, size_t *out_len, size_t max_len);

/* wake a tasklet now if the notify is complete, or log the wake up for later
 * if it's still pending
 */
void pkcs11_notify(struct pkcs11_notify *notify, struct wait_event *wait_event);

/* free a pkcs11_notify structure */
void pkcs11_notify_free(struct pkcs11_notify *notify);

#endif /* _HAPROXY_PKCS11_NOTIFY_H */
