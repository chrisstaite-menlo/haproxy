/*
 * include/haproxy/pkcs11-t.h
 * PKCS#11 internal structures for token management.
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

#ifndef _HAPROXY_PKCS11_TOKEN_T_H
#define _HAPROXY_PKCS11_TOKEN_T_H

#include <haproxy/list.h>
#include <haproxy/pkcs11-spec.h>

struct pkcs11_module {
	/* the list of modules */
	struct mt_list list;
	/* the reference count of this module in pkcs11_token */
	int ref_count;
	/* the path to this module */
	char *module_path;
	/* the loaded module through dlopen */
	void *module;
	/* the module functions */
	CK_FUNCTION_LIST_PTR functions;
};

struct pkcs11_session {
	/* the list that this session belongs to */
	struct mt_list list;
	/* the session for this token */
	CK_SESSION_HANDLE session;
	/* the handle for the key */
	CK_OBJECT_HANDLE key;
};

struct pkcs11_token {
	/* the reference count for this token */
	int ref_count;
	/* the module that this token is loaded through */
	struct pkcs11_module *module;
	/* the slot ID of this token */
	CK_SLOT_ID slot_id;
	/* a list of sessions that are unused */
	struct mt_list sessions;
	/* the id of the token */
	char *id;
	/* the length of id */
	int id_len;
	/* the object of the token */
	char *object;
	/* the length of object */
	int object_len;
};

enum job_type {
	job_type_sign,
	job_type_decrypt,
};

struct pkcs11_job {
	/* the list of jobs */
	struct list list;
	/* the type of job this is */
	enum job_type type;
	/* the SSL_SIGN_* algorithm for sign jobs */
	int signature_algorithm;
	/* the notify for completion of the job */
	struct pkcs11_notify *notify;
	/* the token to perform the operation on */
	struct pkcs11_token *token;
	/* the length of in */
	int in_len;
	/* the input data for the job */
	uint8_t in[];
};

#endif  /* _HAPROXY_PKCS11_TOKEN_T_H */
