/*
 * include/haproxy/pkcs11-uri-t.h
 * PKCS#11 parts parsed from a URI used to find a private signing key.
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

#ifndef _HAPROXY_PKCS11_URI_T_H
#define _HAPROXY_PKCS11_URI_T_H

struct pkcs11_uri {
    /* the PKCS#11 library to load */
    char *module;
    /* the source of a PIN, likely a file path */
    char *pin_source;
    /* the length of pin_source */
    int pin_source_len;
    /* the value of a PIN */
    char *pin_value;
    /* the length of pin_value */
    int pin_value_len;
    /* the slot ID for the token */
    char *slot_id;
    /* the length of slot_id */
    int slot_id_len;
    /* the slot manufacturer */
    char *slot_manufacturer;
    /* the length of slot_manufacturer */
    int slot_manufacturer_len;
    /* the slot description */
    char *slot_description;
    /* the length of slot_description */
    int slot_description_len;
    /* the token name */
    char *token;
    /* the length of token */
    int token_len;
    /* the token manufacturer */
    char *manufacturer;
    /* the length of manufacturer */
    int manufacturer_len;
    /* the token model */
    char *model;
    /* the length of model */
    int model_len;
    /* the serial of the token */
    char *serial;
    /* the length of serial */
    int serial_len;
    /* the id of the token */
    char *id;
    /* the length of id */
    int id_len;
    /* the object of the token */
    char *object;
    /* the length of object */
    int object_len;
};

#endif /* _HAPROXY_PKCS11_URI_T_H */
