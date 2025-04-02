
#include <haproxy/pkcs11-uri.h>
#include <haproxy/pkcs11-uri-t.h>
#include <haproxy/tools.h>

#include <stdlib.h>
#include <string.h>

static const char URI[] = "pkcs11:";

/* search for the next instance of a single character c in a UTF-8 string, if
 * not found before the end returns end, if found returns the pointer after
 * the needle, returns NULL if an invalid UTF-8 character is encountered.
 */
static const char *next_char(const char *ptr, const char *end, char needle)
{
	unsigned int ret, c;

	while (ptr < end) {
		ret = utf8_next(ptr, (end - ptr), &c);
		ptr += utf8_return_length(ret);
		if (utf8_return_code(ret) != UTF8_CODE_OK) {
			ptr = NULL;
			break;
		}
		if (c == needle)
			break;
	}
	return ptr;
}

/* similar to strdup but for a known length UTF-8 string and also handles
 * removal of percent encoding.
 */
static char *copy_utf8(const char *start, const char *end, int *len)
{
	const char *ptr_in = start;
	char *copy, *ptr_out;
	unsigned int ret, c;
	unsigned char char_len;

	ptr_out = copy = calloc(end - start, sizeof(char));
	if (copy == NULL)
		goto out;

	while (ptr_in < end) {
		ret = utf8_next(ptr_in, (end - ptr_in), &c);
		char_len = utf8_return_length(ret);
		if (utf8_return_code(ret) != UTF8_CODE_OK)
			goto err;
		if (c == '%') {
			/* decode the percent encoding. */
			ptr_in += char_len;
			if ((end - ptr_in) < 2 || !ishex(ptr_in[0]) || !ishex(ptr_in[1]))
				goto err;
			*ptr_out = hex2i(*ptr_in++) << 4;
			*ptr_out++ |= hex2i(*ptr_in++);
		} else if (c == '+') {
			/* plus to space */
			ptr_in += char_len;
			*ptr_out++ = ' ';
		} else {
			/* copy a single UTF-8 character over */
			memcpy(ptr_out, ptr_in, char_len);
			ptr_out += char_len;
			ptr_in += char_len;
		}
	}
	goto out;

err:
	free(copy);
	copy = NULL;
	ptr_out = NULL;

out:
	*len = (ptr_out - copy);
	return copy;
}

/* parse the query part of a token */
static int parse_query(struct pkcs11_uri *uri, const char *ptr, const char *end)
{
	static const char MODULE[] = "module-path";
	static const char PIN_SOURCE[] = "pin-source";
	static const char PIN_VALUE[] = "pin-value";
	int ret = 1;
	const char *name_end, *value_end, *next;

	while (ptr < end) {
		name_end = next_char(ptr, end, '=');
		if (name_end == NULL)
			break;
		value_end = next_char(ptr, end, '&');
		if (value_end == NULL)
			break;
		next = value_end;
		if (value_end != name_end && *(value_end - 1) == '&')
			--value_end;
		if (name_end - ptr == sizeof(MODULE) &&
				memcmp(ptr, MODULE, sizeof(MODULE) - 1) == 0) {
			uri->module = copy_utf8(name_end, value_end, &uri->model_len);
			if (uri->module == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(PIN_SOURCE) &&
				memcmp(ptr, PIN_SOURCE, sizeof(PIN_SOURCE) - 1) == 0) {
			uri->pin_source = copy_utf8(name_end, value_end, &uri->pin_source_len);
			if (uri->pin_source == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(PIN_VALUE) &&
				memcmp(ptr, PIN_VALUE, sizeof(PIN_VALUE) - 1) == 0) {
			uri->pin_value = copy_utf8(name_end, value_end, &uri->pin_value_len);
			if (uri->pin_value == NULL) {
				ret = 0;
				break;
			}
		}
		ptr = next;
	}
	return ret;
}

/* parse the main path of the token, the end may have a ?, careful to strip it */
static int parse_path(struct pkcs11_uri *uri, const char *ptr, const char *end)
{
	static const char TYPE[] = "type";
	static const char PRIVATE[] = "private";
	static const char SLOT_ID[] = "slot-id";
	static const char TOKEN[] = "token";
	static const char SERIAL[] = "serial";
	static const char MANUFACTURER[] = "manufacturer";
	static const char MODEL[] = "model";
	static const char SLOT_MANUFACTURER[] = "slot-manufacturer";
	static const char SLOT_DESCRIPTION[] = "slot-description";
	static const char OBJECT[] = "object";
	static const char ID[] = "id";
	int ret = 0;
	const char *name_end, *value_end, *next;

	while (ptr < end) {
		name_end = next_char(ptr, end, '=');
		if (name_end == NULL)
			break;
		value_end = next_char(ptr, end, ';');
		if (value_end == NULL)
			break;
		next = value_end;
		if (value_end != name_end && *(value_end - 1) == ';')
			--value_end;
		if (name_end - ptr == sizeof(TYPE) &&
				memcmp(ptr, TYPE, sizeof(TYPE) - 1) == 0) {
			if (value_end - name_end == sizeof(PRIVATE) - 1 &&
					memcmp(name_end, PRIVATE, sizeof(PRIVATE) - 1) == 0) {
				/* the only valid PKCS#11 tokens are those with type=private */
				ret = 1;
			}
		} else if (name_end - ptr == sizeof(SLOT_ID) &&
				memcmp(ptr, SLOT_ID, sizeof(SLOT_ID) - 1) == 0) {
			uri->slot_id = copy_utf8(name_end, value_end, &uri->slot_id_len);
			if (uri->slot_id == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(TOKEN) &&
				memcmp(ptr, TOKEN, sizeof(TOKEN) - 1) == 0) {
			uri->token = copy_utf8(name_end, value_end, &uri->token_len);
			if (uri->token == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(SERIAL) &&
				memcmp(ptr, SERIAL, sizeof(SERIAL) - 1) == 0) {
			uri->serial = copy_utf8(name_end, value_end, &uri->serial_len);
			if (uri->serial == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(MANUFACTURER) &&
				memcmp(ptr, MANUFACTURER, sizeof(MANUFACTURER) - 1) == 0) {
			uri->manufacturer = copy_utf8(name_end, value_end, &uri->manufacturer_len);
			if (uri->manufacturer == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(MODEL) &&
				memcmp(ptr, MODEL, sizeof(MODEL) - 1) == 0) {
			uri->model = copy_utf8(name_end, value_end, &uri->model_len);
			if (uri->model == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(SLOT_MANUFACTURER) &&
				memcmp(ptr, SLOT_MANUFACTURER, sizeof(SLOT_MANUFACTURER) - 1) == 0) {
			uri->slot_manufacturer = copy_utf8(name_end, value_end, &uri->slot_manufacturer_len);
			if (uri->slot_manufacturer == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(SLOT_DESCRIPTION) &&
				memcmp(ptr, SLOT_DESCRIPTION, sizeof(SLOT_DESCRIPTION) - 1) == 0) {
			uri->slot_description = copy_utf8(name_end, value_end, &uri->slot_description_len);
			if (uri->slot_description == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(OBJECT) &&
				memcmp(ptr, OBJECT, sizeof(OBJECT) - 1) == 0) {
			uri->object = copy_utf8(name_end, value_end, &uri->object_len);
			if (uri->object == NULL) {
				ret = 0;
				break;
			}
		} else if (name_end - ptr == sizeof(ID) &&
				memcmp(ptr, ID, sizeof(ID) - 1) == 0) {
			uri->id = copy_utf8(name_end, value_end, &uri->id_len);
			if (uri->id == NULL) {
				ret = 0;
				break;
			}
		}
		ptr = next;
	}
	return ret;
}

struct pkcs11_uri *pkcs11_uri_parse(const unsigned char *utf8_uri, int len,
                                    const char *default_module)
{
	const char *ptr = (const char *) utf8_uri;
	const char *end = ptr + len;
	const char *query_start;
	struct pkcs11_uri *uri = NULL;

	/* the URI must start with pkcs11: */
	if (len < sizeof(URI) - 1 || memcmp(utf8_uri, URI, sizeof(URI) - 1) != 0)
		goto out;
	ptr += sizeof(URI) - 1;
	uri = calloc(1, sizeof(struct pkcs11_uri));
	if (uri == NULL)
		goto out;
	query_start = next_char(ptr, end, '?');
	if (query_start == NULL) {
		free(uri);
		uri = NULL;
		goto out;
	}
	if (query_start != end && parse_query(uri, query_start, end) == 0) {
		pkcs11_uri_free(uri);
		uri = NULL;
		goto out;
	}
	if (parse_path(uri, ptr, query_start) == 0) {
		pkcs11_uri_free(uri);
		uri = NULL;
		goto out;
	}
	if (uri->module == NULL && default_module != NULL)
		uri->module = strdup(default_module);

out:
	return uri;
}

void pkcs11_uri_free(struct pkcs11_uri *uri)
{
	if (uri->module)
		free(uri->module);
	if (uri->pin_source)
		free(uri->pin_source);
	if (uri->pin_value)
		free(uri->pin_value);
	if (uri->slot_id)
		free(uri->slot_id);
	if (uri->slot_manufacturer)
		free(uri->slot_manufacturer);
	if (uri->slot_description)
		free(uri->slot_description);
	if (uri->token)
		free(uri->token);
	if (uri->manufacturer)
		free(uri->manufacturer);
	if (uri->model)
		free(uri->model);
	if (uri->serial)
		free(uri->serial);
	if (uri->id)
		free(uri->id);
	if (uri->object)
		free(uri->object);
	free(uri);
}
