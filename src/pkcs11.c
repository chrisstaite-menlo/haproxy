
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>
#include <haproxy/proxy-t.h>
#include <haproxy/pkcs11.h>
#include <haproxy/pkcs11-notify.h>
#include <haproxy/pkcs11-token.h>
#include <haproxy/pkcs11-uri.h>
#include <openssl/asn1.h>

#include <dlfcn.h>
#include <stdio.h>

static struct {
	/* the number of threads that service the synchronous PKCS#11 requests */
	int worker_threads;
	/* the ex_data index for SSL_CTX containing the pkcs11_data */
	int data_index;
	/* the ex_data index for SSL containing the pkcs11_notify */
	int ssl_index;
	/* if configured, the PKCS#11 library to use if not configured in the URI */
	char *default_library_path;
} global_pkcs11 = {
	.worker_threads = 0,
	.data_index = -1,
	.ssl_index = -1,
	.default_library_path = NULL,
};

static int pkcs11_driver(char **args, int section_type, struct proxy *curpx,
						 const struct proxy *defpx, const char *file, int line,
						 char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a library path.", args[0]);
		return -1;
	}
	global_pkcs11.default_library_path = strdup(args[1]);
	return 0;
}

static int pkcs11_threads(char **args, int section_type, struct proxy *curpx,
						  const struct proxy *defpx, const char *file, int line,
						  char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	global_pkcs11.worker_threads = atoi(args[1]);
	if (global_pkcs11.worker_threads < 0) {
		global_pkcs11.worker_threads = 0;
		memprintf(err, "'%s' expects a positive numeric value, got '%s'.",
				  args[0], args[1]);
		return -1;
	}
	return 0;
}

static struct cfg_kw_list pkcs11cfg_kws = {{ }, {
	{ CFG_GLOBAL, "pkcs11-worker-threads", pkcs11_threads },
	{ CFG_GLOBAL, "pkcs11-default-driver", pkcs11_driver },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &pkcs11cfg_kws);

struct pkcs11_data {
	/* a reference to a PKCS#11 private key that can sign and decrypt */
	struct pkcs11_token *token;
	/* contains the values of SSL_SIGN supported by this provider in order of
	 * preference, there are 12 possible values, but not all will be
	 * populated.  The populated indexes shall start at zero.
	 */
	uint16_t prefs[12];
	/* the number of populated values in prefs. */
	int num_prefs;
};

static struct pkcs11_notify *get_notify(SSL *ssl)
{
	struct pkcs11_notify *notify = (struct pkcs11_notify *) SSL_get_ex_data(
		ssl, global_pkcs11.ssl_index);
	if (notify == NULL) {
		notify = pkcs11_notify_new();
		if (notify != NULL && SSL_set_ex_data(ssl, global_pkcs11.ssl_index, notify) <= 0) {
			pkcs11_notify_free(notify);
			notify = NULL;
		}
	}
	return notify;
}

#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
static enum ssl_private_key_result_t pkcs11_sign(
		SSL *ssl,
		uint8_t *out, size_t *out_len,
		size_t max_out,
		uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len)
{
	struct pkcs11_data *key_method = (struct pkcs11_data *) SSL_CTX_get_ex_data(
		SSL_get_SSL_CTX(ssl), global_pkcs11.data_index);
	struct pkcs11_notify *notify = get_notify(ssl);
	enum ssl_private_key_result_t ret = ssl_private_key_failure;

	if (key_method != NULL && notify != NULL &&
			pkcs11_notify_alloc(notify, max_out) &&
			pkcs11_token_sign(key_method->token, notify, signature_algorithm, in, in_len))
		ret = ssl_private_key_retry;
	return ret;
}

static enum ssl_private_key_result_t pkcs11_decrypt(
		SSL *ssl,
		uint8_t *out, size_t *out_len, size_t max_out,
		const uint8_t *in, size_t in_len)
{
	struct pkcs11_data *key_method = (struct pkcs11_data *) SSL_CTX_get_ex_data(
		SSL_get_SSL_CTX(ssl), global_pkcs11.data_index);
	struct pkcs11_notify *notify = get_notify(ssl);
	enum ssl_private_key_result_t ret = ssl_private_key_failure;

	if (key_method != NULL && notify != NULL &&
			pkcs11_notify_alloc(notify, max_out) &&
			pkcs11_token_decrypt(key_method->token, notify, in, in_len))
		ret = ssl_private_key_retry;
	return ret;
}

static enum ssl_private_key_result_t pkcs11_complete(
		SSL *ssl, uint8_t *out,
		size_t *out_len, size_t max_out)
{
	struct pkcs11_notify *notify = get_notify(ssl);
	enum ssl_private_key_result_t ret;

	if (notify == NULL)
		ret = ssl_private_key_failure;
	else {
		switch (pkcs11_notify_clear(notify, out, out_len, max_out)) {
		case -1:
			ret = ssl_private_key_retry;
			break;
		case 1:
			ret = ssl_private_key_success;
			break;
		default:
			ret = ssl_private_key_failure;
			break;
		}
	}
	return ret;
}

static SSL_PRIVATE_KEY_METHOD pkcs11_provider = {
	.sign = pkcs11_sign,
	.decrypt = pkcs11_decrypt,
	.complete = pkcs11_complete,
};
#endif  /* BoringSSL, AWS-LC */

static void ex_pkcs11_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
						   int index, long argl, void *argp)
{
	pkcs11_free((struct pkcs11_data *) ptr);
}

static void ex_notify_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
						   int index, long argl, void *argp)
{
	struct pkcs11_notify *notify = (struct pkcs11_notify *) ptr;

	if (notify)
		pkcs11_notify_free(notify);
}

static int init_data_index(void)
{
	int ret = 0;

	if (global_pkcs11.data_index == -1)
		global_pkcs11.data_index = SSL_CTX_get_ex_new_index(
			0, NULL, NULL, NULL, &ex_pkcs11_free);
	if (global_pkcs11.data_index == -1)
		ha_alert("pkcs11 : unable to register with SSL library: %s.\n",
		         ERR_reason_error_string(ERR_get_error()));
	else
		ret = 1;
	return ret;
}

static int init_pkcs11(void)
{
	int ret = ERR_NONE;

	if (global_pkcs11.worker_threads) {
		ret |= pkcs11_token_init(global_pkcs11.worker_threads);
		if (ret != ERR_NONE)
			goto out;

		if (global_pkcs11.data_index == -1 && !init_data_index()) {
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		global_pkcs11.ssl_index = SSL_get_ex_new_index(
			0, NULL, NULL, NULL, &ex_notify_free);
		if (global_pkcs11.ssl_index == -1) {
			ha_alert("pkcs11 : unable to register with SSL library: %s.\n",
					 ERR_reason_error_string(ERR_get_error()));
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

out:
	return ret;
}

static void deinit_pkcs11(void)
{
	if (global_pkcs11.worker_threads)
		pkcs11_token_deinit();

	global_pkcs11.worker_threads = 0;
	if (global_pkcs11.default_library_path != NULL) {
		free(global_pkcs11.default_library_path);
		global_pkcs11.default_library_path = NULL;
	}
	global_pkcs11.data_index = -1;
}

REGISTER_POST_CHECK(init_pkcs11);
REGISTER_POST_DEINIT(deinit_pkcs11);

typedef struct provider_uri_st {
	ASN1_VISIBLESTRING *description;
	ASN1_UTF8STRING *uri;
} PROVIDER_URI;

ASN1_SEQUENCE(PROVIDER_URI) = {
	ASN1_SIMPLE(PROVIDER_URI, description, ASN1_VISIBLESTRING),
	ASN1_SIMPLE(PROVIDER_URI, uri, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(PROVIDER_URI)

IMPLEMENT_ASN1_FUNCTIONS(PROVIDER_URI)

struct pkcs11_data *pkcs11_parse_pem(BIO *pem, char **err)
{
	char *name = NULL, *header = NULL;
	unsigned char *data = NULL;
	const unsigned char *ptr = NULL;
	long len = 0;
	PROVIDER_URI *parsed_provider = NULL;
	struct pkcs11_data *provider = NULL;
	struct pkcs11_uri *uri = NULL;
	struct pkcs11_token *token = NULL;

	/* it is invalid to load a PKCS#11 token when there's no worker threads */
	if (global_pkcs11.worker_threads == 0)
		goto out;
	if (PEM_read_bio(pem, &name, &header, &data, &len) <= 0)
		goto out;
	if (strcmp(name, "PKCS#11 PROVIDER URI") != 0)
		goto out;
	ptr = data;
	parsed_provider = d2i_PROVIDER_URI(NULL, &ptr, len);
	if (parsed_provider == NULL || ptr != data + len)
		goto out;
	provider = calloc(1, sizeof(struct pkcs11_data));
	if (provider == NULL)
		goto out;
	uri = pkcs11_uri_parse(ASN1_STRING_get0_data(parsed_provider->uri),
	                       ASN1_STRING_length(parsed_provider->uri),
	                       global_pkcs11.default_library_path);
	if (uri == NULL)
		goto err;
	token = pkcs11_token_load(uri, err);
	if (token == NULL)
		goto err;
	if (!pkcs11_token_get_prefs(token, provider->prefs, &provider->num_prefs,
	                            sizeof(provider->prefs) / sizeof(provider->prefs[0]))) {
		memprintf(err, "unable to determine key type");
		goto err;
	}
	provider->token = token;
	token = NULL;

out:
	if (name)
		OPENSSL_free(name);
	if (header)
		OPENSSL_free(header);
	if (data)
		OPENSSL_free(data);
	if (parsed_provider)
		PROVIDER_URI_free(parsed_provider);
	if (uri)
		pkcs11_uri_free(uri);
	if (token)
		pkcs11_token_free(token);
	return provider;
err:
	if (provider) {
		pkcs11_free(provider);
		provider = NULL;
	}
	goto out;
}

int pkcs11_set_private_key(SSL_CTX *ctx, struct pkcs11_data *key_method)
{
#if !defined(OPENSSL_IS_AWSLC) && !defined(OPENSSL_IS_BORINGSSL)
#error PKCS#11 is not implemented for this TLS framework.
	return 0;
#else
	int ret = 0;

	if (!init_data_index())
		goto out;
	ret = SSL_CTX_set_ex_data(
		ctx, global_pkcs11.data_index, pkcs11_dup(key_method));
	if (ret <= 0) {
		ret = 0;
		goto out;
	}
	ret = SSL_CTX_set_signing_algorithm_prefs(
		ctx, key_method->prefs, key_method->num_prefs);
	if (ret <= 0) {
		ret = 0;
		goto out;
	}
	SSL_CTX_set_private_key_method(ctx, &pkcs11_provider);
	ret = 1;

out:
	return ret;
#endif
}

int pkcs11_check_private_key(X509 *cert, struct pkcs11_data *key_method)
{
	const EVP_PKEY *pubkey = X509_get0_pubkey(cert);

	if (pubkey == NULL)
		return 0;

	/* TODO: Implement me. */
	return 1;
}

void pkcs11_schedule_wakeup(SSL *ssl, struct wait_event *wait_event)
{
	struct pkcs11_notify *notify = get_notify(ssl);

	if (notify == NULL)
		tasklet_wakeup(wait_event->tasklet);
	else
		pkcs11_notify(notify, wait_event);
}

struct pkcs11_data *pkcs11_dup(struct pkcs11_data *key_method)
{
	struct pkcs11_data *duplicate = NULL;

	if (key_method)
		duplicate = calloc(1, sizeof(struct pkcs11_data));
	if (duplicate) {
		memcpy(duplicate->prefs, key_method->prefs, sizeof(key_method->prefs));
		duplicate->num_prefs = key_method->num_prefs;
		duplicate->token = pkcs11_token_dup(key_method->token);
		if (duplicate->token == NULL) {
			free(duplicate);
			duplicate = NULL;
		}
	}
	return duplicate;
}

void pkcs11_free(struct pkcs11_data *key_method)
{
	if (key_method) {
		if (key_method->token) {
			pkcs11_token_free(key_method->token);
			key_method->token = NULL;
		}
		free(key_method);
	}
}
