
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/pkcs11-notify.h>
#include <haproxy/pkcs11-spec.h>
#include <haproxy/pkcs11-token.h>
#include <haproxy/pkcs11-token-t.h>
#include <haproxy/pkcs11-uri-t.h>
#include <haproxy/tools.h>
#include <openssl/ssl.h>

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static struct {
	/* the number of running worker threads */
	int thread_count;
	/* the handles to the worker threads */
	pthread_t *thread_handles;
	/* the job queue which is processed by the worker threads */
	struct list queue;
	/* a mutex for the queue, we don't use mt_list because the queue is often
	 * empty and we don't want to spin on NULL checks
	 */
	pthread_mutex_t mutex;
	/* a condition variable to wake the threads when the queue is not empty */
	pthread_cond_t condition;
	/* a list of loaded pkcs11_modules */
	struct mt_list modules;
} global_pkcs11_token = {
	.thread_count = 0,
	.thread_handles = NULL,
	.queue = LIST_HEAD_INIT(global_pkcs11_token.queue),
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
	.modules = MT_LIST_HEAD_INIT(global_pkcs11_token.modules),
};

static int find_key(struct pkcs11_module *module,
                    CK_SESSION_HANDLE session,
                    char *id, int id_len,
                    char *object, int object_len,
                    CK_OBJECT_HANDLE *key)
{
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE attributes[3] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
	};
	CK_ULONG attribute_count = 1;
	CK_ULONG found_keys = 0;

	if (id) {
		attributes[attribute_count].type = CKA_ID;
		attributes[attribute_count].pValue = id;
		attributes[attribute_count].ulValueLen = id_len;
		++attribute_count;
	}
	if (object) {
		attributes[attribute_count].type = CKA_LABEL;
		attributes[attribute_count].pValue = object;
		attributes[attribute_count].ulValueLen = object_len;
		++attribute_count;
	}
	if (module->functions->C_FindObjectsInit(session, attributes, attribute_count) != CKR_OK)
		goto out;
	if (module->functions->C_FindObjects(session, key, 1, &found_keys) != CKR_OK)
		found_keys = 0;
	(void) module->functions->C_FindObjectsFinal(session);
out:
	return found_keys;
}

static struct pkcs11_session *get_session(struct pkcs11_token *token)
{
	struct pkcs11_session *p11_session;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;

	p11_session = MT_LIST_POP(&token->sessions, struct pkcs11_session*, list);
	if (p11_session != NULL)
		goto out;
	/* try to create a new session */
	if (token->module->functions->C_OpenSession(token->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &session) != CKR_OK)
		goto out;
	if (!find_key(token->module, session, token->id, token->id_len, token->object, token->object_len, &key))
		goto out;
	p11_session = calloc(1, sizeof(struct pkcs11_session));
	if (p11_session == NULL)
		goto out;
	p11_session->session = session;
	session = CK_INVALID_HANDLE;
	p11_session->key = key;

out:
	if (session != CK_INVALID_HANDLE)
		token->module->functions->C_CloseSession(session);
	/* ensure that the session is configured to be added back */
	if (p11_session)
		MT_LIST_INIT(&p11_session->list);
	return p11_session;
}

static void release_session(struct pkcs11_token *token, struct pkcs11_session *session)
{
	MT_LIST_APPEND(&token->sessions, &session->list);
}

static int get_mechanism(int signature_algorithm, CK_MECHANISM_TYPE *mechanism)
{
	int ret = 1;

	switch (signature_algorithm) {
	case SSL_SIGN_RSA_PKCS1_SHA1:
		*mechanism = CKM_SHA1_RSA_PKCS;
		break;
	case SSL_SIGN_RSA_PKCS1_SHA256:
		*mechanism = CKM_SHA256_RSA_PKCS;
		break;
	case SSL_SIGN_RSA_PKCS1_SHA384:
		*mechanism = CKM_SHA384_RSA_PKCS;
		break;
	case SSL_SIGN_RSA_PKCS1_SHA512:
		*mechanism = CKM_SHA512_RSA_PKCS;
		break;
	case SSL_SIGN_ECDSA_SHA1:
		*mechanism = CKM_ECDSA_SHA1;
		break;
	case SSL_SIGN_ECDSA_SECP256R1_SHA256:
		*mechanism = CKM_ECDSA_SHA256;
		break;
	case SSL_SIGN_ECDSA_SECP384R1_SHA384:
		*mechanism = CKM_ECDSA_SHA384;
		break;
	case SSL_SIGN_ECDSA_SECP521R1_SHA512:
		*mechanism = CKM_ECDSA_SHA512;
		break;
	case SSL_SIGN_RSA_PSS_RSAE_SHA256:
		*mechanism = CKM_SHA256_RSA_PKCS_PSS;
		break;
	case SSL_SIGN_RSA_PSS_RSAE_SHA384:
		*mechanism = CKM_SHA384_RSA_PKCS_PSS;
		break;
	case SSL_SIGN_RSA_PSS_RSAE_SHA512:
		*mechanism = CKM_SHA512_RSA_PKCS_PSS;
		break;
	case SSL_SIGN_ED25519:
		*mechanism = CKM_EDDSA;
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}

static int execute_sign(CK_FUNCTION_LIST_PTR functions,
						CK_SESSION_HANDLE session,
						CK_OBJECT_HANDLE key,
						CK_MECHANISM_TYPE mechanism_type,
						uint8_t *in, int in_len,
						uint8_t *out, int max_out)
{
	CK_ULONG out_len = 0;
	CK_MECHANISM mechanism = {
		.mechanism = mechanism_type,
		.pParameter = NULL,
		.ulParameterLen = 0,
	};

	if (functions->C_SignInit(session, &mechanism, key) != CKR_OK)
		goto out;
	out_len = max_out;
	if (functions->C_Sign(session, in, in_len, out, &out_len) != CKR_OK)
		out_len = 0;
out:
	return out_len;
}

static int execute_decrypt(CK_FUNCTION_LIST_PTR functions,
						   CK_SESSION_HANDLE session,
						   CK_OBJECT_HANDLE key,
						   uint8_t *in, int in_len,
						   uint8_t *out, int max_out)
{
	CK_ULONG out_len = 0;
	CK_MECHANISM mechanism = {
		.mechanism = CKM_RSA_X_509,
		.pParameter = NULL,
		.ulParameterLen = 0,
	};

	if (functions->C_DecryptInit(session, &mechanism, key) != CKR_OK)
		goto out;
	out_len = max_out;
	if (functions->C_Decrypt(session, in, in_len, out, &out_len) != CKR_OK)
		out_len = 0;
out:
	return out_len;
}

static void execute_job(struct pkcs11_job *job)
{
	int max_out = pkcs11_notify_size(job->notify);
	uint8_t *out = pkcs11_notify_buffer(job->notify);
	int out_len = 0;
	struct pkcs11_session *session = NULL;
	CK_MECHANISM_TYPE mechanism = 0;

	if (job->type == job_type_sign &&
			!get_mechanism(job->signature_algorithm, &mechanism)) {
		goto out;
	}
	session = get_session(job->token);
	if (session == NULL) {
		/* there is at least one session for this token, so re-queue */
		LIST_INIT(&job->list);
		pthread_mutex_lock(&global_pkcs11_token.mutex);
		LIST_APPEND(&global_pkcs11_token.queue, &job->list);
		pthread_mutex_unlock(&global_pkcs11_token.mutex);
		job = NULL;
		goto out;
	}
	switch (job->type) {
	case job_type_sign:
		out_len = execute_sign(job->token->module->functions, session->session, session->key, mechanism, job->in, job->in_len, out, max_out);
		break;
	case job_type_decrypt:
		out_len = execute_decrypt(job->token->module->functions, session->session, session->key, job->in, job->in_len, out, max_out);
		break;
	}

out:
	if (session)
		release_session(job->token, session);
	if (job) {
		pkcs11_notify_complete(job->notify, out_len);
		pkcs11_token_free(job->token);
		free(job);
	}
}

static void submit_job(struct pkcs11_job *job)
{
	pthread_mutex_lock(&global_pkcs11_token.mutex);
	LIST_APPEND(&global_pkcs11_token.queue, &job->list);
	pthread_cond_signal(&global_pkcs11_token.condition);
	pthread_mutex_unlock(&global_pkcs11_token.mutex);
}

static int submit_task(struct pkcs11_token *token, struct pkcs11_notify *notify,
                       int signature_algorithm, const uint8_t *in, size_t in_len, enum job_type type)
{
	int ret = 0;
	struct pkcs11_job *job = calloc(1, sizeof(struct pkcs11_job) + in_len);

	if (job == NULL) {
		pkcs11_notify_complete(notify, 0);
		goto out;
	}
	job->type = type;
	job->signature_algorithm = signature_algorithm;
	job->token = pkcs11_token_dup(token);
	LIST_INIT(&job->list);
	job->in_len = in_len;
	memcpy(job->in, in, in_len);
	job->notify = notify;
	submit_job(job);
	ret = 1;
out:
	return ret;
}

static void *token_worker_thread(void *arg)
{
	struct pkcs11_job *job;

	pthread_mutex_lock(&global_pkcs11_token.mutex);
	while (global_pkcs11_token.thread_count) {
		pthread_cond_wait(&global_pkcs11_token.condition, &global_pkcs11_token.mutex);
		while (!LIST_ISEMPTY(&global_pkcs11_token.queue)) {
			job = LIST_NEXT(&global_pkcs11_token.queue, struct pkcs11_job *, list);
			if (job) {
				LIST_DELETE(&job->list);
				pthread_mutex_unlock(&global_pkcs11_token.mutex);
				execute_job(job);
				pthread_mutex_lock(&global_pkcs11_token.mutex);
			}
		}
	}
	return NULL;
}

int pkcs11_token_init(int threads)
{
	int ret = ERR_NONE;
	int i;

	global_pkcs11_token.thread_handles = calloc(threads, sizeof(pthread_t));
	if (global_pkcs11_token.thread_handles == NULL) {
		ha_alert("pkcs11 : unable to allocate %d worker threads.\n", threads);
		ret |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	global_pkcs11_token.thread_count = threads;
	for (i = 0; i < threads; ++i) {
		if (pthread_create(&global_pkcs11_token.thread_handles[i], NULL,
						   token_worker_thread, NULL) != 0) {
			ha_alert("pkcs11 : unable to start worker thread %d of %d.\n",
					 i, threads);
			ret |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

out:
	return ret;
}

void pkcs11_token_deinit(void)
{
	int i;
	int threads = global_pkcs11_token.thread_count;

	pthread_mutex_lock(&global_pkcs11_token.mutex);
	global_pkcs11_token.thread_count = 0;
	pthread_cond_broadcast(&global_pkcs11_token.condition);
	pthread_mutex_unlock(&global_pkcs11_token.mutex);
	for (i = 0; i < threads; ++i)
		pthread_join(global_pkcs11_token.thread_handles[i], NULL);
	if (global_pkcs11_token.thread_handles)
		free(global_pkcs11_token.thread_handles);
	global_pkcs11_token.thread_handles = NULL;
}

static int pkcs11_module_init(struct pkcs11_module *module)
{
	int ret = 0;
	CK_C_GetFunctionList get_function_list = dlsym(module->module, "C_GetFunctionList");

	if (get_function_list == NULL)
		goto out;
	if (get_function_list(&module->functions) != CKR_OK)
		goto out;
	if (module->functions->C_Initialize(NULL) == CKR_OK)
		ret = 1;

out:
	return ret;
}

static struct pkcs11_module *pkcs11_module_load(const char *module_path,
                                                char **err)
{
	struct pkcs11_module *module;
	struct mt_list back;

	MT_LIST_FOR_EACH_ENTRY_LOCKED(module, &global_pkcs11_token.modules, list, back) {
		if (strcmp(module->module_path, module_path) == 0) {
			HA_ATOMIC_INC(&module->ref_count);
			goto out;
		}
	}

	module = calloc(1, sizeof(struct pkcs11_module));
	if (module == NULL)
		goto err;
	module->ref_count = 1;
	module->module_path = strdup(module_path);
	if (module->module_path == NULL)
		goto err;
	module->module = dlopen(module_path, RTLD_LOCAL | RTLD_NOW);
	if (module->module == NULL) {
		memprintf(err, "error loading '%s': %s", module_path, dlerror());
		goto err;
	}
	if (!pkcs11_module_init(module)) {
		memprintf(err, "invalid PKCS#11 driver '%s'", module_path);
		goto err;
	}
	MT_LIST_INIT(&module->list);
	MT_LIST_APPEND(&global_pkcs11_token.modules, &module->list);

out:
	return module;

err:
	if (module) {
		if (module->module_path)
			free(module->module_path);
		if (module->module)
			dlclose(module->module);
		free(module);
	}
	return NULL;
}

static void pkcs11_module_free(struct pkcs11_module *module)
{
	if (HA_ATOMIC_SUB_FETCH(&module->ref_count, 1) == 0) {
		MT_LIST_DELETE(&module->list);
		free(module->module_path);
		module->functions->C_Finalize(NULL);
		dlclose(module->module);
		free(module);
	}
}

/* compares two UTF-8 strings, str2 may be padded with spaces */
static int utf8cmp(const char *str1, int str1len, CK_UTF8CHAR *str2, int str2len)
{
	const char *str1ptr = str1;
	const char *str1end = str1 + str1len;
	const char *str2ptr = (const char *) str2;
	const char *str2end = str2ptr + str2len;
	unsigned int ret1, c1, ret2, c2;
	int ret = 0;

	while (ret == 0 && str2ptr < str2end) {
		if (str1ptr < str1end) {
			ret1 = utf8_next(str1ptr, (str1end - str1ptr), &c1);
			str1ptr += utf8_return_length(ret1);
			if (utf8_return_code(ret1) != UTF8_CODE_OK)
				ret = 1;
		} else
			c1 = ' ';
		ret2 = utf8_next(str2ptr, (str2end - str2ptr), &c2);
		str2ptr += utf8_return_length(ret2);
		if (utf8_return_code(ret2) != UTF8_CODE_OK || c1 != c2)
			ret = 1;
	}
	return ret;
}

/* compares two byte strings, str2 may be padded with spaces */
static int bytescmp(const char *str1, int str1len, CK_CHAR *str2, int str2len)
{
	int ret = 1;
	CK_CHAR *str2pad;

	if (str2len < str1len || memcmp(str1, str2, str1len) != 0)
		ret = 0;
	else {
		/* padding can be spaces */
		str2pad = str2 + str1len;
		while (str2pad < str2 + str2len) {
			if (*str2pad++ != ' ') {
				ret = 0;
			}
		}
	}
	return ret;
}

/* check whether a slot matches the description in the given URI */
static int slot_matches(struct pkcs11_uri *uri, CK_SLOT_INFO *slot_info)
{
	int ret = 1;

	if (uri->slot_manufacturer && utf8cmp(uri->slot_manufacturer, uri->slot_manufacturer_len, slot_info->manufacturerID, 32))
		ret = 0;
	else if (uri->slot_description && utf8cmp(uri->slot_description, uri->slot_description_len, slot_info->slotDescription, 64))
		ret = 0;
	return ret;
}

/* check whether a token matches the description in the given URI */
static int token_matches(struct pkcs11_module *module,
                         struct pkcs11_uri *uri,
                         CK_SLOT_ID slot_id)
{
	CK_TOKEN_INFO token_info;
	int ret = 0;

	if (module->functions->C_GetTokenInfo(slot_id, &token_info) != CKR_OK)
		goto out;
	ret = 1;
	if (uri->serial && bytescmp(uri->serial, uri->serial_len, token_info.serialNumber, 16))
		ret = 0;
	else if (uri->model && utf8cmp(uri->model, uri->model_len, token_info.model, 16))
		ret = 0;
	else if (uri->manufacturer && utf8cmp(uri->manufacturer, uri->manufacturer_len, token_info.manufacturerID, 32))
		ret = 0;
	else if (uri->token && utf8cmp(uri->token, uri->token_len, token_info.label, 32))
		ret = 0;
out:
	return ret;
}

struct pkcs11_token *pkcs11_token_load(struct pkcs11_uri *uri, char **err)
{
	struct pkcs11_token *token = NULL;
	struct pkcs11_module *module = NULL;
	CK_SLOT_ID slot_id;
	CK_SLOT_INFO slot_info;
	CK_SLOT_ID *slot_list = NULL;
	CK_ULONG i, slot_count = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;
	struct pkcs11_session *p11_session = NULL;
	char *id = NULL, *object = NULL;

	if (uri->module == NULL) {
		memprintf(err, "no driver specified");
		goto out;
	}
	module = pkcs11_module_load(uri->module, err);
	if (module == NULL)
		goto out;

	/* easy lookup by the slot ID first if it's available. */
	if (uri->slot_id) {
		slot_id = atoi(uri->slot_id);
		if (module->functions->C_GetSlotInfo(slot_id, &slot_info) == CKR_OK) {
			if (!(slot_info.flags & CKF_TOKEN_PRESENT) ||
					!token_matches(module, uri, slot_id)) {
				memprintf(err, "no token present in slot '%ld'", slot_id);
				goto out;
			}
			goto found_slot;
		}
	}

	/* slot ID not specified, search for the token instead. */
	if (module->functions->C_GetSlotList(CK_TRUE, NULL, &slot_count) != CKR_OK ||
			slot_count <= 0) {
		memprintf(err, "no slots available");
		goto out;
	}
	slot_list = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (slot_list == NULL)
		goto out;
	if (module->functions->C_GetSlotList(CK_TRUE, slot_list, &slot_count) != CKR_OK ||
			slot_count <= 0)
		goto out;
	for (i = 0; i < slot_count; ++i) {
		if (module->functions->C_GetSlotInfo(slot_list[i], &slot_info) == CKR_OK &&
				slot_matches(uri, &slot_info) &&
				token_matches(module, uri, slot_list[i])) {
			slot_id = slot_list[i];
			goto found_slot;
		}
	}

	/* if we haven't jumped to found_slot then the token could not be found. */
	memprintf(err, "no matching token found");
	goto out;

found_slot:
	/* now we try to log in and get an appropriate key */
	if (module->functions->C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &session) != CKR_OK)
		goto out;
	// TODO: Support pin_source
	if (uri->pin_value != NULL &&
			module->functions->C_Login(session, CKU_USER, (CK_UTF8CHAR *) uri->pin_value, uri->pin_value_len) != CKR_OK) {
		memprintf(err, "login failed");
		goto out;
	}
	if (!find_key(module, session, uri->id, uri->id_len, uri->object, uri->object_len, &key)) {
		memprintf(err, "could not find any keys");
		goto out;
	}
	if (uri->id) {
		id = malloc(uri->id_len);
		if (id == NULL)
			goto out;
		memcpy(id, uri->id, uri->id_len);
	}
	if (uri->object) {
		object = malloc(uri->object_len);
		if (object == NULL)
			goto out;
		memcpy(object, uri->object, uri->object_len);
	}
	p11_session = calloc(1, sizeof(struct pkcs11_session));
	if (p11_session == NULL)
		goto out;
	token = calloc(1, sizeof(struct pkcs11_token));
	if (token == NULL) {
		free(p11_session);
		goto out;
	}
	token->ref_count = 1;
	token->slot_id = slot_id;
	token->module = module;
	module = NULL;
	MT_LIST_INIT(&token->sessions);
	MT_LIST_INIT(&p11_session->list);
	MT_LIST_APPEND(&token->sessions, &p11_session->list);
	p11_session->session = session;
	session = CK_INVALID_HANDLE;
	p11_session->key = key;
	p11_session = NULL;
	token->id = id;
	id = NULL;
	token->id_len = uri->id_len;
	token->object = object;
	object = NULL;
	token->object_len = uri->object_len;

out:
	if (p11_session)
		free(p11_session);
	if (id)
		free(id);
	if (object)
		free(object);
	if (module && session != CK_INVALID_HANDLE)
		module->functions->C_CloseSession(session);
	if (module)
		pkcs11_module_free(module);
	if (slot_list)
		free(slot_list);
	return token;
}

static int check_mechanism(struct pkcs11_token *token, CK_MECHANISM_TYPE type)
{
	CK_MECHANISM mechanism = {
		.mechanism = type,
		.pParameter = NULL,
		.ulParameterLen = 0,
	};
	int ret = 0;
	CK_BYTE input[1] = { 0 };
	CK_ULONG input_len = sizeof(input);
	CK_BYTE dummy[4096];
	CK_ULONG size = sizeof(dummy);

	struct pkcs11_session* session;

	session = MT_LIST_NEXT(&token->sessions, struct pkcs11_session*, list);
	if (session == NULL)
		goto out;

	if (token->module->functions->C_SignInit(session->session, &mechanism, session->key) != CKR_OK)
		goto out;

	/* clear the session with a dummy sign operation */
	if (token->module->functions->C_Sign(session->session, input, input_len, dummy, &size) != CKR_OK)
		goto out;

	ret = 1;

out:
	return ret;
}

int pkcs11_token_get_prefs(struct pkcs11_token *token,
                           uint16_t *prefs, int *num_prefs, int max_prefs)
{
	int ret = 0;
	CK_MECHANISM_TYPE *types = NULL;
	CK_ULONG i, count = 0;

	*num_prefs = 0;
	if (token->module->functions->C_GetMechanismList(token->slot_id, NULL, &count) != CKR_OK || count <= 0)
		goto out;
	types = calloc(count, sizeof(CK_MECHANISM_TYPE));
	if (types == NULL)
		goto out;
	if (token->module->functions->C_GetMechanismList(token->slot_id, types, &count) != CKR_OK || count <= 0)
		goto out;
	for (i = 0; i < count && *num_prefs < max_prefs; ++i) {
		/* the preferences tell us what the slot supports, but not what the
		 * actual object supports, so we need to attempt to use each of them.
		 */
		if (!check_mechanism(token, types[i]))
			continue;
		switch (types[i]) {
		case CKM_EDDSA:
			prefs[(*num_prefs)++] = SSL_SIGN_ED25519;
			break;
		case CKM_SHA512_RSA_PKCS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PKCS1_SHA512;
			break;
		case CKM_ECDSA_SHA512:
			prefs[(*num_prefs)++] = SSL_SIGN_ECDSA_SECP521R1_SHA512;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PSS_RSAE_SHA512;
			break;
		case CKM_SHA384_RSA_PKCS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PKCS1_SHA384;
			break;
		case CKM_ECDSA_SHA384:
			prefs[(*num_prefs)++] = SSL_SIGN_ECDSA_SECP384R1_SHA384;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PSS_RSAE_SHA384;
			break;
		case CKM_SHA256_RSA_PKCS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PKCS1_SHA256;
			break;
		case CKM_ECDSA_SHA256:
			prefs[(*num_prefs)++] = SSL_SIGN_ECDSA_SECP256R1_SHA256;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PSS_RSAE_SHA256;
			break;
		case CKM_ECDSA_SHA1:
			prefs[(*num_prefs)++] = SSL_SIGN_ECDSA_SHA1;
			break;
		case CKM_SHA1_RSA_PKCS:
			prefs[(*num_prefs)++] = SSL_SIGN_RSA_PKCS1_SHA1;
			break;
		}
	}
	ret = 1;

out:
	if (types)
		free(types);
	return ret;
}

int pkcs11_token_sign(struct pkcs11_token *token, struct pkcs11_notify *notify,
                      int signature_algorithm, const uint8_t *in, size_t in_len)
{
	return submit_task(token, notify, signature_algorithm, in, in_len, job_type_sign);
}

int pkcs11_token_decrypt(struct pkcs11_token *token, struct pkcs11_notify *notify,
                         const uint8_t *in, size_t in_len)
{
	return submit_task(token, notify, -1, in, in_len, job_type_decrypt);
}

void pkcs11_token_free(struct pkcs11_token *token)
{
	struct pkcs11_session *p11_session;

	if (HA_ATOMIC_SUB_FETCH(&token->ref_count, 1) == 0) {
		while ((p11_session = MT_LIST_POP(&token->sessions,
		                                  struct pkcs11_session*, list))) {
			token->module->functions->C_CloseSession(p11_session->session);
			free(p11_session);
		}
		pkcs11_module_free(token->module);
		if (token->id)
			free(token->id);
		if (token->object)
			free(token->object);
		free(token);
	}
}

struct pkcs11_token *pkcs11_token_dup(struct pkcs11_token *token)
{
	HA_ATOMIC_INC(&token->ref_count);
	return token;
}
