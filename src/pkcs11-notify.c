
#include <haproxy/atomic.h>
#include <haproxy/pkcs11-notify.h>
#include <haproxy/task.h>
#include <haproxy/tools-t.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct pkcs11_notify {
	/* whether an action is currently pending, if this is 0 but pending_out is
	 * not NULL then the action is waiting to be collected, if this is 1 then
	 * pending_out will be non-NULL and the action is queued or being processed,
	 * if this is 2 then the action was queued but was freed before it
	 * completed.
	 */
	int pending;
	/* the wait_event to notify when a pending operation is complete */
	struct wait_event *wait_event;
	/* if set, the buffer ready to output the data into */
	uint8_t *pending_out;
	/* the number of bytes in pending_out */
	size_t pending_len;
};

struct pkcs11_notify *pkcs11_notify_new(void)
{
	return calloc(1, sizeof(struct pkcs11_notify));
}

int pkcs11_notify_alloc(struct pkcs11_notify *notify, size_t max_out)
{
	int ret = 0;
	int old = 0;
	uint8_t *output_buffer = calloc(max_out, sizeof(uint8_t));

	if (output_buffer == NULL)
		goto out;
	if (notify->pending_out != NULL || !HA_ATOMIC_CAS(&notify->pending, &old, 1)) {
		free(output_buffer);
		output_buffer = NULL;
		goto out;
	}
	notify->pending_out = output_buffer;
	notify->pending_len = max_out;
	ret = 1;

out:
	return ret;
}

uint8_t *pkcs11_notify_buffer(struct pkcs11_notify *notify)
{
	return notify->pending_out;
}

size_t pkcs11_notify_size(struct pkcs11_notify *notify)
{
	return notify->pending_len;
}

void pkcs11_notify_complete(struct pkcs11_notify *notify, size_t len)
{
	int pending = HA_ATOMIC_SUB_FETCH(&notify->pending, 1);
	int tid;

	if (pending == 1) {
		/* complete occurred after pkcs11_notify_free was called */
		free(notify->pending_out);
		free(notify);
	} else {
		notify->pending_len = len;
		if (notify->wait_event) {
			tid = notify->wait_event->tasklet->tid;
			if (tid < 0) {
				/* cannot wake on the current tid, so place on 0 */
				tid = 0;
			}
			tasklet_wakeup_on(notify->wait_event->tasklet, tid);
		}
	}
}

int pkcs11_notify_clear(struct pkcs11_notify *notify,
						uint8_t *out, size_t *out_len, size_t max_len)
{
	int ret = 0;

	if (HA_ATOMIC_LOAD(&notify->pending) == 1)
		ret = -1;
	else if (notify->pending_out) {
		*out_len = notify->pending_len;
		if (*out_len > max_len)
			*out_len = max_len;
		memcpy(out, notify->pending_out, *out_len);
		free(notify->pending_out);
		notify->pending_out = NULL;
		notify->wait_event = NULL;
		ret = 1;
	}
	return ret;
}

void pkcs11_notify(struct pkcs11_notify *notify, struct wait_event *wait_event)
{
	notify->wait_event = wait_event;
	if (HA_ATOMIC_LOAD(&notify->pending) != 1)
		tasklet_wakeup(wait_event->tasklet);
}

void pkcs11_notify_free(struct pkcs11_notify *notify)
{
	int pending = HA_ATOMIC_ADD_FETCH(&notify->pending, 1);

	if (pending != 2) {
		notify->wait_event = NULL;
		if (notify->pending_out) {
			free(notify->pending_out);
			notify->pending_out = NULL;
		}
		free(notify);
	}
}
