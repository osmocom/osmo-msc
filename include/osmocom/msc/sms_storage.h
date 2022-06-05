#pragma once

#include <stdbool.h>
#include <limits.h>

struct sms_storage_inst;
struct gsm_sms;


/* configuration of SMS storage */
struct sms_storage_cfg {
	char storage_dir[PATH_MAX+1];
	/* unlink messages after delivery, or just move them? */
	bool unlink_delivered;
	/* unlink messages after expiration, or just move them? */
	bool unlink_expired;
};

enum smss_delete_cause {
	SMSS_DELETE_CAUSE_UNKNOWN,
	SMSS_DELETE_CAUSE_DELIVERED,
	SMSS_DELETE_CAUSE_EXPIRED,
};


struct sms_storage_inst *sms_storage_init(void *ctx, const struct sms_storage_cfg *scfg);

int sms_storage_to_disk_req(struct sms_storage_inst *ssi, struct gsm_sms *sms);

int sms_storage_delete_from_disk_req(struct sms_storage_inst *ssi, unsigned long long id,
				     enum smss_delete_cause cause);
