#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

#include <stdbool.h>
#include <osmocom/core/timer.h>
#include <osmocom/msc/gsm_subscriber.h>

struct gsm_network;
/* (global) state of the SMS queue. */
struct gsm_sms_queue {
	struct osmo_timer_list resend_pending;	/* timer triggering sms_resend_pending() */
	struct osmo_timer_list push_queue;	/* timer triggering sms_submit_pending() */
	struct gsm_network *network;
	struct llist_head pending_sms;		/* list of gsm_sms_pending */
	struct sms_queue_config *cfg;
	int pending;				/* current number of gsm_sms_pending in RAM */

	/* last MSISDN for which we read SMS from the database and created gsm_sms_pending records */
	char last_msisdn[GSM23003_MSISDN_MAX_DIGITS+1];

	/* statistics / counters */
	struct osmo_stat_item_group *statg;
	struct rate_ctr_group *ctrg;
};
struct vty;

struct sms_queue_config {
	char *db_file_path;			/* SMS database file path */
	int max_fail;				/* maximum number of delivery failures */
	int max_pending;			/* maximum number of gsm_sms_pending in RAM */
	bool delete_delivered;			/* delete delivered SMS from DB? */
	bool delete_expired;			/* delete expired SMS from DB? */
	unsigned int minimum_validity_mins;	/* minimum validity period in minutes */
	unsigned int default_validity_mins;	/* default validity period in minutes */
	unsigned int trigger_holdoff;		/* How often can the queue be re-triggered? */
};

struct sms_queue_config *sms_queue_cfg_alloc(void *ctx);

#define VSUB_USE_SMS_PENDING "SMS-pending"
#define MSC_A_USE_SMS_PENDING "SMS-pending"

int sms_queue_start(struct gsm_network *net);
int sms_queue_trigger(struct gsm_sms_queue *);

/* vty helper functions */
int sms_queue_stats(struct gsm_sms_queue *, struct vty* vty);
int sms_queue_clear(struct gsm_sms_queue *);
int sms_queue_sms_is_pending(struct gsm_sms_queue *smsq, unsigned long long sms_id);

#endif
