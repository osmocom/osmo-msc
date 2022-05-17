/* SMS queue to continuously attempt to deliver SMS */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * The difficulty of such a queue is to send a lot of SMS without
 * overloading the paging subsystem and the database and other users
 * of the MSC. To make the best use we would need to know the number
 * of pending paging requests, then throttle the number of SMS we
 * want to send and such.
 * We will start with a very simple SMS Queue and then try to speed
 * things up by collecting data from other parts of the system.
 */

#include <limits.h>

#include <osmocom/msc/sms_queue.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/vlr.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>

#include <osmocom/vty/vty.h>

enum smsq_stat_item_idx {
	SMSQ_STAT_SMS_RAM_PENDING,
};

static const struct osmo_stat_item_desc smsq_stat_item_desc[] = {
	[SMSQ_STAT_SMS_RAM_PENDING]			= { "ram:pending",
		"Number of SMSs in the in-RAM pending delivery queue" },
};

static const struct osmo_stat_item_group_desc smsq_statg_desc = {
	"sms_queue",
	"SMS queue",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(smsq_stat_item_desc),
	smsq_stat_item_desc,
};

enum smsq_rate_ctr_idx {
	SMSQ_CTR_SMS_DELIVERY_ATTEMPTS,
	SMSQ_CTR_SMS_DELIVERY_ACK,
	SMSQ_CTR_SMS_DELIVERY_ERR,
	SMSQ_CTR_SMS_DELIVERY_NOMEM,
	SMSQ_CTR_SMS_DELIVERY_TIMEOUT,
};

static const struct rate_ctr_desc smsq_ctr_desc[] = {
	[SMSQ_CTR_SMS_DELIVERY_ATTEMPTS]	= { "delivery:attempts",
		"Attempted MT SMS deliveries to subscriber" },
	[SMSQ_CTR_SMS_DELIVERY_ACK]		= { "deliver:ack",
		"Successful MT SMS delivery to subscriber" },
	[SMSQ_CTR_SMS_DELIVERY_ERR]		= { "deliver:error",
		"Erroneous MT SMS delivery" },
	[SMSQ_CTR_SMS_DELIVERY_NOMEM]		= { "deliver:no_memory",
		"Failed MT SMS delivery due to no memory on MS" },
	[SMSQ_CTR_SMS_DELIVERY_TIMEOUT]		= { "deliver:paging_timeout",
		"Failed MT SMS delivery due to paging timeout (MS gone?)" },
};

static const struct rate_ctr_group_desc smsq_ctrg_desc = {
	"sms_queue",
	"SMS queue",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(smsq_ctr_desc),
	smsq_ctr_desc,
};

#define smsq_rate_ctr_inc(smsq, idx) \
	rate_ctr_inc(rate_ctr_group_get_ctr((smsq)->ctrg, idx))
#define smsq_rate_ctr_add(smsq, idx, val) \
	rate_ctr_add(rate_ctr_group_get_ctr((smsq)->ctrg, idx), val)

#define smsq_stat_item_inc(smsq, idx) \
	osmo_stat_item_inc(osmo_stat_item_group_get_item((smsq)->statg, idx), 1)
#define smsq_stat_item_dec(smsq, idx) \
	osmo_stat_item_dec(osmo_stat_item_group_get_item((smsq)->statg, idx), 1)
#define smsq_stat_item_set(smsq, idx, val) \
	osmo_stat_item_set(osmo_stat_item_group_get_item((smsq)->statg, idx), val)


/* One in-RAM record of a "pending SMS".  This is not the SMS itself, but merely
 * a pointer to the database record.  It holds a reference on the vlr_subscriber
 * and some counters.  While this object exists in RAM, we are regularly attempting
 * to deliver the related SMS. */
struct gsm_sms_pending {
	struct llist_head entry;	/* gsm_sms_queue.pending_sms */

	struct vlr_subscr *vsub;	/* destination subscriber for this SMS */
	struct msc_a *msc_a;		/* MSC_A associated with this SMS */
	unsigned long long sms_id;	/* unique ID (in SQL database) of this SMS */
	int failed_attempts;		/* count of failed deliver attempts so far */
	int resend;			/* should we try re-sending it (now) ? */
};

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

/* private wrapper function to make sure we count all SMS delivery attempts */
static void _gsm411_send_sms(struct gsm_network *net, struct vlr_subscr *vsub, struct gsm_sms *sms)
{
	smsq_rate_ctr_inc(net->sms_queue, SMSQ_CTR_SMS_DELIVERY_ATTEMPTS);
	gsm411_send_sms(net, vsub, sms);
}

static int sms_subscr_cb(unsigned int, unsigned int, void *, void *);
static int sms_sms_cb(unsigned int, unsigned int, void *, void *);

/* look-up a 'gsm_sms_pending' for the given sms_id; return NULL if none */
static struct gsm_sms_pending *sms_find_pending(struct gsm_sms_queue *smsq,
						unsigned long long sms_id)
{
	struct gsm_sms_pending *pending;

	llist_for_each_entry(pending, &smsq->pending_sms, entry) {
		if (pending->sms_id == sms_id)
			return pending;
	}

	return NULL;
}

/* do we currently have a gsm_sms_pending object for the given SMS id? */
int sms_queue_sms_is_pending(struct gsm_sms_queue *smsq, unsigned long long sms_id)
{
	return sms_find_pending(smsq, sms_id) != NULL;
}

/* find the first pending SMS (in RAM) for the given subscriber */
static struct gsm_sms_pending *sms_subscriber_find_pending(
					struct gsm_sms_queue *smsq,
					struct vlr_subscr *vsub)
{
	struct gsm_sms_pending *pending;

	llist_for_each_entry(pending, &smsq->pending_sms, entry) {
		if (pending->vsub == vsub)
			return pending;
	}

	return NULL;
}

/* do we have any pending SMS (in RAM) for the given subscriber? */
static int sms_subscriber_is_pending(struct gsm_sms_queue *smsq,
				     struct vlr_subscr *vsub)
{
	return sms_subscriber_find_pending(smsq, vsub) != NULL;
}

/* allocate a new gsm_sms_pending record and fill it with information from 'sms' */
static struct gsm_sms_pending *sms_pending_from(struct gsm_sms_queue *smsq,
						struct gsm_sms *sms)
{
	struct gsm_sms_pending *pending;

	pending = talloc_zero(smsq, struct gsm_sms_pending);
	if (!pending)
		return NULL;

	vlr_subscr_get(sms->receiver, VSUB_USE_SMS_PENDING);
	pending->vsub = sms->receiver;
	pending->sms_id = sms->id;
	llist_add_tail(&pending->entry, &smsq->pending_sms);

	smsq->pending += 1;
	smsq_stat_item_inc(smsq, SMSQ_STAT_SMS_RAM_PENDING);

	return pending;
}

/* release a gsm_sms_pending object */
static void sms_pending_free(struct gsm_sms_queue *smsq, struct gsm_sms_pending *pending)
{
	smsq->pending -= 1;
	smsq_stat_item_dec(smsq, SMSQ_STAT_SMS_RAM_PENDING);
	vlr_subscr_put(pending->vsub, VSUB_USE_SMS_PENDING);
	llist_del(&pending->entry);
	talloc_free(pending);
}

/* this sets the 'resend' flag of the gsm_sms_pending and schedules
 * the timer for re-sending */
static void sms_pending_resend(struct gsm_sms_pending *pending)
{
	struct gsm_network *net = pending->vsub->vlr->user_ctx;
	struct gsm_sms_queue *smsq;
	LOGP(DLSMS, LOGL_DEBUG,
	     "Scheduling resend of SMS %llu.\n", pending->sms_id);

	pending->resend = 1;

	smsq = net->sms_queue;
	if (osmo_timer_pending(&smsq->resend_pending))
		return;

	osmo_timer_schedule(&smsq->resend_pending, 1, 0);
}

/* call-back when a pending SMS has failed; try another re-send if number of
 * attempts is < smsq->max_fail */
static void sms_pending_failed(struct gsm_sms_pending *pending, int paging_error)
{
	struct gsm_network *net = pending->vsub->vlr->user_ctx;
	struct gsm_sms_queue *smsq;

	pending->failed_attempts++;
	LOGP(DLSMS, LOGL_NOTICE, "Sending SMS %llu failed %d times.\n",
	     pending->sms_id, pending->failed_attempts);

	smsq = net->sms_queue;
	if (pending->failed_attempts < smsq->cfg->max_fail)
		return sms_pending_resend(pending);

	sms_pending_free(smsq, pending);
}

/* Resend all SMS that are scheduled for a resend. This is done to
 * avoid an immediate failure.  This iterates over all the (in RAM)
 * pending_sms records, checks for resend == true, reads them from the
 * DB and attempts to send them via _gsm411_send_sms() */
static void sms_resend_pending(void *_data)
{
	struct gsm_sms_pending *pending, *tmp;
	struct gsm_sms_queue *smsq = _data;

	llist_for_each_entry_safe(pending, tmp, &smsq->pending_sms, entry) {
		struct gsm_sms *sms;
		if (!pending->resend)
			continue;

		sms = db_sms_get(smsq->network, pending->sms_id);

		/* the sms is gone? Move to the next */
		if (!sms) {
			sms_pending_free(smsq, pending);
			sms_queue_trigger(smsq);
		} else {
			pending->resend = 0;
			_gsm411_send_sms(smsq->network, sms->receiver, sms);
		}
	}
}

/* Find the next pending SMS by cycling through the recipients. We could also
 * cycle through the pending SMS, but that might cause us to keep trying to
 * send SMS to the same few subscribers repeatedly while not servicing other
 * subscribers for a long time. By walking the list of recipient MSISDNs, we
 * ensure that all subscribers get their fair time to receive SMS. */
struct gsm_sms *smsq_take_next_sms(struct gsm_network *net,
				   char *last_msisdn,
				   size_t last_msisdn_buflen)
{
	struct gsm_sms *sms;
	int wrapped = 0;
	int sanity = 100;
	char started_with_msisdn[last_msisdn_buflen];

	OSMO_STRLCPY_ARRAY(started_with_msisdn, last_msisdn);

	while (wrapped < 2 && (--sanity)) {
		/* If we wrapped around and passed the first msisdn, we're
		 * through the entire SMS DB; end it. */
		if (wrapped && strcmp(last_msisdn, started_with_msisdn) >= 0)
			break;

		sms = db_sms_get_next_unsent_rr_msisdn(net, last_msisdn, 9);
		if (!sms) {
			last_msisdn[0] = '\0';
			wrapped++;
			continue;
		}

		/* Whatever happens, next time around service another recipient
		 */
		osmo_strlcpy(last_msisdn, sms->dst.addr, last_msisdn_buflen);

		/* Is the subscriber attached? If not, go to next SMS */
		if (!sms->receiver || !sms->receiver->lu_complete) {
			LOGP(DLSMS, LOGL_DEBUG,
			     "Subscriber %s%s is not attached, skipping SMS %llu\n",
			     sms->receiver ? "" : "MSISDN-",
			     sms->receiver ? vlr_subscr_msisdn_or_name(sms->receiver)
					   : sms->dst.addr, sms->id);
			sms_free(sms);
			continue;
		}

		return sms;
	}

	DEBUGP(DLSMS, "SMS queue: no SMS to be sent\n");
	return NULL;
}

/* read up to 'max_pending' pending SMS from the database and add them to the in-memory
 * sms_queue; trigger the first delivery attempt. 'submit' in this context means
 * "read from the database and add to the in-memory gsm_sms_queue" and is not to be
 * confused with the SMS SUBMIT operation a MS performs when sending a MO-SMS. */
static void sms_submit_pending(void *_data)
{
	struct gsm_sms_queue *smsq = _data;
	int attempts = smsq->cfg->max_pending - smsq->pending;
	int initialized = 0;
	unsigned long long first_sub = 0;
	int attempted = 0, rounds = 0;

	LOGP(DLSMS, LOGL_DEBUG, "Attempting to send up to %d SMS\n", attempts);

	do {
		struct gsm_sms_pending *pending;
		struct gsm_sms *sms;


		sms = smsq_take_next_sms(smsq->network, smsq->last_msisdn,
					 sizeof(smsq->last_msisdn));
		if (!sms) {
			LOGP(DLSMS, LOGL_DEBUG, "Sending SMS done (%d attempted)\n",
			     attempted);
			break;
		}

		rounds += 1;
		LOGP(DLSMS, LOGL_DEBUG, "Checking whether to send SMS %llu\n", sms->id);

		/*
		 * This code needs to detect a loop. It assumes that no SMS
		 * will vanish during the time this is executed. We will remember
		 * the id of the first GSM subscriber we see and then will
		 * compare this. The Database code should make sure that we will
		 * see all other subscribers first before seeing this one again.
		 *
		 * It is always scary to have an infinite loop like this.
		 */
		if (!initialized) {
			first_sub = sms->receiver->id;
			initialized = 1;
		} else if (first_sub == sms->receiver->id) {
			LOGP(DLSMS, LOGL_DEBUG, "Sending SMS done (loop) (%d attempted)\n",
			     attempted);
			sms_free(sms);
			break;
		}

		/* no need to send a pending sms */
		if (sms_queue_sms_is_pending(smsq, sms->id)) {
			LOGP(DLSMS, LOGL_DEBUG,
			     "SMSqueue with pending sms: %llu. Skipping\n", sms->id);
			sms_free(sms);
			continue;
		}

		/* no need to send a SMS with the same receiver */
		if (sms_subscriber_is_pending(smsq, sms->receiver)) {
			LOGP(DLSMS, LOGL_DEBUG,
			     "SMSqueue with pending sub: %llu. Skipping\n", sms->receiver->id);
			sms_free(sms);
			continue;
		}

		/* allocate a new gsm_sms_pending object in RAM */
		pending = sms_pending_from(smsq, sms);
		if (!pending) {
			LOGP(DLSMS, LOGL_ERROR,
			     "Failed to create pending SMS entry.\n");
			sms_free(sms);
			continue;
		}

		attempted += 1;
		_gsm411_send_sms(smsq->network, sms->receiver, sms);
	} while (attempted < attempts && rounds < 1000);

	LOGP(DLSMS, LOGL_DEBUG, "SMSqueue added %d messages in %d rounds\n", attempted, rounds);
}

/* obtain the next pending SMS for given subscriber from database,
 * create gsm_sms_pending object and attempt first delivery. If there
 * are no SMS pending for the given subscriber, call sms_submit_pending()
 * to read more SMS (for any subscriber) into the in-RAM pending queue */
static void sms_send_next(struct vlr_subscr *vsub)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	struct gsm_sms_queue *smsq = net->sms_queue;
	struct gsm_sms_pending *pending;
	struct gsm_sms *sms;

	/* the subscriber should not be in the queue */
	OSMO_ASSERT(!sms_subscriber_is_pending(smsq, vsub));

	/* check for more messages for this subscriber */
	sms = db_sms_get_unsent_for_subscr(vsub, INT_MAX);
	if (!sms)
		goto no_pending_sms;

	/* The sms should not be scheduled right now */
	OSMO_ASSERT(!sms_queue_sms_is_pending(smsq, sms->id));

	/* Remember that we deliver this SMS and send it */
	pending = sms_pending_from(smsq, sms);
	if (!pending) {
		LOGP(DLSMS, LOGL_ERROR,
			"Failed to create pending SMS entry.\n");
		sms_free(sms);
		goto no_pending_sms;
	}

	_gsm411_send_sms(smsq->network, sms->receiver, sms);
	return;

no_pending_sms:
	/* Try to send the SMS to avoid the queue being stuck */
	sms_submit_pending(net->sms_queue);
}

/* Trigger a call to sms_submit_pending() in one second */
int sms_queue_trigger(struct gsm_sms_queue *smsq)
{
	LOGP(DLSMS, LOGL_DEBUG, "Triggering SMS queue\n");
	if (osmo_timer_pending(&smsq->push_queue))
		return 0;

	osmo_timer_schedule(&smsq->push_queue, 1, 0);
	return 0;
}

/* allocate + initialize SMS queue configuration with some default values */
struct sms_queue_config *sms_queue_cfg_alloc(void *ctx)
{
	struct sms_queue_config *sqcfg = talloc_zero(ctx, struct sms_queue_config);
	OSMO_ASSERT(sqcfg);

	sqcfg->max_pending = 20;
	sqcfg->max_fail = 1;
	sqcfg->db_file_path = talloc_strdup(ctx, SMS_DEFAULT_DB_FILE_PATH);

	return sqcfg;
}

/* initialize the sms_queue subsystem and read the first batch of SMS from
 * the database for delivery */
int sms_queue_start(struct gsm_network *network)
{
	struct gsm_sms_queue *sms = talloc_zero(network, struct gsm_sms_queue);
	if (!sms) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create the SMS queue.\n");
		return -1;
	}

	sms->cfg = network->sms_queue_cfg;
	sms->statg = osmo_stat_item_group_alloc(sms, &smsq_statg_desc, 0);
	if (!sms->statg)
		goto err_free;

	sms->ctrg = rate_ctr_group_alloc(sms, &smsq_ctrg_desc, 0);
	if (!sms->ctrg)
		goto err_statg;

	network->sms_queue = sms;
	INIT_LLIST_HEAD(&sms->pending_sms);
	sms->network = network;
	osmo_timer_setup(&sms->push_queue, sms_submit_pending, sms);
	osmo_timer_setup(&sms->resend_pending, sms_resend_pending, sms);

	osmo_signal_register_handler(SS_SUBSCR, sms_subscr_cb, network);
	osmo_signal_register_handler(SS_SMS, sms_sms_cb, network);

	if (db_init(sms, sms->cfg->db_file_path, true)) {
		LOGP(DMSC, LOGL_FATAL, "DB: Failed to init database: %s\n",
			osmo_quote_str(sms->cfg->db_file_path, -1));
		return -1;
	}

	if (db_prepare()) {
		LOGP(DMSC, LOGL_FATAL, "DB: Failed to prepare database.\n");
		return -1;
	}

	sms_submit_pending(sms);

	return 0;

err_statg:
	osmo_stat_item_group_free(sms->statg);
err_free:
	talloc_free(sms);

	return -ENOMEM;
}

/* call-back: Given subscriber is now ready for short messages. */
static int sub_ready_for_sm(struct gsm_network *net, struct vlr_subscr *vsub)
{
	struct gsm_sms *sms;
	struct gsm_sms_pending *pending;

	/*
	 * The code used to be very clever and tried to submit
	 * a SMS during the Location Updating Request. This has
	 * two issues:
	 *   1.) The Phone might not be ready yet, e.g. the C155
	 *       will not respond to the Submit when it is booting.
	 *   2.) The queue is already trying to submit SMS to the
	 *	 user and by not responding to the paging request
	 *	 we will set the LAC back to 0. We would have to
	 *	 stop the paging and move things over.
	 *
	 * We need to be careful in what we try here.
	 */

	/* check if we have pending requests */
	pending = sms_subscriber_find_pending(net->sms_queue, vsub);
	if (pending) {
		LOGP(DMSC, LOGL_NOTICE,
		     "Pending paging while subscriber %llu attached.\n",
		      vsub->id);
		return 0;
	}

	/* Now try to deliver any pending SMS to this sub */
	sms = db_sms_get_unsent_for_subscr(vsub, INT_MAX);
	if (!sms)
		return -1;

	_gsm411_send_sms(net, vsub, sms);
	return 0;
}

/* call-back for SS_SUBSCR signals */
static int sms_subscr_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct vlr_subscr *vsub = signal_data;

	if (signal != S_SUBSCR_ATTACHED)
		return 0;

	/* this is readyForSM */
	return sub_ready_for_sm(handler_data, vsub);
}

/* call-back for SS_SMS signals */
static int sms_sms_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_network *network = handler_data;
	struct sms_signal_data *sig_sms = signal_data;
	struct gsm_sms_pending *pending;
	struct vlr_subscr *vsub;

	/* We got a new SMS and maybe should launch the queue again. */
	if (signal == S_SMS_SUBMITTED || signal == S_SMS_SMMA) {
		/* TODO: For SMMA we might want to re-use the radio connection. */
		sms_queue_trigger(network->sms_queue);
		return 0;
	}

	if (!sig_sms->sms)
		return -1;


	/*
	 * Find the entry of our queue. The SMS subsystem will submit
	 * sms that are not in our control as we just have a channel
	 * open anyway.
	 */
	pending = sms_find_pending(network->sms_queue, sig_sms->sms->id);
	if (!pending)
		return 0;

	switch (signal) {
	case S_SMS_DELIVERED:
		smsq_rate_ctr_inc(network->sms_queue, SMSQ_CTR_SMS_DELIVERY_ACK);
		/* Remember the subscriber and clear the pending entry */
		vsub = pending->vsub;
		vlr_subscr_get(vsub, __func__);
		db_sms_delete_sent_message_by_id(pending->sms_id);
		sms_pending_free(network->sms_queue, pending);
		/* Attempt to send another SMS to this subscriber */
		sms_send_next(vsub);
		vlr_subscr_put(vsub, __func__);
		break;
	case S_SMS_MEM_EXCEEDED:
		smsq_rate_ctr_inc(network->sms_queue, SMSQ_CTR_SMS_DELIVERY_NOMEM);
		sms_pending_free(network->sms_queue, pending);
		sms_queue_trigger(network->sms_queue);
		break;
	case S_SMS_UNKNOWN_ERROR:
		/*
		 * There can be many reasons for this failure. E.g. the paging
		 * timed out, the subscriber was not paged at all, or there was
		 * a protocol error. The current strategy is to try sending the
		 * next SMS for busy/oom and to retransmit when we have paged.
		 *
		 * When the paging expires three times we will disable the
		 * subscriber. If we have some kind of other transmit error we
		 * should flag the SMS as bad.
		 */
		if (sig_sms->paging_result) {
			smsq_rate_ctr_inc(network->sms_queue, SMSQ_CTR_SMS_DELIVERY_ERR);
			/* BAD SMS? */
			db_sms_inc_deliver_attempts(sig_sms->sms);
			sms_pending_failed(pending, 0);
		} else {
			smsq_rate_ctr_inc(network->sms_queue, SMSQ_CTR_SMS_DELIVERY_TIMEOUT);
			sms_pending_failed(pending, 1);
		}
		break;
	default:
		LOGP(DLSMS, LOGL_ERROR, "Unhandled result: %d\n",
		     sig_sms->paging_result);
	}

	/* While here, attempt to remove an expired SMS from the DB. */
	db_sms_delete_oldest_expired_message();

	return 0;
}

/* VTY helper functions */
int sms_queue_stats(struct gsm_sms_queue *smsq, struct vty *vty)
{
	struct gsm_sms_pending *pending;

	vty_out(vty, "SMSqueue with max_pending: %d pending: %d%s",
		smsq->cfg->max_pending, smsq->pending, VTY_NEWLINE);

	llist_for_each_entry(pending, &smsq->pending_sms, entry)
		vty_out(vty, " SMS Pending for Subscriber: %llu SMS: %llu Failed: %d.%s",
			pending->vsub->id, pending->sms_id,
			pending->failed_attempts, VTY_NEWLINE);
	return 0;
}

int sms_queue_clear(struct gsm_sms_queue *smsq)
{
	struct gsm_sms_pending *pending, *tmp;

	llist_for_each_entry_safe(pending, tmp, &smsq->pending_sms, entry) {
		LOGP(DLSMS, LOGL_NOTICE,
		     "SMSqueue clearing for sub %llu\n", pending->vsub->id);
		sms_pending_free(smsq, pending);
	}

	return 0;
}
