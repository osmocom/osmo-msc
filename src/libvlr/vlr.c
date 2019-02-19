/* Osmocom Visitor Location Register (VLR) code base */

/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/msc/vlr_sgs.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/debug.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <errno.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"
#include "vlr_lu_fsm.h"
#include "vlr_access_req_fsm.h"
#include "vlr_sgs_fsm.h"

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

/***********************************************************************
 * Convenience functions
 ***********************************************************************/

const struct value_string vlr_ciph_names[] = {
	OSMO_VALUE_STRING(VLR_CIPH_NONE),
	OSMO_VALUE_STRING(VLR_CIPH_A5_1),
	OSMO_VALUE_STRING(VLR_CIPH_A5_2),
	OSMO_VALUE_STRING(VLR_CIPH_A5_3),
	{ 0, NULL }
};

uint32_t vlr_timer(struct vlr_instance *vlr, uint32_t timer)
{
	uint32_t tidx = 0xffffffff;

	switch (timer) {
	case 3270:
		tidx = VLR_T_3270;
		break;
	case 3260:
		tidx = VLR_T_3260;
		break;
	case 3250:
		tidx = VLR_T_3250;
		break;
	}

	OSMO_ASSERT(tidx < sizeof(vlr->cfg.timer));
	return vlr->cfg.timer[tidx];
}

/* return static buffer with printable name of VLR subscriber */
const char *vlr_subscr_name(const struct vlr_subscr *vsub)
{
	static char buf[128];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	bool present = false;
	if (!vsub)
		return "unknown";
	if (vsub->imsi[0]) {
		OSMO_STRBUF_PRINTF(sb, "IMSI-%s", vsub->imsi);
		present = true;
	}
	if (vsub->msisdn[0]) {
		OSMO_STRBUF_PRINTF(sb, "%sMSISDN-%s", present? ":" : "", vsub->msisdn);
		present = true;
	}
	if (vsub->tmsi != GSM_RESERVED_TMSI) {
		OSMO_STRBUF_PRINTF(sb, "%sTMSI-0x%08X", present? ":" : "", vsub->tmsi);
		present = true;
	}
	if (vsub->tmsi_new != GSM_RESERVED_TMSI) {
		OSMO_STRBUF_PRINTF(sb, "%sTMSInew-0x%08X", present? ":" : "", vsub->tmsi_new);
		present = true;
	}
	if (!present)
		return "unknown";

	return buf;
}

const char *vlr_subscr_msisdn_or_name(const struct vlr_subscr *vsub)
{
	if (!vsub || !vsub->msisdn[0])
		return vlr_subscr_name(vsub);
	return vsub->msisdn;
}

struct vlr_subscr *_vlr_subscr_find_by_imsi(struct vlr_instance *vlr,
					    const char *imsi,
					    const char *use,
					    const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (!imsi || !*imsi)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_imsi(vsub, imsi)) {
			vlr_subscr_get_src(vsub, use, file, line);
			return vsub;
		}
	}
	return NULL;
}

struct vlr_subscr *_vlr_subscr_find_by_tmsi(struct vlr_instance *vlr,
					    uint32_t tmsi,
					    const char *use,
					    const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (tmsi == GSM_RESERVED_TMSI)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_tmsi(vsub, tmsi)) {
			vlr_subscr_get_src(vsub, use, file, line);
			return vsub;
		}
	}
	return NULL;
}

struct vlr_subscr *_vlr_subscr_find_by_msisdn(struct vlr_instance *vlr,
					      const char *msisdn,
					      const char *use,
					      const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (!msisdn || !*msisdn)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_msisdn(vsub, msisdn)) {
			vlr_subscr_get_src(vsub, use, file, line);
			return vsub;
		}
	}
	return NULL;
}

/* Transmit GSUP message to HLR */
static int vlr_tx_gsup_message(const struct vlr_instance *vlr,
			       const struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = osmo_gsup_client_msgb_alloc();

	int rc = osmo_gsup_encode(msg, gsup_msg);
	if (rc < 0) {
		LOGP(DVLR, LOGL_ERROR, "GSUP encoding failure: %s\n", strerror(-rc));
		return rc;
	}

	if (!vlr->gsup_client) {
		LOGP(DVLR, LOGL_NOTICE, "GSUP link is down, cannot "
			"send GSUP: %s\n", msgb_hexdump(msg));
		msgb_free(msg);
		return -ENOTSUP;
	}

	LOGP(DVLR, LOGL_DEBUG, "GSUP tx: %s\n",
	     osmo_hexdump_nospc(msg->data, msg->len));

	return osmo_gsup_client_send(vlr->gsup_client, msg);
}

/* Transmit GSUP message for subscriber to HLR, using IMSI from subscriber */
static int vlr_subscr_tx_gsup_message(const struct vlr_subscr *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr = vsub->vlr;

	if (strlen(gsup_msg->imsi) == 0)
		OSMO_STRLCPY_ARRAY(gsup_msg->imsi, vsub->imsi);

	return vlr_tx_gsup_message(vlr, gsup_msg);
}

/* Transmit GSUP error in response to original message */
static int vlr_tx_gsup_error_reply(const struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_orig,
				   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	OSMO_STRLCPY_ARRAY(gsup_reply.imsi, gsup_orig->imsi);
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return vlr_tx_gsup_message(vlr, &gsup_reply);
}

static int vlr_subscr_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct vlr_subscr *vsub = e->use_count->talloc_object;
	char buf[128];

	if (!e->use)
		return -EINVAL;

	LOGPSRC(DREF, LOGL_DEBUG, file, line, "VLR subscr %s %s %s: now used by %s\n",
		vlr_subscr_name(vsub), (e->count - old_use_count) > 0? "+" : "-", e->use,
		osmo_use_count_name_buf(buf, sizeof(buf), e->use_count));

	if (e->count < 0)
		return -ERANGE;

	if (osmo_use_count_total(e->use_count) <= 0)
		vlr_subscr_free(vsub);
	return 0;
}

/* Allocate a new subscriber and insert it into list */
static struct vlr_subscr *_vlr_subscr_alloc(struct vlr_instance *vlr)
{
	struct vlr_subscr *vsub;
	int i;

	vsub = talloc_zero(vlr, struct vlr_subscr);
	*vsub = (struct vlr_subscr){
		.vlr = vlr,
		.tmsi = GSM_RESERVED_TMSI,
		.tmsi_new = GSM_RESERVED_TMSI,
		.use_count = (struct osmo_use_count){
			.talloc_object = vsub,
			.use_cb = vlr_subscr_use_cb,
		},
	};
	osmo_use_count_make_static_entries(&vsub->use_count, vsub->use_count_buf, ARRAY_SIZE(vsub->use_count_buf));

	for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
		vsub->auth_tuples[i].key_seq = VLR_KEY_SEQ_INVAL;

	INIT_LLIST_HEAD(&vsub->cs.requests);
	INIT_LLIST_HEAD(&vsub->ps.pdp_list);

	/* Create an SGs FSM, which is needed to control CSFB,
	 * in cases where CSFB/SGs is not in use, this FSM will
	 * just do nothing. (see also: sgs_iface.c) */
	vlr_sgs_fsm_create(vsub);

	llist_add_tail(&vsub->list, &vlr->subscribers);
	return vsub;
}

/* Send a GSUP Purge MS request.
 * TODO: this should be sent to the *previous* VLR when this VLR is "taking"
 * this subscriber, not to the HLR? */
int vlr_subscr_purge(struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;

	/* provide HLR number in case we know it */
	gsup_msg.hlr_enc_len = vsub->hlr.len;
	gsup_msg.hlr_enc = vsub->hlr.buf;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

void vlr_subscr_cancel_attach_fsm(struct vlr_subscr *vsub,
				  enum osmo_fsm_term_cause fsm_cause,
				  uint8_t gsm48_cause)
{
	if (!vsub)
		return;

	vlr_subscr_get(vsub, __func__);
	if (vsub->lu_fsm)
		vlr_loc_update_cancel(vsub->lu_fsm, fsm_cause, gsm48_cause);
	if (vsub->proc_arq_fsm)
		vlr_parq_cancel(vsub->proc_arq_fsm, fsm_cause, gsm48_cause);
	vlr_subscr_put(vsub, __func__);
}

/* Call vlr_subscr_cancel(), then completely drop the entry from the VLR */
void vlr_subscr_free(struct vlr_subscr *vsub)
{
	llist_del(&vsub->list);
	DEBUGP(DREF, "freeing VLR subscr %s\n", vlr_subscr_name(vsub));

	/* Make sure SGs timer Ts5 is removed */
	osmo_timer_del(&vsub->sgs.Ts5);

	/* Remove SGs FSM (see also: sgs_iface.c) */
	vlr_sgs_fsm_remove(vsub);

	talloc_free(vsub);
}

/* Generate a new TMSI and store in vsub->tmsi_new.
 * Search all known subscribers to ensure that the TMSI is unique. */
int vlr_subscr_alloc_tmsi(struct vlr_subscr *vsub)
{
	struct vlr_instance *vlr = vsub->vlr;
	uint32_t tmsi;
	int tried, rc;
	struct vlr_subscr *other_vsub;

	for (tried = 0; tried < 100; tried++) {
		rc = osmo_get_rand_id((uint8_t *) &tmsi, sizeof(tmsi));
		if (rc < 0) {
			LOGP(DDB, LOGL_ERROR, "osmo_get_rand_id() failed: %s\n", strerror(-rc));
			return rc;
		}
		/* throw the dice again, if the TSMI doesn't fit */
		if (tmsi == GSM_RESERVED_TMSI)
			continue;

		/* Section 2.4 of 23.003: MSC has two MSB 00/01/10, SGSN 11 */
		if (vlr->cfg.is_ps) {
			/* SGSN */
			tmsi |= 0xC000000;
		} else {
			/* MSC */
			if ((tmsi & 0xC0000000) == 0xC0000000)
				tmsi &= ~0xC0000000;
		}

		/* If this TMSI is already in use, try another one. */
		if ((other_vsub = vlr_subscr_find_by_tmsi(vlr, tmsi, __func__))) {
			vlr_subscr_put(other_vsub, __func__);
			continue;
		}

		vsub->tmsi_new = tmsi;
		vsub->vlr->ops.subscr_update(vsub);
		return 0;
	}

	LOGP(DVLR, LOGL_ERROR, "subscr %s: unable to generate valid TMSI"
	     " after %d tries\n", vlr_subscr_name(vsub), tried);
	return -1;
}

/* Find subscriber by IMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instace.
 * \param[in] imsi  IMSI string.
 * \param[out] created  if non-NULL, returns whether a new entry was created. */
struct vlr_subscr *_vlr_subscr_find_or_create_by_imsi(struct vlr_instance *vlr,
						      const char *imsi,
						      const char *use,
						      bool *created,
						      const char *file,
						      int line)
{
	struct vlr_subscr *vsub;
	vsub = _vlr_subscr_find_by_imsi(vlr, imsi, use, file, line);
	if (vsub) {
		if (created)
			*created = false;
		return vsub;
	}

	vsub = _vlr_subscr_alloc(vlr);
	if (!vsub)
		return NULL;
	vlr_subscr_get_src(vsub, use, file, line);
	vlr_subscr_set_imsi(vsub, imsi);
	LOGP(DVLR, LOGL_INFO, "New subscr, IMSI: %s\n", vsub->imsi);
	if (created)
		*created = true;
	return vsub;
}

/* Find subscriber by TMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instace.
 * \param[in] tmsi  TMSI.
 * \param[out] created  if non-NULL, returns whether a new entry was created. */
struct vlr_subscr *_vlr_subscr_find_or_create_by_tmsi(struct vlr_instance *vlr,
						      uint32_t tmsi,
						      const char *use,
						      bool *created,
						      const char *file,
						      int line)
{
	struct vlr_subscr *vsub;
	vsub = _vlr_subscr_find_by_tmsi(vlr, tmsi, use, file, line);
	if (vsub) {
		if (created)
			*created = false;
		return vsub;
	}

	vsub = _vlr_subscr_alloc(vlr);
	if (!vsub)
		return NULL;
	vlr_subscr_get_src(vsub, use, file, line);
	vsub->tmsi = tmsi;
	LOGP(DVLR, LOGL_INFO, "New subscr, TMSI: 0x%08x\n", vsub->tmsi);
	if (created)
		*created = true;
	return vsub;
}

void vlr_subscr_set_imsi(struct vlr_subscr *vsub, const char *imsi)
{
	if (!vsub)
		return;

	if (OSMO_STRLCPY_ARRAY(vsub->imsi, imsi) >= sizeof(vsub->imsi)) {
		LOGP(DVLR, LOGL_NOTICE, "IMSI was truncated: full IMSI=%s, truncated IMSI=%s\n",
		       imsi, vsub->imsi);
		/* XXX Set truncated IMSI anyway, we currently cannot return an error from here. */
	}

	vsub->id = atoll(vsub->imsi);
	DEBUGP(DVLR, "set IMSI on subscriber; IMSI=%s id=%llu\n",
	       vsub->imsi, vsub->id);
}

void vlr_subscr_set_imei(struct vlr_subscr *vsub, const char *imei)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->imei, imei);
	DEBUGP(DVLR, "set IMEI on subscriber; IMSI=%s IMEI=%s\n",
	       vsub->imsi, vsub->imei);
}

void vlr_subscr_set_imeisv(struct vlr_subscr *vsub, const char *imeisv)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->imeisv, imeisv);
	DEBUGP(DVLR, "set IMEISV on subscriber; IMSI=%s IMEISV=%s\n",
	       vsub->imsi, vsub->imeisv);
}

/* Safely copy the given MSISDN string to vsub->msisdn */
void vlr_subscr_set_msisdn(struct vlr_subscr *vsub, const char *msisdn)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->msisdn, msisdn);
	DEBUGP(DVLR, "set MSISDN on subscriber; IMSI=%s MSISDN=%s\n",
	       vsub->imsi, vsub->msisdn);
}

bool vlr_subscr_matches_imsi(struct vlr_subscr *vsub, const char *imsi)
{
	return vsub && imsi && vsub->imsi[0] && !strcmp(vsub->imsi, imsi);
}

bool vlr_subscr_matches_tmsi(struct vlr_subscr *vsub, uint32_t tmsi)
{
	return vsub && tmsi != GSM_RESERVED_TMSI
		&& (vsub->tmsi == tmsi || vsub->tmsi_new == tmsi);
}

bool vlr_subscr_matches_msisdn(struct vlr_subscr *vsub, const char *msisdn)
{
	return vsub && msisdn && vsub->msisdn[0]
		&& !strcmp(vsub->msisdn, msisdn);
}

bool vlr_subscr_matches_imei(struct vlr_subscr *vsub, const char *imei)
{
	return vsub && imei && vsub->imei[0]
		&& !strcmp(vsub->imei, imei);
}

/* Send updated subscriber information to HLR */
int vlr_subscr_changed(struct vlr_subscr *vsub)
{
	/* FIXME */
	LOGP(DVLR, LOGL_ERROR, "Not implemented: %s\n", __func__);
	return 0;
}

void vlr_subscr_enable_expire_lu(struct vlr_subscr *vsub)
{
	struct gsm_network *net = vsub->vlr->user_ctx; /* XXX move t3212 into struct vlr_instance? */
	struct timespec now;

	/* The T3212 timeout value field is coded as the binary representation of the timeout
	 * value for periodic updating in decihours. Mark the subscriber as inactive if it missed
	 * two consecutive location updates. Timeout is twice the t3212 value plus one minute. */
	if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
		vsub->expire_lu = now.tv_sec + (net->t3212 * 60 * 6 * 2) + 60;
	} else {
		LOGP(DVLR, LOGL_ERROR,
		     "%s: Could not enable Location Update expiry: unable to read current time\n", vlr_subscr_name(vsub));
		/* Disable LU expiry for this subscriber. This subscriber will only be freed after an explicit IMSI detach. */
		vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;
	}
}

void vlr_subscr_expire_lu(void *data)
{
	struct vlr_instance *vlr = data;
	struct vlr_subscr *vsub, *vsub_tmp;
	struct timespec now;

	if (llist_empty(&vlr->subscribers))
		goto done;

	if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		LOGP(DVLR, LOGL_ERROR, "Skipping Location Update expiry: Could not read current time\n");
		goto done;
	}

	llist_for_each_entry_safe(vsub, vsub_tmp, &vlr->subscribers, list) {
		if (vsub->expire_lu == VLR_SUBSCRIBER_NO_EXPIRATION || vsub->expire_lu > now.tv_sec)
			continue;

		LOGP(DVLR, LOGL_DEBUG, "%s: Location Update expired\n", vlr_subscr_name(vsub));
		vlr_subscr_rx_imsi_detach(vsub);
	}

done:
	osmo_timer_schedule(&vlr->lu_expire_timer, VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL, 0);
}

/***********************************************************************
 * PDP context data
 ***********************************************************************/

#define GSM_APN_LENGTH 102

/* see GSM 09.02, 17.7.1, PDP-Context and GPRSSubscriptionData */
/* see GSM 09.02, B.1, gprsSubscriptionData */
struct sgsn_subscriber_pdp_data {
        struct llist_head       list;

        unsigned int            context_id;
        uint16_t                pdp_type;
        char                    apn_str[GSM_APN_LENGTH];
        uint8_t                 qos_subscribed[20];
        size_t                  qos_subscribed_len;
};

struct sgsn_subscriber_pdp_data *
vlr_subscr_pdp_data_alloc(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(vsub, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &vsub->ps.pdp_list);

	return pdata;
}

static int vlr_subscr_pdp_data_clear(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data *pdp, *pdp2;
	int count = 0;

	llist_for_each_entry_safe(pdp, pdp2, &vsub->ps.pdp_list, list) {
		llist_del(&pdp->list);
		talloc_free(pdp);
		count += 1;
	}

	return count;
}

static struct sgsn_subscriber_pdp_data *
vlr_subscr_pdp_data_get_by_id(struct vlr_subscr *vsub, unsigned context_id)
{
	struct sgsn_subscriber_pdp_data *pdp;

	llist_for_each_entry(pdp, &vsub->ps.pdp_list, list) {
		if (pdp->context_id == context_id)
			return pdp;
	}

	return NULL;
}

/***********************************************************************
 * Actual Implementation
 ***********************************************************************/

static int vlr_rx_gsup_unknown_imsi(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		int rc = vlr_tx_gsup_error_reply(vlr, gsup_msg, GMM_CAUSE_IMSI_UNKNOWN);
		if (rc < 0)
			LOGP(DVLR, LOGL_ERROR, "Failed to send error reply for IMSI %s\n", gsup_msg->imsi);

		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

static int vlr_rx_gsup_purge_no_subscr(struct vlr_instance *vlr,
				struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGGSUPP(LOGL_NOTICE, gsup_msg,
			 "Purge MS has failed with cause '%s' (%d)\n",
			 get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			 gsup_msg->cause);
		return -gsup_msg->cause;
	}
	LOGGSUPP(LOGL_INFO, gsup_msg, "Completing purge MS\n");
	return 0;
}

/* VLR internal call to request UpdateLocation from HLR */
int vlr_subscr_req_lu(struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};
	int rc;

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	gsup_msg.cn_domain = vsub->vlr->cfg.is_ps ? OSMO_GSUP_CN_DOMAIN_PS : OSMO_GSUP_CN_DOMAIN_CS;
	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_msg);

	return rc;
}

/* VLR internal call to request tuples from HLR */
int vlr_subscr_req_sai(struct vlr_subscr *vsub,
		       const uint8_t *auts, const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.auts = auts;
	gsup_msg.rand = auts_rand;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

/* Initiate Check_IMEI_VLR Procedure (23.018 Chapter 7.1.2.9) */
int vlr_subscr_tx_req_check_imei(const struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};
	uint8_t imei_enc[GSM23003_IMEI_NUM_DIGITS+2]; /* +2: IE header */
	int len;

	/* Encode IMEI */
	len = gsm48_encode_bcd_number(imei_enc, sizeof(imei_enc), 0, vsub->imei);
	if (len < 1) {
		LOGVSUBP(LOGL_ERROR, vsub, "Error: cannot encode IMEI '%s'\n", vsub->imei);
		return -ENOSPC;
	}
	gsup_msg.imei_enc = imei_enc;
	gsup_msg.imei_enc_len = len;

	/* Send CHECK_IMEI_REQUEST */
	gsup_msg.message_type = OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST;
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, vsub->imsi);
	return vlr_tx_gsup_message(vsub->vlr, &gsup_msg);
}

/* Tell HLR that authentication failure occurred */
int vlr_subscr_tx_auth_fail_rep(const struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_AUTH_FAIL_REPORT;
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, vsub->imsi);
	return vlr_tx_gsup_message(vsub->vlr, &gsup_msg);
}

/* Update the subscriber with GSUP-received auth tuples */
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup)
{
	unsigned int i;
	unsigned int got_tuples;

	if (gsup->num_auth_vectors) {
		memset(&vsub->auth_tuples, 0, sizeof(vsub->auth_tuples));
		for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
			vsub->auth_tuples[i].key_seq = VLR_KEY_SEQ_INVAL;
	}

	got_tuples = 0;
	for (i = 0; i < gsup->num_auth_vectors; i++) {
		size_t key_seq = i;

		if (key_seq >= ARRAY_SIZE(vsub->auth_tuples)) {
			LOGVSUBP(LOGL_NOTICE, vsub,
				"Skipping auth tuple wih invalid cksn %zu\n",
				key_seq);
			continue;
		}
		vsub->auth_tuples[i].vec = gsup->auth_vectors[i];
		vsub->auth_tuples[i].key_seq = key_seq;
		got_tuples++;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "Received %u auth tuples\n", got_tuples);

	if (!got_tuples) {
		/* FIXME what now? */
		// vlr_subscr_cancel(vsub, GMM_CAUSE_GSM_AUTH_UNACCEPT); ?
	}

	/* New tuples means last_tuple becomes invalid */
	vsub->last_tuple = NULL;
}

/* Handle SendAuthInfo Result/Error from HLR */
static int vlr_subscr_handle_sai_res(struct vlr_subscr *vsub,
				     const struct osmo_gsup_message *gsup)
{
	struct osmo_fsm_inst *auth_fi = vsub->auth_fsm;
	void *data = (void *) gsup;

	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_HLR_SAI_ACK, data);
		break;
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_HLR_SAI_NACK, data);
		break;
	default:
		return -1;
	}

	return 0;
}

static int decode_bcd_number_safe(char *output, int output_len,
				  const uint8_t *bcd_lv, int input_len,
				  int h_len)
{
	uint8_t len;
	OSMO_ASSERT(output_len >= 1);
	*output = '\0';
	if (input_len < 1)
		return -EIO;
	len = bcd_lv[0];
	if (input_len < len)
		return -EIO;
	return gsm48_decode_bcd_number(output, output_len, bcd_lv, h_len);
}

static void vlr_subscr_gsup_insert_data(struct vlr_subscr *vsub,
					const struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc) {//FIXME: vlr_subscr_set_msisdn()?
		decode_bcd_number_safe(vsub->msisdn, sizeof(vsub->msisdn),
				       gsup_msg->msisdn_enc,
				       gsup_msg->msisdn_enc_len, 0);
		LOGP(DVLR, LOGL_DEBUG, "IMSI:%s has MSISDN:%s\n",
		     vsub->imsi, vsub->msisdn);
	}

	if (gsup_msg->hlr_enc) {
		if (gsup_msg->hlr_enc_len > sizeof(vsub->hlr.buf)) {
			LOGP(DVLR, LOGL_ERROR, "HLR-Number too long (%zu)\n",
				gsup_msg->hlr_enc_len);
			vsub->hlr.len = 0;
		} else {
			memcpy(vsub->hlr.buf, gsup_msg->hlr_enc,
				gsup_msg->hlr_enc_len);
			vsub->hlr.len = gsup_msg->hlr_enc_len;
		}
	}

	if (gsup_msg->pdp_info_compl) {
		rc = vlr_subscr_pdp_data_clear(vsub);
		if (rc > 0)
			LOGP(DVLR, LOGL_INFO, "Cleared existing PDP info\n");
	}

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		const struct osmo_gsup_pdp_info *pdp_info = &gsup_msg->pdp_infos[idx];
		size_t ctx_id = pdp_info->context_id;
		struct sgsn_subscriber_pdp_data *pdp_data;

		if (pdp_info->apn_enc_len >= sizeof(pdp_data->apn_str)-1) {
			LOGVSUBP(LOGL_ERROR, vsub,
			     "APN too long, context id = %zu, APN = %s\n",
			     ctx_id, osmo_hexdump(pdp_info->apn_enc,
						  pdp_info->apn_enc_len));
			continue;
		}

		if (pdp_info->qos_enc_len > sizeof(pdp_data->qos_subscribed)) {
			LOGVSUBP(LOGL_ERROR, vsub,
				"QoS info too long (%zu)\n",
				pdp_info->qos_enc_len);
			continue;
		}

		LOGVSUBP(LOGL_INFO, vsub,
		     "Will set PDP info, context id = %zu, APN = %s\n",
		     ctx_id, osmo_hexdump(pdp_info->apn_enc, pdp_info->apn_enc_len));

		/* Set PDP info [ctx_id] */
		pdp_data = vlr_subscr_pdp_data_get_by_id(vsub, ctx_id);
		if (!pdp_data) {
			pdp_data = vlr_subscr_pdp_data_alloc(vsub);
			pdp_data->context_id = ctx_id;
		}

		OSMO_ASSERT(pdp_data != NULL);
		pdp_data->pdp_type = pdp_info->pdp_type;
		osmo_apn_to_str(pdp_data->apn_str,
				pdp_info->apn_enc, pdp_info->apn_enc_len);
		memcpy(pdp_data->qos_subscribed, pdp_info->qos_enc, pdp_info->qos_enc_len);
		pdp_data->qos_subscribed_len = pdp_info->qos_enc_len;
	}
}


/* Handle InsertSubscrData Result from HLR */
static int vlr_subscr_handle_isd_req(struct vlr_subscr *vsub,
				     const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};

	vlr_subscr_gsup_insert_data(vsub, gsup);
	vsub->vlr->ops.subscr_update(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return vlr_subscr_tx_gsup_message(vsub, &gsup_reply);
}

/* Handle UpdateLocation Result from HLR */
static int vlr_subscr_handle_lu_res(struct vlr_subscr *vsub,
				    const struct osmo_gsup_message *gsup)
{
	struct sgs_lu_response sgs_lu_response;
	bool sgs_lu_in_progress = false;

	if (vsub->sgs_fsm->state == SGS_UE_ST_LA_UPD_PRES)
		sgs_lu_in_progress = true;

	if (!vsub->lu_fsm && !sgs_lu_in_progress) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP LU Result "
			 "without LU in progress\n");
		return -ENODEV;
	}

	/* contrary to MAP, we allow piggy-backing subscriber data onto the
	 * UPDATE LOCATION RESULT, and don't mandate the use of a separate
	 * nested INSERT SUBSCRIBER DATA transaction */
	vlr_subscr_gsup_insert_data(vsub, gsup);

	if (sgs_lu_in_progress) {
		sgs_lu_response.accepted = true;
		sgs_lu_response.vsub = vsub;
		vsub->sgs.response_cb(&sgs_lu_response);
	} else
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES, NULL);

	return 0;
}

/* Handle UpdateLocation Result from HLR */
static int vlr_subscr_handle_lu_err(struct vlr_subscr *vsub,
				    const struct osmo_gsup_message *gsup)
{
	struct sgs_lu_response sgs_lu_response;
	bool sgs_lu_in_progress = false;

	if (vsub->sgs_fsm->state == SGS_UE_ST_LA_UPD_PRES)
		sgs_lu_in_progress = true;

	if (!vsub->lu_fsm && !sgs_lu_in_progress) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP LU Error "
			 "without LU in progress\n");
		return -ENODEV;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "UpdateLocation failed; gmm_cause: %s\n",
		 get_value_string(gsm48_gmm_cause_names, gsup->cause));

	if (sgs_lu_in_progress) {
		sgs_lu_response.accepted = false;
		sgs_lu_response.vsub = vsub;
		vsub->sgs.response_cb(&sgs_lu_response);
	} else
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES,
					(void *)&gsup->cause);
	return 0;
}

static void gmm_cause_to_fsm_and_mm_cause(enum gsm48_gmm_cause gmm_cause,
					  enum osmo_fsm_term_cause *fsm_cause_p,
					  enum gsm48_reject_value *gsm48_rej_p)
{
	enum osmo_fsm_term_cause fsm_cause = OSMO_FSM_TERM_ERROR;
	enum gsm48_reject_value gsm48_rej = GSM48_REJECT_NETWORK_FAILURE;
	switch (gmm_cause) {
	case GMM_CAUSE_IMSI_UNKNOWN:
		gsm48_rej = GSM48_REJECT_IMSI_UNKNOWN_IN_HLR;
		break;
	case GMM_CAUSE_ILLEGAL_MS:
		gsm48_rej = GSM48_REJECT_ILLEGAL_MS;
		break;
	case GMM_CAUSE_IMEI_NOT_ACCEPTED:
		gsm48_rej = GSM48_REJECT_IMEI_NOT_ACCEPTED;
		break;
	case GMM_CAUSE_ILLEGAL_ME:
		gsm48_rej = GSM48_REJECT_ILLEGAL_ME;
		break;
	case GMM_CAUSE_GPRS_NOTALLOWED:
		gsm48_rej = GSM48_REJECT_GPRS_NOT_ALLOWED;
		break;
	case GMM_CAUSE_GPRS_OTHER_NOTALLOWED:
		gsm48_rej = GSM48_REJECT_SERVICES_NOT_ALLOWED;
		break;
	case GMM_CAUSE_MS_ID_NOT_DERIVED:
		gsm48_rej = GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE;
		break;
	case GMM_CAUSE_IMPL_DETACHED:
		gsm48_rej = GSM48_REJECT_IMPLICITLY_DETACHED;
		break;
	case GMM_CAUSE_PLMN_NOTALLOWED:
		gsm48_rej = GSM48_REJECT_PLMN_NOT_ALLOWED;
		break;
	case GMM_CAUSE_LA_NOTALLOWED:
		gsm48_rej = GSM48_REJECT_LOC_NOT_ALLOWED;
		break;
	case GMM_CAUSE_ROAMING_NOTALLOWED:
		gsm48_rej = GSM48_REJECT_ROAMING_NOT_ALLOWED;
		break;
	case GMM_CAUSE_NO_GPRS_PLMN:
		gsm48_rej = GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN;
		break;
	case GMM_CAUSE_MSC_TEMP_NOTREACH:
		gsm48_rej = GSM48_REJECT_MSC_TMP_NOT_REACHABLE;
		break;
	case GMM_CAUSE_SYNC_FAIL:
		gsm48_rej = GSM48_REJECT_SYNCH_FAILURE;
		break;
	case GMM_CAUSE_CONGESTION:
		gsm48_rej = GSM48_REJECT_CONGESTION;
		break;
	case GMM_CAUSE_SEM_INCORR_MSG:
		gsm48_rej = GSM48_REJECT_INCORRECT_MESSAGE;
		break;
	case GMM_CAUSE_INV_MAND_INFO:
		gsm48_rej = GSM48_REJECT_INVALID_MANDANTORY_INF;
		break;
	case GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL:
		gsm48_rej = GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED;
		break;
	case GMM_CAUSE_MSGT_INCOMP_P_STATE:
		gsm48_rej = GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE;
		break;
	case GMM_CAUSE_IE_NOTEXIST_NOTIMPL:
		gsm48_rej = GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED;
		break;
	case GMM_CAUSE_COND_IE_ERR:
		gsm48_rej = GSM48_REJECT_CONDTIONAL_IE_ERROR;
		break;
	case GMM_CAUSE_MSG_INCOMP_P_STATE:
		gsm48_rej = GSM48_REJECT_MSG_NOT_COMPATIBLE;
		break;
	case GMM_CAUSE_PROTO_ERR_UNSPEC:
		gsm48_rej = GSM48_REJECT_PROTOCOL_ERROR;
		break;

	case GMM_CAUSE_NO_SUIT_CELL_IN_LA:
	case GMM_CAUSE_MAC_FAIL:
	case GMM_CAUSE_GSM_AUTH_UNACCEPT:
	case GMM_CAUSE_NOT_AUTH_FOR_CSG:
	case GMM_CAUSE_SMS_VIA_GPRS_IN_RA:
	case GMM_CAUSE_NO_PDP_ACTIVATED:
	case GMM_CAUSE_NET_FAIL:
		gsm48_rej = GSM48_REJECT_NETWORK_FAILURE;
		break;
	}
	switch (gmm_cause) {
		/* refine any error causes here? */
	default:
		fsm_cause = OSMO_FSM_TERM_ERROR;
		break;
	}
	if (fsm_cause_p)
		*fsm_cause_p = fsm_cause;
	if (gsm48_rej_p)
		*gsm48_rej_p = gsm48_rej;
}

/* Handle LOCATION CANCEL request from HLR */
static int vlr_subscr_handle_cancel_req(struct vlr_subscr *vsub,
					struct osmo_gsup_message *gsup_msg)
{
	enum gsm48_reject_value gsm48_rej;
	enum osmo_fsm_term_cause fsm_cause;
	struct osmo_gsup_message gsup_reply = {0};
	int rc, is_update_procedure = !gsup_msg->cancel_type ||
		gsup_msg->cancel_type == OSMO_GSUP_CANCEL_TYPE_UPDATE;

	LOGVSUBP(LOGL_INFO, vsub, "Cancelling MS subscriber (%s)\n",
		 is_update_procedure ?
		 "update procedure" : "subscription withdraw");

	gsup_reply.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_reply);

	gmm_cause_to_fsm_and_mm_cause(gsup_msg->cause, &fsm_cause, &gsm48_rej);
	vlr_subscr_cancel_attach_fsm(vsub, fsm_cause, gsm48_rej);

	vlr_subscr_rx_imsi_detach(vsub);

	return rc;
}

/* Handle Check_IMEI_VLR result and error from HLR */
static int vlr_subscr_handle_check_imei(struct vlr_subscr *vsub, const struct osmo_gsup_message *gsup)
{
	if (!vsub->lu_fsm) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx %s without LU in progress\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		return -ENODEV;
	}

	if (gsup->message_type == OSMO_GSUP_MSGT_CHECK_IMEI_RESULT) {
		if (gsup->imei_result == OSMO_GSUP_IMEI_RESULT_ACK)
			osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_IMEI_ACK, NULL);
		else
			osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_IMEI_NACK, NULL);
	} else {
		LOGVSUBP(LOGL_ERROR, vsub, "Check_IMEI_VLR failed; gmm_cause: %s\n",
			 get_value_string(gsm48_gmm_cause_names, gsup->cause));
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_IMEI_NACK, NULL);
	}

	return 0;
}

/* Incoming handler for GSUP from HLR.
 * Keep this function non-static for direct invocation by unit tests. */
int vlr_gsupc_read_cb(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct vlr_instance *vlr = (struct vlr_instance *) gsupc->data;
	struct vlr_subscr *vsub;
	struct osmo_gsup_message gsup;
	int rc;

	DEBUGP(DVLR, "GSUP rx %u: %s\n", msgb_l2len(msg),
	       osmo_hexdump_nospc(msgb_l2(msg), msgb_l2len(msg)));

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DVLR, LOGL_ERROR,
			"decoding GSUP message fails with error '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		goto msgb_free_and_return;
	}

	if (!gsup.imsi[0]) {
		LOGP(DVLR, LOGL_ERROR, "Missing IMSI in GSUP message\n");
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup.message_type)) {
			rc = vlr_tx_gsup_error_reply(vlr, &gsup, GMM_CAUSE_INV_MAND_INFO);
			if (rc < 0)
				LOGP(DVLR, LOGL_ERROR, "Failed to send error reply for IMSI %s\n", gsup.imsi);
		}
		rc = -GMM_CAUSE_INV_MAND_INFO;
		goto msgb_free_and_return;
	}

	vsub = vlr_subscr_find_by_imsi(vlr, gsup.imsi, __func__);
	if (!vsub) {
		switch (gsup.message_type) {
		case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
			rc = vlr_rx_gsup_purge_no_subscr(vlr, &gsup);
			goto msgb_free_and_return;
		default:
			rc = vlr_rx_gsup_unknown_imsi(vlr, &gsup);
			goto msgb_free_and_return;
		}
	}

	switch (gsup.message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = vlr_subscr_handle_sai_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		rc = vlr_subscr_handle_isd_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = vlr_subscr_handle_cancel_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = vlr_subscr_handle_lu_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = vlr_subscr_handle_lu_err(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		LOGVSUBP(LOGL_ERROR, vsub,
			"Rx GSUP msg_type=%d not yet implemented\n",
			gsup.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	case OSMO_GSUP_MSGT_CHECK_IMEI_ERROR:
	case OSMO_GSUP_MSGT_CHECK_IMEI_RESULT:
		rc = vlr_subscr_handle_check_imei(vsub, &gsup);
		break;
	default:
		/* Forward message towards MSC */
		rc = vlr->ops.forward_gsup_msg(vsub, &gsup);
		break;
	}

	vlr_subscr_put(vsub, __func__);

msgb_free_and_return:
	msgb_free(msg);
	return rc;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_subscr_rx_id_resp(struct vlr_subscr *vsub,
			  const uint8_t *mi, size_t mi_len)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type = mi[0] & GSM_MI_TYPE_MASK;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	/* update the vlr_subscr with the given identity */
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (strlen(mi_string) >= sizeof(vsub->imsi)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP too long (>%zu bytes): %s\n",
				 sizeof(vsub->imsi) - 1, mi_string);
			return -ENOSPC; /* ignore message; do not avance LU FSM */
		} else if (vsub->imsi[0]
		    && !vlr_subscr_matches_imsi(vsub, mi_string)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi_string);
			/* XXX Should we return an error, e.g. -EINVAL ? */
		} else
			vlr_subscr_set_imsi(vsub, mi_string);
		break;
	case GSM_MI_TYPE_IMEI:
		vlr_subscr_set_imei(vsub, mi_string);
		break;
	case GSM_MI_TYPE_IMEISV:
		vlr_subscr_set_imeisv(vsub, mi_string);
		break;
	}

	if (vsub->auth_fsm) {
		switch (mi_type) {
		case GSM_MI_TYPE_IMSI:
			osmo_fsm_inst_dispatch(vsub->auth_fsm,
					VLR_AUTH_E_MS_ID_IMSI, mi_string);
			break;
		}
	}

	if (vsub->lu_fsm) {
		uint32_t event = 0;
		switch (mi_type) {
		case GSM_MI_TYPE_IMSI:
			event = VLR_ULA_E_ID_IMSI;
			break;
		case GSM_MI_TYPE_IMEI:
			event = VLR_ULA_E_ID_IMEI;
			break;
		case GSM_MI_TYPE_IMEISV:
			event = VLR_ULA_E_ID_IMEISV;
			break;
		default:
			OSMO_ASSERT(0);
			break;
		}
		osmo_fsm_inst_dispatch(vsub->lu_fsm, event, mi_string);
	} else {
		LOGVSUBP(LOGL_NOTICE,  vsub, "gratuitous ID RESPONSE?!?\n");
	}

	return 0;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_subscr_rx_tmsi_reall_compl(struct vlr_subscr *vsub)
{
	if (vsub->lu_fsm) {
		return osmo_fsm_inst_dispatch(vsub->lu_fsm,
					      VLR_ULA_E_NEW_TMSI_ACK, NULL);
	} else if (vsub->proc_arq_fsm) {
		return osmo_fsm_inst_dispatch(vsub->proc_arq_fsm,
					      PR_ARQ_E_TMSI_ACK, NULL);
	} else {
		LOGVSUBP(LOGL_NOTICE, vsub,
			 "gratuitous TMSI REALLOC COMPL");
		return -EINVAL;
	}
}

bool vlr_subscr_expire(struct vlr_subscr *vsub)
{
	if (vsub->lu_complete) {
		/* balancing the get from vlr_lu_compl_fsm_success() */
		vsub->lu_complete = false;
		vlr_subscr_put(vsub, VSUB_USE_ATTACHED);

		return true;
	}

	return false;
}

/* See TS 23.012 version 9.10.0 4.3.2.1 "Process Detach_IMSI_VLR" */
int vlr_subscr_rx_imsi_detach(struct vlr_subscr *vsub)
{
	/* paranoia: should any LU or PARQ FSMs still be running, stop them. */
	vlr_subscr_cancel_attach_fsm(vsub, OSMO_FSM_TERM_ERROR, GSM48_REJECT_CONGESTION);

	vsub->imsi_detached_flag = true;
	vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;

	/* Inform the UE-SGs FSM that the subscriber has been detached */
	osmo_fsm_inst_dispatch(vsub->sgs_fsm, SGS_UE_E_RX_DETACH_IND_FROM_UE, NULL);

	vlr_subscr_expire(vsub);

	return 0;
}

/* Tear down any running FSMs due to MSC connection timeout.
 * Visit all vsub->*_fsm pointers and give them a queue to send a final reject
 * message before the entire connection is torn down.
 * \param[in] vsub  subscriber to tear down
 */
void vlr_ran_conn_timeout(struct vlr_subscr *vsub)
{
	vlr_subscr_cancel_attach_fsm(vsub, OSMO_FSM_TERM_TIMEOUT, GSM48_REJECT_CONGESTION);
}

struct vlr_instance *vlr_alloc(void *ctx, const struct vlr_ops *ops)
{
	struct vlr_instance *vlr = talloc_zero(ctx, struct vlr_instance);
	OSMO_ASSERT(vlr);

	/* Some of these are needed only on UTRAN, but in case the caller wants
	 * only GERAN, she should just provide dummy callbacks. */
	OSMO_ASSERT(ops->tx_auth_req);
	OSMO_ASSERT(ops->tx_auth_rej);
	OSMO_ASSERT(ops->tx_id_req);
	OSMO_ASSERT(ops->tx_lu_acc);
	OSMO_ASSERT(ops->tx_lu_rej);
	OSMO_ASSERT(ops->tx_cm_serv_acc);
	OSMO_ASSERT(ops->tx_cm_serv_rej);
	OSMO_ASSERT(ops->set_ciph_mode);
	OSMO_ASSERT(ops->tx_common_id);
	OSMO_ASSERT(ops->subscr_update);
	OSMO_ASSERT(ops->subscr_assoc);
	OSMO_ASSERT(ops->forward_gsup_msg);

	INIT_LLIST_HEAD(&vlr->subscribers);
	INIT_LLIST_HEAD(&vlr->operations);
	memcpy(&vlr->ops, ops, sizeof(vlr->ops));

	/* defaults */
	vlr->cfg.assign_tmsi = true;

	/* osmo_auth_fsm.c */
	osmo_fsm_register(&vlr_auth_fsm);
	/* osmo_lu_fsm.c */
	vlr_lu_fsm_init();
	/* vlr_access_request_fsm.c */
	vlr_parq_fsm_init();
	/* vlr_sgs_fsm.c */
	vlr_sgs_fsm_init();

	return vlr;
}

int vlr_start(struct ipaccess_unit *ipa_dev, struct vlr_instance *vlr,
	      const char *gsup_server_addr_str, uint16_t gsup_server_port)
{
	OSMO_ASSERT(vlr);

	vlr->gsup_client = osmo_gsup_client_create2(vlr, ipa_dev,
						    gsup_server_addr_str,
						    gsup_server_port,
						    &vlr_gsupc_read_cb, NULL);
	if (!vlr->gsup_client)
		return -ENOMEM;
	vlr->gsup_client->data = vlr;

	osmo_timer_setup(&vlr->lu_expire_timer, vlr_subscr_expire_lu, vlr);
	osmo_timer_schedule(&vlr->lu_expire_timer, VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL, 0);
	return 0;
}

/* MSC->VLR: Subscribre has disconnected */
int vlr_subscr_disconnected(struct vlr_subscr *vsub)
{
	/* This corresponds to a MAP-ABORT from MSC->VLR on a classic B
	 * interface */
	osmo_fsm_inst_term(vsub->lu_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	osmo_fsm_inst_term(vsub->auth_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	vsub->msc_conn_ref = NULL;

	return 0;
}

/* MSC->VLR: Receive Authentication Failure from Subscriber */
int vlr_subscr_rx_auth_fail(struct vlr_subscr *vsub, const uint8_t *auts)
{
	struct vlr_auth_resp_par par = {0};
	par.auts = auts;

	osmo_fsm_inst_dispatch(vsub->auth_fsm, VLR_AUTH_E_MS_AUTH_FAIL, &par);
	return 0;
}

/* MSC->VLR: Receive Authentication Response from MS
 * \returns 1 in case of success, 0 in case of delay, -1 on auth error */
int vlr_subscr_rx_auth_resp(struct vlr_subscr *vsub, bool is_r99,
			 bool is_utran, const uint8_t *res, uint8_t res_len)
{
	struct osmo_fsm_inst *auth_fi = vsub->auth_fsm;
	struct vlr_auth_resp_par par;

	par.is_r99 = is_r99;
	par.is_utran = is_utran;
	par.res = res;
	par.res_len = res_len;
	osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_MS_AUTH_RESP, (void *) &par);

	return 0;
}

/* MSC->VLR: Receive result of Ciphering Mode Command from MS */
void vlr_subscr_rx_ciph_res(struct vlr_subscr *vsub, struct vlr_ciph_result *res)
{
	if (vsub->lu_fsm && vsub->lu_fsm->state == VLR_ULA_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_CIPH_RES, res);
	if (vsub->proc_arq_fsm
	    && vsub->proc_arq_fsm->state == PR_ARQ_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->proc_arq_fsm, PR_ARQ_E_CIPH_RES,
				       res);
}

/* Internal evaluation of requested ciphering mode.
 * Send set_ciph_mode() to MSC depending on the ciph_mode argument.
 * \param[in] vlr  VLR instance.
 * \param[in] fi  Calling FSM instance, for logging.
 * \param[in] msc_conn_ref  MSC conn to send to.
 * \param[in] ciph_mode  Ciphering config, to decide whether to do ciphering.
 * \returns 0 if no ciphering is needed or message was sent successfully,
 *          or a negative value if ciph_mode is invalid or sending failed.
 */
int vlr_set_ciph_mode(struct vlr_instance *vlr,
		      struct osmo_fsm_inst *fi,
		      void *msc_conn_ref,
		      bool ciph_required,
		      bool umts_aka,
		      bool retrieve_imeisv)
{
	if (!ciph_required)
		return 0;

	LOGPFSML(fi, LOGL_DEBUG, "Set Ciphering Mode\n");
	return vlr->ops.set_ciph_mode(msc_conn_ref, umts_aka, retrieve_imeisv);
}

/* Decide whether UMTS AKA should be used.
 * UTRAN networks are by definition R99 capable, and the auth vector is required to contain UMTS AKA
 * tokens. This is expected to be verified by the caller. On GERAN, UMTS AKA must be used iff MS and
 * GERAN are R99 capable and UMTS AKA tokens are available.
 * \param[in] vec  Auth tokens (received from the HLR).
 * \param[in] is_r99  True when BTS and GERAN are R99 capable.
 * \returns true to use UMTS AKA, false to use pre-R99 GSM AKA.
 */
bool vlr_use_umts_aka(struct osmo_auth_vector *vec, bool is_r99)
{
	if (!is_r99)
		return false;
	if (!(vec->auth_types & OSMO_AUTH_TYPE_UMTS))
		return false;
	return true;
}

void log_set_filter_vlr_subscr(struct log_target *target,
			       struct vlr_subscr *vlr_subscr)
{
	struct vlr_subscr **fsub = (void*)&target->filter_data[LOG_FLT_VLR_SUBSCR];
	const char *use = "logfilter";

	/* free the old data */
	if (*fsub) {
		vlr_subscr_put(*fsub, use);
		*fsub = NULL;
	}

	if (vlr_subscr) {
		target->filter_map |= (1 << LOG_FLT_VLR_SUBSCR);
		vlr_subscr_get(vlr_subscr, use);
		*fsub = vlr_subscr;
	} else
		target->filter_map &= ~(1 << LOG_FLT_VLR_SUBSCR);
}
