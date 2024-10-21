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
#include <osmocom/core/stats.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsm23236.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/vlr/vlr_sgs.h>
#include <osmocom/vlr/vlr.h>
#include <osmocom/msc/gsup_client_mux.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"
#include "vlr_lu_fsm.h"
#include "vlr_access_req_fsm.h"
#include "vlr_sgs_fsm.h"

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

enum vlr_stat_item_idx {
	VLR_STAT_SUBSCRIBER_COUNT,
	VLR_STAT_PDP_COUNT,
};

static const struct osmo_stat_item_desc vlr_stat_item_desc[] = {
	[VLR_STAT_SUBSCRIBER_COUNT] =		{ "subscribers",
		"Number of subscribers present in VLR" },
	[VLR_STAT_PDP_COUNT] =			{ "pdp",
		"Number of PDP records present in VLR" },
};

static const struct osmo_stat_item_group_desc vlr_statg_desc = {
	"vlr",
	"visitor location register",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(vlr_stat_item_desc),
	vlr_stat_item_desc,
};

enum vlr_rate_ctr_idx {
	VLR_CTR_GSUP_RX_UNKNOWN_IMSI,
	VLR_CTR_GSUP_RX_PURGE_NO_SUBSCR,
	VLR_CTR_GSUP_RX_TUPLES,
	VLR_CTR_GSUP_RX_UL_RES,
	VLR_CTR_GSUP_RX_UL_ERR,
	VLR_CTR_GSUP_RX_SAI_RES,
	VLR_CTR_GSUP_RX_SAI_ERR,
	VLR_CTR_GSUP_RX_ISD_REQ,
	VLR_CTR_GSUP_RX_CANCEL_REQ,
	VLR_CTR_GSUP_RX_CHECK_IMEI_RES,
	VLR_CTR_GSUP_RX_CHECK_IMEI_ERR,
	VLR_CTR_GSUP_RX_PURGE_MS_RES,
	VLR_CTR_GSUP_RX_PURGE_MS_ERR,
	VLR_CTR_GSUP_RX_DELETE_DATA_REQ,
	VLR_CTR_GSUP_RX_UNKNOWN,

	VLR_CTR_GSUP_TX_UL_REQ,
	VLR_CTR_GSUP_TX_ISD_RES,
	VLR_CTR_GSUP_TX_SAI_REQ,
	VLR_CTR_GSUP_TX_PURGE_MS_REQ,
	VLR_CTR_GSUP_TX_CHECK_IMEI_REQ,
	VLR_CTR_GSUP_TX_AUTH_FAIL_REP,
	VLR_CTR_GSUP_TX_CANCEL_RES,

	VLR_CTR_DETACH_BY_REQ,
	VLR_CTR_DETACH_BY_CANCEL,
	VLR_CTR_DETACH_BY_T3212,
};

static const struct rate_ctr_desc vlr_ctr_desc[] = {
	[VLR_CTR_GSUP_RX_UNKNOWN_IMSI] =	{ "gsup:rx:unknown_imsi",
		"Received GSUP messages for unknown IMSI" },
	[VLR_CTR_GSUP_RX_PURGE_NO_SUBSCR] =	{ "gsup:rx:purge_no_subscr",
		"Received GSUP purge for unknown subscriber" },
	[VLR_CTR_GSUP_RX_TUPLES] =		{ "gsup:rx:auth_tuples",
		"Received GSUP authentication tuples" },
	[VLR_CTR_GSUP_RX_UL_RES] =		{ "gsup:rx:upd_loc:res",
		"Received GSUP Update Location Result messages" },
	[VLR_CTR_GSUP_RX_UL_ERR] =		{ "gsup:rx:upd_loc:err",
		"Received GSUP Update Location Error messages" },
	[VLR_CTR_GSUP_RX_SAI_RES] =		{ "gsup:rx:send_auth_info:res",
		"Received GSUP Send Auth Info Result messages" },
	[VLR_CTR_GSUP_RX_SAI_ERR] =		{ "gsup:rx:send_auth_info:err",
		"Received GSUP Send Auth Info Error messages" },
	[VLR_CTR_GSUP_RX_ISD_REQ] =		{ "gsup:rx:ins_sub_data:req",
		"Received GSUP Insert Subscriber Data Request messages" },
	[VLR_CTR_GSUP_RX_CANCEL_REQ] =		{ "gsup:rx:cancel:req",
		"Received GSUP Cancel Subscriber messages" },
	[VLR_CTR_GSUP_RX_CHECK_IMEI_RES] =	{ "gsup:rx:check_imei:res",
		"Received GSUP Check IMEI Result messages" },
	[VLR_CTR_GSUP_RX_CHECK_IMEI_ERR] =	{ "gsup:rx:check_imei:err",
		"Received GSUP Check IMEI Error messages" },
	[VLR_CTR_GSUP_RX_PURGE_MS_RES] =	{ "gsup:rx:purge_ms:res",
		"Received GSUP Purge MS Result messages" },
	[VLR_CTR_GSUP_RX_PURGE_MS_ERR] =	{ "gsup:rx:purge_ms:err",
		"Received GSUP Purge MS Error messages" },
	[VLR_CTR_GSUP_RX_DELETE_DATA_REQ] =	{ "gsup:rx:del_sub_data:req",
		"Received GSUP Delete Subscriber Data Request messages" },
	[VLR_CTR_GSUP_RX_UNKNOWN] =		{ "gsup:rx:unknown_msgtype",
		"Received GSUP message of unknown type" },

	[VLR_CTR_GSUP_TX_UL_REQ] =		{ "gsup:tx:upd_loc:req",
		"Transmitted GSUP Update Location Request messages" },
	[VLR_CTR_GSUP_TX_ISD_RES] =		{ "gsup:tx:ins_sub_data:res",
		"Transmitted GSUP Insert Subscriber Data Result messages" },
	[VLR_CTR_GSUP_TX_SAI_REQ] =		{ "gsup:tx:send_auth_info:res",
		"Transmitted GSUP Send Auth Info Request messages" },
	[VLR_CTR_GSUP_TX_PURGE_MS_REQ] =	{ "gsup:tx:purge_ms:req",
		"Transmitted GSUP Purge MS Request messages" },
	[VLR_CTR_GSUP_TX_CHECK_IMEI_REQ] =	{ "gsup:tx:check_imei:req",
		"Transmitted GSUP Check IMEI Request messages" },
	[VLR_CTR_GSUP_TX_AUTH_FAIL_REP] =	{ "gsup:tx:auth_fail:rep",
		"Transmitted GSUP Auth Fail Report messages" },
	[VLR_CTR_GSUP_TX_CANCEL_RES] =		{ "gsup:tx:cancel:res",
		"Transmitted GSUP Cancel Result messages" },

	[VLR_CTR_DETACH_BY_REQ] =		{ "detach:imsi_det_req",
		"VLR Subscriber Detach by IMSI DETACH REQ" },
	[VLR_CTR_DETACH_BY_CANCEL] =		{ "detach:gsup_cancel_req",
		"VLR Subscriber Detach by GSUP CANCEL REQ" },
	[VLR_CTR_DETACH_BY_T3212] =		{ "detach:t3212_timeout",
		"VLR Subscriber Detach by T3212 timeout" },
};

static const struct rate_ctr_group_desc vlr_ctrg_desc = {
	"vlr",
	"visitor location register",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(vlr_ctr_desc),
	vlr_ctr_desc,
};


#define vlr_rate_ctr_inc(vlr, idx) \
	rate_ctr_inc(rate_ctr_group_get_ctr((vlr)->ctrg, idx))
#define vlr_rate_ctr_add(vlr, idx, val) \
	rate_ctr_add(rate_ctr_group_get_ctr((vlr)->ctrg, idx), val)

#define vlr_stat_item_inc(vlr, idx) \
	osmo_stat_item_inc(osmo_stat_item_group_get_item((vlr)->statg, idx), 1)
#define vlr_stat_item_dec(vlr, idx) \
	osmo_stat_item_dec(osmo_stat_item_group_get_item((vlr)->statg, idx), 1)
#define vlr_stat_item_set(vlr, idx, val) \
	osmo_stat_item_set(osmo_stat_item_group_get_item((vlr)->statg, idx), val)

/***********************************************************************
 * Convenience functions
 ***********************************************************************/

static int vlr_subscr_detach(struct vlr_subscr *vsub);

const struct value_string vlr_ciph_names[] = {
	OSMO_VALUE_STRING(VLR_CIPH_NONE),
	OSMO_VALUE_STRING(VLR_CIPH_A5_1),
	OSMO_VALUE_STRING(VLR_CIPH_A5_2),
	OSMO_VALUE_STRING(VLR_CIPH_A5_3),
	{ 0, NULL }
};

/* 3GPP TS 24.008, table 11.2 Mobility management timers (network-side) */
struct osmo_tdef msc_tdefs_vlr[] = {
	{ .T = 3212, .default_val = 60, .unit = OSMO_TDEF_M, .desc = "Subscriber expiration timeout" },
	{ .T = 3250, .default_val = 12, .desc = "TMSI Reallocation procedure" },
	{ .T = 3260, .default_val = 12, .desc = "Authentication procedure" },
	{ .T = 3270, .default_val = 12, .desc = "Identification procedure" },
	{ /* terminator */ }
};

/* 3GPP TS 24.008, table 11.2 Mobility management timers (network-side) */
struct osmo_tdef sgsn_tdefs_vlr[] = {
	{ .T = 3312, .default_val = 60, .unit = OSMO_TDEF_M, .desc = "Subscriber expiration timeout" },
	{ .T = 3350, .default_val = 6, .desc = "Attach/RAU Complete Reallocation procedure" },
	{ .T = 3360, .default_val = 6, .desc = "Authentication procedure" },
	{ .T = 3370, .default_val = 6, .desc = "Identification procedure" },
	{ /* terminator */ }
};

struct osmo_tdef *vlr_tdefs;

/* This is just a wrapper around the osmo_tdef API.
 * TODO: we should start using osmo_tdef_fsm_inst_state_chg() */
unsigned long vlr_timer_secs(struct vlr_instance *vlr, int cs_timer, int ps_timer)
{
	/* NOTE: since we usually do not need more than one instance of the VLR,
	 * and since libosmocore's osmo_tdef API does not (yet) support dynamic
	 * configuration, we always use the global instance of msc_tdefs_vlr. */
	if (vlr_is_cs(vlr))
		return osmo_tdef_get(vlr_tdefs, cs_timer, OSMO_TDEF_S, 0);
	else
		return osmo_tdef_get(vlr_tdefs, ps_timer, OSMO_TDEF_S, 0);
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

const char *vlr_subscr_short_name(const struct vlr_subscr *vsub, unsigned int maxlen)
{
	/* cast away the const so we can shorten the string within the static buffer */
	char *name = (char*)vlr_subscr_name(vsub);
	size_t len = strlen(name);
	if (maxlen < 2)
		return "-";
	if (len > maxlen)
		strcpy(name + maxlen - 2, "..");
	return name;
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
			if (use)
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

struct vlr_subscr *_vlr_subscr_find_by_mi(struct vlr_instance *vlr,
					  const struct osmo_mobile_identity *mi,
					  const char *use,
					  const char *file, int line)
{
	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		return _vlr_subscr_find_by_imsi(vlr, mi->imsi, use, file, line);
	case GSM_MI_TYPE_TMSI:
		return _vlr_subscr_find_by_tmsi(vlr, mi->tmsi, use, file, line);
	default:
		return NULL;
	}
}

/* Transmit GSUP message for subscriber to HLR, using IMSI from subscriber */
static int vlr_subscr_tx_gsup_message(const struct vlr_subscr *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr = vsub->vlr;

	if (strlen(gsup_msg->imsi) == 0)
		OSMO_STRLCPY_ARRAY(gsup_msg->imsi, vsub->imsi);

	gsup_msg->message_class = OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT;

	return gsup_client_mux_tx(vlr->gcm, gsup_msg);
}

static int vlr_subscr_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct vlr_subscr *vsub = e->use_count->talloc_object;
	char buf[128];
	int32_t total;
	int level;

	if (!e->use)
		return -EINVAL;

	total = osmo_use_count_total(&vsub->use_count);

	if (total == 0
	    || (total == 1 && old_use_count == 0 && e->count == 1))
		level = LOGL_INFO;
	else
		level = LOGL_DEBUG;

	LOGPSRC(g_vlr_log_cat[OSMO_VLR_LOGC_VLR], level, file, line, "VLR subscr %s %s %s: now used by %s\n",
		vlr_subscr_name(vsub), (e->count - old_use_count) > 0? "+" : "-", e->use,
		osmo_use_count_name_buf(buf, sizeof(buf), e->use_count));

	if (e->count < 0)
		return -ERANGE;

	vsub->max_total_use_count = OSMO_MAX(vsub->max_total_use_count, total);

	if (total <= 0)
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
		.expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION,
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
	vlr_stat_item_inc(vlr, VLR_STAT_SUBSCRIBER_COUNT);
	return vsub;
}

/* Send a GSUP Purge MS request.
 * TODO: this should be sent to the *previous* VLR when this VLR is "taking"
 * this subscriber, not to the HLR? */
int vlr_subscr_purge(struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_PURGE_MS_REQ);

	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;

	/* provide HLR number in case we know it */
	gsup_msg.hlr_enc_len = vsub->hlr.len;
	gsup_msg.hlr_enc = vsub->hlr.buf;

	gsup_msg.cn_domain = vlr_is_cs(vsub->vlr) ? OSMO_GSUP_CN_DOMAIN_CS : OSMO_GSUP_CN_DOMAIN_PS;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

void vlr_subscr_cancel_attach_fsm(struct vlr_subscr *vsub,
				  enum osmo_fsm_term_cause fsm_cause,
				  enum gsm48_reject_value gsm48_cause)
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
	vlr_stat_item_dec(vsub->vlr, VLR_STAT_SUBSCRIBER_COUNT);
	LOGVSUBP(LOGL_DEBUG, vsub, "freeing VLR subscr (max total use count was %d)\n",
	       vsub->max_total_use_count);

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
			LOGVLR(LOGL_ERROR, "osmo_get_rand_id() failed: %s\n", strerror(-rc));
			return rc;
		}

		if (!llist_empty(&vlr->cfg.nri_ranges->entries)) {
			int16_t nri_v;
			osmo_tmsi_nri_v_limit_by_ranges(&tmsi, vlr->cfg.nri_ranges, vlr->cfg.nri_bitlen);
			osmo_tmsi_nri_v_get(&nri_v, tmsi, vlr->cfg.nri_bitlen);
			LOGVLR(LOGL_DEBUG, "New NRI from range [%s] = 0x%x --> TMSI 0x%08x\n",
			     osmo_nri_ranges_to_str_c(OTC_SELECT, vlr->cfg.nri_ranges), nri_v, tmsi);
		}

		/* throw the dice again, if the TSMI doesn't fit */
		if (tmsi == GSM_RESERVED_TMSI)
			continue;

		/* Section 2.4 of 23.003: MSC has two MSB 00/01/10, SGSN 11 */
		if (vlr->cfg.is_ps) {
			/* SGSN */
			tmsi |= GSM23003_TMSI_SGSN_MASK;
		} else {
			/* MSC */
			if ((tmsi & GSM23003_TMSI_SGSN_MASK) == GSM23003_TMSI_SGSN_MASK)
				tmsi &= ~GSM23003_TMSI_SGSN_MASK;
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

	LOGVLR(LOGL_ERROR, "subscr %s: unable to generate valid TMSI"
	     " after %d tries\n", vlr_subscr_name(vsub), tried);
	return -1;
}

/* Find subscriber by IMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instance.
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
	LOGVLR(LOGL_INFO, "New subscr, IMSI: %s\n", vsub->imsi);
	if (created)
		*created = true;
	return vsub;
}

/* Find subscriber by TMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instance.
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
	LOGVLR(LOGL_INFO, "New subscr, TMSI: 0x%08x\n", vsub->tmsi);
	if (created)
		*created = true;
	return vsub;
}

static void dedup_vsub(struct vlr_subscr *exists, struct vlr_subscr *vsub)
{
	struct vlr_instance *vlr = exists->vlr;
	int i;
	int j;
	LOGVLR(LOGL_NOTICE,
	     "There is an existing subscriber for IMSI %s used by %s, replacing with new VLR subscr: %s used by %s\n",
	     exists->imsi, osmo_use_count_to_str_c(OTC_SELECT, &exists->use_count),
	     vlr_subscr_name(vsub),
	     osmo_use_count_to_str_c(OTC_SELECT, &vsub->use_count));

	if (!vsub->msisdn[0])
		OSMO_STRLCPY_ARRAY(vsub->msisdn, exists->msisdn);
	if (!vsub->name[0])
		OSMO_STRLCPY_ARRAY(vsub->name, exists->name);
	/* Copy valid auth tuples we may already have, to reduce the need to ask for new ones from the HLR */
	for (i = 0; i < ARRAY_SIZE(exists->auth_tuples); i++) {
		if (exists->auth_tuples[i].key_seq == VLR_KEY_SEQ_INVAL)
			continue;
		for (j = 0; j < ARRAY_SIZE(vsub->auth_tuples); j++) {
			if (vsub->auth_tuples[j].key_seq != VLR_KEY_SEQ_INVAL)
				continue;
			vsub->auth_tuples[j] = exists->auth_tuples[i];
		}
	}

	if (exists->msc_conn_ref)
		LOGVSUBP(LOGL_ERROR, vsub,
			 "There is an existing VLR entry for this same subscriber with an active connection."
			 " That should not be possible. Discarding old subscriber entry %s.\n",
			 exists->imsi);

	if (vlr->ops.subscr_inval)
		vlr->ops.subscr_inval(exists->msc_conn_ref, exists, 0, true);
	vlr_subscr_free(exists);
}

void vlr_subscr_set_imsi(struct vlr_subscr *vsub, const char *imsi)
{
	struct vlr_subscr *exists;
	if (!vsub)
		return;

	/* If the same IMSI is already set, nothing changes. */
	if (!strcmp(vsub->imsi, imsi))
		return;

	/* We've just learned about this new IMSI, our primary key in the VLR. make sure to invalidate any prior VLR
	 * entries for this IMSI. */
	exists = vlr_subscr_find_by_imsi(vsub->vlr, imsi, NULL);

	if (exists)
		dedup_vsub(exists, vsub);

	/* Set the IMSI on the new subscriber, here. */
	if (OSMO_STRLCPY_ARRAY(vsub->imsi, imsi) >= sizeof(vsub->imsi)) {
		LOGVLR(LOGL_NOTICE, "IMSI was truncated: full IMSI=%s, truncated IMSI=%s\n",
		       imsi, vsub->imsi);
		/* XXX Set truncated IMSI anyway, we currently cannot return an error from here. */
	}

	vsub->id = atoll(vsub->imsi);
	LOGVLR(LOGL_DEBUG, "set IMSI on subscriber; IMSI=%s id=%llu\n",
	       vsub->imsi, vsub->id);
}

void vlr_subscr_set_imei(struct vlr_subscr *vsub, const char *imei)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->imei, imei);
	LOGVLR(LOGL_DEBUG, "set IMEI on subscriber; IMSI=%s IMEI=%s\n",
	       vsub->imsi, vsub->imei);
}

void vlr_subscr_set_imeisv(struct vlr_subscr *vsub, const char *imeisv)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->imeisv, imeisv);
	LOGVLR(LOGL_DEBUG, "set IMEISV on subscriber; IMSI=%s IMEISV=%s\n",
	       vsub->imsi, vsub->imeisv);

	/* Copy IMEISV to IMEI (additional SV digits get cut off) */
	vlr_subscr_set_imei(vsub, imeisv);
}

/* Safely copy the given MSISDN string to vsub->msisdn */
void vlr_subscr_set_msisdn(struct vlr_subscr *vsub, const char *msisdn)
{
	if (!vsub)
		return;
	OSMO_STRLCPY_ARRAY(vsub->msisdn, msisdn);
	LOGVLR(LOGL_DEBUG, "set MSISDN on subscriber; IMSI=%s MSISDN=%s\n",
	       vsub->imsi, vsub->msisdn);
}

void vlr_subscr_set_last_used_eutran_plmn_id(struct vlr_subscr *vsub,
					     const struct osmo_plmn_id *last_eutran_plmn)
{
	if (!vsub)
		return;
	if (last_eutran_plmn) {
		vsub->sgs.last_eutran_plmn_present = true;
		memcpy(&vsub->sgs.last_eutran_plmn, last_eutran_plmn, sizeof(*last_eutran_plmn));
	} else {
		vsub->sgs.last_eutran_plmn_present = false;
	}
	LOGVLR(LOGL_DEBUG, "set Last E-UTRAN PLMN ID on subscriber: %s\n",
	       vsub->sgs.last_eutran_plmn_present ?
	         osmo_plmn_name(&vsub->sgs.last_eutran_plmn) :
		 "(none)");
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
	LOGVLR(LOGL_ERROR, "Not implemented: %s\n", __func__);
	return 0;
}

void vlr_subscr_enable_expire_lu(struct vlr_subscr *vsub)
{
	struct timespec now;

	/* Mark the subscriber as inactive if it stopped to do periodical location updates. */
	if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
		vsub->expire_lu = now.tv_sec + vlr_timer_secs(vsub->vlr, 3212, 3312);
	} else {
		LOGVLR(LOGL_ERROR,
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

	/* Periodic location update might be disabled from the VTY,
	 * so we shall not expire subscribers until explicit IMSI Detach. */
	if (!vlr_timer_secs(vlr, 3212, 3312))
		goto done;

	if (llist_empty(&vlr->subscribers))
		goto done;

	if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		LOGVLR(LOGL_ERROR, "Skipping Location Update expiry: Could not read current time\n");
		goto done;
	}

	llist_for_each_entry_safe(vsub, vsub_tmp, &vlr->subscribers, list) {
		if (vsub->expire_lu == VLR_SUBSCRIBER_NO_EXPIRATION || vsub->expire_lu > now.tv_sec)
			continue;

		LOGVLR(LOGL_DEBUG, "%s: Location Update expired\n", vlr_subscr_name(vsub));
		vlr_rate_ctr_inc(vlr, VLR_CTR_DETACH_BY_T3212);
		vlr_subscr_detach(vsub);
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
	struct llist_head	list;

	unsigned int		context_id;
	enum gsm48_pdp_type_org	pdp_type_org;
	enum gsm48_pdp_type_nr	pdp_type_nr;
	struct osmo_sockaddr	pdp_address[2];
	char			apn_str[GSM_APN_LENGTH];
	uint8_t			qos_subscribed[20];
	size_t			qos_subscribed_len;
};

struct sgsn_subscriber_pdp_data *
vlr_subscr_pdp_data_alloc(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(vsub, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &vsub->ps.pdp_list);
	vlr_stat_item_inc(vsub->vlr, VLR_STAT_PDP_COUNT);

	return pdata;
}

static int vlr_subscr_pdp_data_clear(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data *pdp, *pdp2;
	int count = 0;

	llist_for_each_entry_safe(pdp, pdp2, &vsub->ps.pdp_list, list) {
		llist_del(&pdp->list);
		vlr_stat_item_dec(vsub->vlr, VLR_STAT_PDP_COUNT);
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
				    const struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		LOGVLR(LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
		gsup_client_mux_tx_error_reply(vlr->gcm, gsup_msg, GMM_CAUSE_IMSI_UNKNOWN);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGVLR(LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGVLR(LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

static int vlr_rx_gsup_purge_no_subscr(struct vlr_instance *vlr,
				       const struct osmo_gsup_message *gsup_msg)
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

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_UL_REQ);

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	gsup_msg.cn_domain = vlr_is_cs(vsub->vlr) ? OSMO_GSUP_CN_DOMAIN_CS : OSMO_GSUP_CN_DOMAIN_PS;
	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_msg);

	return rc;
}

/* VLR internal call to request tuples from HLR */
int vlr_subscr_req_sai(struct vlr_subscr *vsub,
		       const uint8_t *auts, const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_SAI_REQ);

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.auts = auts;
	gsup_msg.rand = auts_rand;
	gsup_msg.cn_domain = vlr_is_cs(vsub->vlr) ? OSMO_GSUP_CN_DOMAIN_CS : OSMO_GSUP_CN_DOMAIN_PS;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

/* Initiate Check_IMEI_VLR Procedure (23.018 Chapter 7.1.2.9) */
int vlr_subscr_tx_req_check_imei(const struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {
		.message_class = OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT,
		.message_type = OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST,
	};
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

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_CHECK_IMEI_REQ);

	/* Send CHECK_IMEI_REQUEST */
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, vsub->imsi);
	return gsup_client_mux_tx(vsub->vlr->gcm, &gsup_msg);
}

/* Tell HLR that authentication failure occurred */
int vlr_subscr_tx_auth_fail_rep(const struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {
		.message_class = OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT,
		.message_type = OSMO_GSUP_MSGT_AUTH_FAIL_REPORT,
		.cn_domain = vlr_is_cs(vsub->vlr) ? OSMO_GSUP_CN_DOMAIN_CS : OSMO_GSUP_CN_DOMAIN_PS,
	};

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_AUTH_FAIL_REP);

	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, vsub->imsi);
	return gsup_client_mux_tx(vsub->vlr->gcm, &gsup_msg);
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
				"Skipping auth tuple with invalid cksn %zu\n",
				key_seq);
			continue;
		}
		vsub->auth_tuples[i].vec = gsup->auth_vectors[i];
		vsub->auth_tuples[i].key_seq = key_seq;
		got_tuples++;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "Received %u auth tuples\n", got_tuples);
	vlr_rate_ctr_add(vsub->vlr, VLR_CTR_GSUP_RX_TUPLES, got_tuples);

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

	if (!auth_fi) {
		LOGVSUBP(LOGL_ERROR, vsub, "Received GSUP %s, but there is no auth_fsm\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		return -1;
	}

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

static void vlr_subscr_gsup_insert_data(struct vlr_subscr *vsub,
					const struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc_len) {//FIXME: vlr_subscr_set_msisdn()?
		gsm48_decode_bcd_number2(vsub->msisdn, sizeof(vsub->msisdn),
					 gsup_msg->msisdn_enc,
					 gsup_msg->msisdn_enc_len, 0);
		LOGVLR(LOGL_DEBUG, "IMSI:%s has MSISDN:%s\n",
		     vsub->imsi, vsub->msisdn);
	}

	if (gsup_msg->hlr_enc) {
		if (gsup_msg->hlr_enc_len > sizeof(vsub->hlr.buf)) {
			LOGVLR(LOGL_ERROR, "HLR-Number too long (%zu)\n",
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
			LOGVLR(LOGL_INFO, "Cleared existing PDP info\n");
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
		pdp_data->pdp_type_org = pdp_info->pdp_type_org;
		pdp_data->pdp_type_nr = pdp_info->pdp_type_nr;
		memcpy(&pdp_data->pdp_address[0], &pdp_info->pdp_address[0], sizeof(pdp_data->pdp_address[0]));
		memcpy(&pdp_data->pdp_address[1], &pdp_info->pdp_address[1], sizeof(pdp_data->pdp_address[1]));
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

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_GSUP_TX_ISD_RES);

	vlr_subscr_gsup_insert_data(vsub, gsup);
	vsub->vlr->ops.subscr_update(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return vlr_subscr_tx_gsup_message(vsub, &gsup_reply);
}

/* Handle UpdateLocation Result from HLR */
static int vlr_subscr_handle_lu_res(struct vlr_subscr *vsub,
				    const struct osmo_gsup_message *gsup)
{
	struct sgs_lu_response sgs_lu_response = {0};
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
	struct sgs_lu_response sgs_lu_response = {0};
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

enum gsm48_reject_value vlr_gmm_cause_to_reject_cause_domain(enum gsm48_gmm_cause gmm_cause, bool is_cs)
{
	enum gsm48_reject_value reject_cause = vlr_gmm_cause_to_reject_cause(gmm_cause);
	if (is_cs)
		return vlr_reject_causes_cs(reject_cause);
	else
		return vlr_reject_causes_ps(reject_cause);
}

enum gsm48_reject_value vlr_gmm_cause_to_reject_cause(enum gsm48_gmm_cause gmm_cause)
{
	switch (gmm_cause) {
	case GMM_CAUSE_IMSI_UNKNOWN:
		return GSM48_REJECT_IMSI_UNKNOWN_IN_HLR;
	case GMM_CAUSE_ILLEGAL_MS:
		return GSM48_REJECT_ILLEGAL_MS;
	case GMM_CAUSE_IMEI_NOT_ACCEPTED:
		return GSM48_REJECT_IMEI_NOT_ACCEPTED;
	case GMM_CAUSE_ILLEGAL_ME:
		return GSM48_REJECT_ILLEGAL_ME;
	case GMM_CAUSE_GPRS_NOTALLOWED:
		return GSM48_REJECT_GPRS_NOT_ALLOWED;
	case GMM_CAUSE_GPRS_OTHER_NOTALLOWED:
		return GSM48_REJECT_SERVICES_NOT_ALLOWED;
	case GMM_CAUSE_MS_ID_NOT_DERIVED:
		return GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE;
	case GMM_CAUSE_IMPL_DETACHED:
		return GSM48_REJECT_IMPLICITLY_DETACHED;
	case GMM_CAUSE_PLMN_NOTALLOWED:
		return GSM48_REJECT_PLMN_NOT_ALLOWED;
	case GMM_CAUSE_LA_NOTALLOWED:
		return GSM48_REJECT_LOC_NOT_ALLOWED;
	case GMM_CAUSE_ROAMING_NOTALLOWED:
		return GSM48_REJECT_ROAMING_NOT_ALLOWED;
	case GMM_CAUSE_NO_GPRS_PLMN:
		return GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN;
	case GMM_CAUSE_MSC_TEMP_NOTREACH:
		return GSM48_REJECT_MSC_TMP_NOT_REACHABLE;
	case GMM_CAUSE_SYNC_FAIL:
		return GSM48_REJECT_SYNCH_FAILURE;
	case GMM_CAUSE_CONGESTION:
		return GSM48_REJECT_CONGESTION;
	case GMM_CAUSE_SEM_INCORR_MSG:
		return GSM48_REJECT_INCORRECT_MESSAGE;
	case GMM_CAUSE_INV_MAND_INFO:
		return GSM48_REJECT_INVALID_MANDANTORY_INF;
	case GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL:
		return GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED;
	case GMM_CAUSE_MSGT_INCOMP_P_STATE:
		return GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE;
	case GMM_CAUSE_IE_NOTEXIST_NOTIMPL:
		return GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED;
	case GMM_CAUSE_COND_IE_ERR:
		return GSM48_REJECT_CONDTIONAL_IE_ERROR;
	case GMM_CAUSE_MSG_INCOMP_P_STATE:
		return GSM48_REJECT_MSG_NOT_COMPATIBLE;
	case GMM_CAUSE_PROTO_ERR_UNSPEC:
		return GSM48_REJECT_PROTOCOL_ERROR;
	case GMM_CAUSE_NO_SUIT_CELL_IN_LA:
		return GSM48_REJECT_NO_SUIT_CELL_IN_LA;
	case GMM_CAUSE_MAC_FAIL:
		return GSM48_REJECT_MAC_FAILURE;
	case GMM_CAUSE_GSM_AUTH_UNACCEPT:
		return GSM48_REJECT_GSM_AUTH_UNACCEPTABLE;
	case GMM_CAUSE_NOT_AUTH_FOR_CSG:
		return GSM48_REJECT_NOT_AUTH_FOR_CSG;
	case GMM_CAUSE_SMS_VIA_GPRS_IN_RA:
		return GSM48_REJECT_SMS_PROV_VIA_GPRS_IN_RA;
	case GMM_CAUSE_NO_PDP_ACTIVATED:
		return GSM48_REJECT_NO_PDP_CONTEXT_ACTIVATED;
	case GMM_CAUSE_NET_FAIL:
		return GSM48_REJECT_NETWORK_FAILURE;
	default:
		return GSM48_REJECT_NETWORK_FAILURE;
	}
}

enum gsm48_reject_value vlr_reject_causes_ps(enum gsm48_reject_value reject_cause)
{
	switch (reject_cause) {
	case GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED:
		return GSM48_REJECT_NETWORK_FAILURE;
	default:
		return reject_cause;
	}
}

enum gsm48_reject_value vlr_reject_causes_cs(enum gsm48_reject_value reject_cause)
{
	switch (reject_cause) {
	case GSM48_REJECT_NO_SUIT_CELL_IN_LA:
	case GSM48_REJECT_MAC_FAILURE:
	case GSM48_REJECT_GSM_AUTH_UNACCEPTABLE:
	case GSM48_REJECT_NOT_AUTH_FOR_CSG:
	case GSM48_REJECT_SMS_PROV_VIA_GPRS_IN_RA:
	case GSM48_REJECT_NO_PDP_CONTEXT_ACTIVATED:
		return GSM48_REJECT_NETWORK_FAILURE;
	default:
		return reject_cause;
	}
}

/* Handle LOCATION CANCEL request from HLR */
static int vlr_subscr_handle_cancel_req(struct vlr_subscr *vsub,
					const struct osmo_gsup_message *gsup_msg)
{
	enum gsm48_reject_value gsm48_rej;
	enum osmo_fsm_term_cause fsm_cause = OSMO_FSM_TERM_ERROR;
	struct vlr_instance *vlr = vsub->vlr;
	struct osmo_gsup_message gsup_reply = {0};
	int is_update_procedure = !gsup_msg->cancel_type ||
		gsup_msg->cancel_type == OSMO_GSUP_CANCEL_TYPE_UPDATE;

	vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_TX_CANCEL_RES);

	LOGVSUBP(LOGL_INFO, vsub, "Cancelling MS subscriber (%s)\n",
		 is_update_procedure ?
		 "update procedure" : "subscription withdraw");

	gsm48_rej = vlr_gmm_cause_to_reject_cause_domain(gsup_msg->cause, vlr_is_cs(vlr));
	vlr_subscr_cancel_attach_fsm(vsub, fsm_cause, gsm48_rej);

	if (vlr->ops.subscr_inval)
		vlr->ops.subscr_inval(vsub->msc_conn_ref, vsub, gsm48_rej, is_update_procedure);

	vlr_rate_ctr_inc(vlr, VLR_CTR_DETACH_BY_CANCEL);
	vlr_subscr_detach(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	gsup_reply.cn_domain = vlr_is_cs(vlr) ? OSMO_GSUP_CN_DOMAIN_CS : OSMO_GSUP_CN_DOMAIN_PS;
	return vlr_subscr_tx_gsup_message(vsub, &gsup_reply);
}

/* Handle Check_IMEI_VLR result and error from HLR */
static int vlr_subscr_handle_check_imei(struct vlr_subscr *vsub, const struct osmo_gsup_message *gsup)
{
	if (!vsub->lu_fsm) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx %s without LU in progress\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		return -ENODEV;
	}

	/* Dispatch result to vsub->lu_fsm, which will either handle the result by itself (Check IMEI early) or dispatch
	 * it further to lu_compl_vlr_fsm (Check IMEI after LU). */
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
int vlr_gsup_rx(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *gsup)
{
	struct vlr_instance *vlr = data;
	struct vlr_subscr *vsub;
	int rc = 0;

	vsub = vlr_subscr_find_by_imsi(vlr, gsup->imsi, __func__);
	if (!vsub) {
		switch (gsup->message_type) {
		case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
			vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_PURGE_NO_SUBSCR);
			return vlr_rx_gsup_purge_no_subscr(vlr, gsup);
		default:
			vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_UNKNOWN_IMSI);
			return vlr_rx_gsup_unknown_imsi(vlr, gsup);
		}
	}

	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_SAI_RES);
		rc = vlr_subscr_handle_sai_res(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_SAI_ERR);
		rc = vlr_subscr_handle_sai_res(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_ISD_REQ);
		rc = vlr_subscr_handle_isd_req(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_CANCEL_REQ);
		rc = vlr_subscr_handle_cancel_req(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_UL_RES);
		rc = vlr_subscr_handle_lu_res(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_UL_ERR);
		rc = vlr_subscr_handle_lu_err(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_PURGE_MS_ERR);
		goto out_unimpl;
	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_PURGE_MS_RES);
		goto out_unimpl;
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_DELETE_DATA_REQ);
		goto out_unimpl;
	case OSMO_GSUP_MSGT_CHECK_IMEI_ERROR:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_CHECK_IMEI_ERR);
		rc = vlr_subscr_handle_check_imei(vsub, gsup);
		break;
	case OSMO_GSUP_MSGT_CHECK_IMEI_RESULT:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_CHECK_IMEI_RES);
		rc = vlr_subscr_handle_check_imei(vsub, gsup);
		break;
	default:
		vlr_rate_ctr_inc(vlr, VLR_CTR_GSUP_RX_UNKNOWN);
		LOGP(DLGSUP, LOGL_ERROR, "GSUP Message type not handled by VLR: %d\n", gsup->message_type);
		rc = -EINVAL;
		break;
	}

	vlr_subscr_put(vsub, __func__);
	return rc;

out_unimpl:
	LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP msg_type=%d not yet implemented\n", gsup->message_type);
	vlr_subscr_put(vsub, __func__);
	return -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_subscr_rx_id_resp(struct vlr_subscr *vsub, const struct osmo_mobile_identity *mi)
{
	/* update the vlr_subscr with the given identity */
	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		if (vsub->imsi[0]
		    && !vlr_subscr_matches_imsi(vsub, mi->imsi)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi->imsi);
			/* XXX Should we return an error, e.g. -EINVAL ? */
		} else
			vlr_subscr_set_imsi(vsub, mi->imsi);
		break;
	case GSM_MI_TYPE_IMEI:
		vlr_subscr_set_imei(vsub, mi->imei);
		break;
	case GSM_MI_TYPE_IMEISV:
		vlr_subscr_set_imeisv(vsub, mi->imeisv);
		break;
	default:
		return -EINVAL;
	}

	if (vsub->auth_fsm) {
		switch (mi->type) {
		case GSM_MI_TYPE_IMSI:
			return osmo_fsm_inst_dispatch(vsub->auth_fsm,
						      VLR_AUTH_E_MS_ID_IMSI, (void*)mi->imsi);
			break;
		}
	}

	if (vsub->lu_fsm) {
		switch (mi->type) {
		case GSM_MI_TYPE_IMSI:
			return osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_ID_IMSI, (void*)mi->imsi);
		case GSM_MI_TYPE_IMEI:
			return osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_ID_IMEI, (void*)mi->imei);
		case GSM_MI_TYPE_IMEISV:
			return osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_ID_IMEISV, (void*)mi->imeisv);
		default:
			return -EINVAL;
		}
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
			 "gratuitous TMSI REALLOC COMPL\n");
		return -EINVAL;
	}
}

/* SGSN->VLR: Subscriber has provided ATTACH/RAU Complete */
int vlr_subscr_rx_rau_complete(struct vlr_subscr *vsub)
{
	if (!vsub->lu_fsm)
		return -EINVAL;

	return osmo_fsm_inst_dispatch(vsub->lu_fsm,
					      VLR_ULA_E_NEW_TMSI_ACK, NULL);
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

static int vlr_subscr_detach(struct vlr_subscr *vsub)
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

/* See TS 23.012 version 9.10.0 4.3.2.1 "Process Detach_IMSI_VLR" */
int vlr_subscr_rx_imsi_detach(struct vlr_subscr *vsub)
{
	int rc = 0;

	vlr_rate_ctr_inc(vsub->vlr, VLR_CTR_DETACH_BY_REQ);

	if (!vsub->imsi_detached_flag)
		rc = vlr_subscr_purge(vsub);

	rc |= vlr_subscr_detach(vsub);
	return rc;
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

struct vlr_instance *vlr_alloc(void *ctx, const struct vlr_ops *ops, bool is_ps)
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

	INIT_LLIST_HEAD(&vlr->subscribers);
	INIT_LLIST_HEAD(&vlr->operations);
	memcpy(&vlr->ops, ops, sizeof(vlr->ops));

	/* defaults */
	vlr->cfg.is_ps = is_ps;
	vlr->cfg.assign_tmsi = true;
	vlr->cfg.nri_bitlen = OSMO_NRI_BITLEN_DEFAULT;
	vlr->cfg.nri_ranges = osmo_nri_ranges_alloc(vlr);

	vlr->statg = osmo_stat_item_group_alloc(vlr, &vlr_statg_desc, 0);
	if (!vlr->statg)
		goto err_free;

	vlr->ctrg = rate_ctr_group_alloc(vlr, &vlr_ctrg_desc, 0);
	if (!vlr->ctrg)
		goto err_statg;

	/* reset shared timer definitions */
	osmo_tdefs_reset(msc_tdefs_vlr);
	osmo_tdefs_reset(sgsn_tdefs_vlr);

	/* osmo_auth_fsm.c */
	vlr_auth_fsm_init(is_ps);

	/* osmo_lu_fsm.c */
	vlr_lu_fsm_init(is_ps);
	/* vlr_access_request_fsm.c */
	vlr_parq_fsm_init(is_ps);
	/* vlr_sgs_fsm.c */
	vlr_sgs_fsm_init();

	if (is_ps)
		vlr_tdefs = sgsn_tdefs_vlr;
	else
		vlr_tdefs = msc_tdefs_vlr;

	return vlr;

err_statg:
	osmo_stat_item_group_free(vlr->statg);
err_free:
	talloc_free(vlr);
	return NULL;
}

int vlr_start(struct vlr_instance *vlr, struct gsup_client_mux *gcm)
{
	OSMO_ASSERT(vlr);

	vlr->gcm = gcm;
	gcm->rx_cb[OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT] = (struct gsup_client_mux_rx_cb){
		.func = vlr_gsup_rx,
		.data = vlr,
	};

	osmo_timer_setup(&vlr->lu_expire_timer, vlr_subscr_expire_lu, vlr);
	osmo_timer_schedule(&vlr->lu_expire_timer, VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL, 0);
	return 0;
}

/* MSC->VLR: Subscriber has disconnected */
int vlr_subscr_disconnected(struct vlr_subscr *vsub)
{
	/* This corresponds to a MAP-ABORT from MSC->VLR on a classic B
	 * interface */
	if (vsub->lu_fsm)
		osmo_fsm_inst_term(vsub->lu_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	if (vsub->auth_fsm)
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
void vlr_subscr_rx_ciph_res(struct vlr_subscr *vsub, enum vlr_ciph_result_cause result)
{
	if (vsub->lu_fsm && vsub->lu_fsm->state == VLR_ULA_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_CIPH_RES, &result);
	if (vsub->proc_arq_fsm
	    && vsub->proc_arq_fsm->state == PR_ARQ_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->proc_arq_fsm, PR_ARQ_E_CIPH_RES, &result);
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
		      bool umts_aka,
		      bool retrieve_imeisv)
{
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

int g_vlr_log_cat[_OSMO_VLR_LOGC_MAX];

void osmo_vlr_set_log_cat(enum osmo_vlr_cat logc, int logc_num)
{
	if (logc < OSMO_VLR_LOGC_VLR || logc >= _OSMO_VLR_LOGC_MAX)
		return;

	g_vlr_log_cat[logc] = logc_num;

	switch (logc) {
	case OSMO_VLR_LOGC_VLR:
		vlr_auth_fsm_set_log_subsys(logc_num);
		vlr_parq_fsm_set_log_subsys(logc_num);
		vlr_lu_fsm_set_log_subsys(logc_num);
		break;
	case OSMO_VLR_LOGC_SGS:
		vlr_sgs_fsm_set_log_subsys(logc_num);
		break;
	default:
		break;
	}
}
