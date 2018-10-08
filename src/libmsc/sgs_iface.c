/* SGs Interface according to 3GPP TS 23.272 + TS 29.118 */

/* (C 2018 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/protocol/gsm_29_118.h>

#include <osmocom/netif/stream.h>

#include <osmocom/msc/debug.h>

#define S(x) (1 << (x))

static struct osmo_fsm sgs_vlr_reset_fsm;

/***********************************************************************
 * SGs state per MME connection
 ***********************************************************************/

struct sgs_state;
struct sgs_connection;

struct sgs_mme_ctx {
	/* global list of MME contexts */
	struct llist_head list;
	/* back-pointer */
	struct sgs_state *sgs;

	/* MME name as string representation */
	char fqdn[GSM23003_MME_DOMAIN_LEN+1];

	/* current connection for this MME, if any. Can be NULL if the SCTP
	 * connection to the MME was lost and hasn't been re-established yet */
	struct sgs_connection *conn;

	/* FSM for the "VLR reset" procedure" */
	struct osmo_fsm_inst *fi;
	unsigned int ns11_remaining;
};

struct sgs_connection {
	/* global list of SGs connections */
	struct llist_head list;
	/* back-pointer */
	struct sgs_state *sgs;

	/* Socket name from osmo_sock_get_name() */
	char *sockname;

	/* MME for this connection, if any.  This field is NULL until we
	 * receive the first "MME name" IE from the MME, which could be part
	 * of the RESET procedure, but also just a normal LU request. */
	struct sgs_mme_ctx *mme;

	/* represents the SCTP connection we accept()ed from this MME */
	struct osmo_stream_srv *srv;
};

enum {
	SGS_STATE_TS5,
	SGS_STATE_TS6_2,
	SGS_STATE_TS7,
	SGS_STATE_TS11,
	SGS_STATE_TS14,
	SGS_STATE_TS15,
	_NUM_SGS_STATE_TIMERS
};

enum {
	SGS_STATE_NS7,
	SGS_STATE_NS11,
	_NUM_SGS_STATE_COUNTERS
};

static const unsigned int sgs_state_timer_defaults[_NUM_SGS_STATE_TIMERS] = {
	[SGS_STATE_TS5] = SGS_TS5_DEFAULT,
	[SGS_STATE_TS6_2] = SGS_TS6_2_DEFAULT,
	[SGS_STATE_TS7] = SGS_TS7_DEFAULT,
	[SGS_STATE_TS11] = SGS_TS11_DEFAULT,
	[SGS_STATE_TS14] = SGS_TS14_DEFAULT,
	[SGS_STATE_TS15] = SGS_TS15_DEFAULT,
};

static const char *sgs_state_timer_names[_NUM_SGS_STATE_TIMERS] = {
	[SGS_STATE_TS5] = "Ts5",
	[SGS_STATE_TS6_2] = "Ts6-2",
	[SGS_STATE_TS7] = "Ts7",
	[SGS_STATE_TS11] = "Ts11",
	[SGS_STATE_TS14] = "Ts14",
	[SGS_STATE_TS15] = "Ts15",
};

static const unsigned int sgs_state_counter_defaults[_NUM_SGS_STATE_COUNTERS] = {
	[SGS_STATE_NS7] = SGS_NS7_DEFAULT,
	[SGS_STATE_NS11] = SGS_NS11_DEFAULT,
};

static const char *sgs_state_counter_names[_NUM_SGS_STATE_COUNTERS] = {
	[SGS_STATE_NS7] = "Ns7",
	[SGS_STATE_NS11] = "Ns11",
};

/* global SGs state */
struct sgs_state {
	/* list of MMEs (sgs_mme_ctx) */
	struct llist_head mme_list;

	/* list of SCTP client connections */
	struct llist_head conn_list;

	/* SCTP server for inbound SGs connections */
	struct osmo_stream_srv_link *srv_link;

	struct {
		char *local_addr;
		uint16_t local_port;
		/* user-configured VLR name (FQDN) */
		char *vlr_name;
		/* timers on VLR side */
		unsigned int timer[_NUM_SGS_STATE_TIMERS];
		/* countrs on VLR side */
		unsigned int counter[_NUM_SGS_STATE_COUNTERS];
	} cfg;
};

#define LOGSGC(sgc, lvl, fmt, args...) \
	LOGP(DSGS, lvl, "%s: " fmt, (sgc)->sockname, ## args)

#define LOGMME(mme, lvl, fmt, args...) \
	LOGP(DSGS, lvl, "%s: " fmt, (mme)->fqdn ? (mme)->fqdn : (mme)->conn->sockname, ## args)

static struct sgs_state *g_sgs;


enum sgs_vlr_reset_fsm_state {
	SGS_VLRR_ST_NULL,
	SGS_VLRR_ST_WAIT_ACK,
	SGS_VLRR_ST_COMPLETE,
};

enum sgs_vlr_reset_fsm_event {
	SGS_VLRR_E_START_RESET,
	SGS_VLRR_E_RX_RESET_ACK,
};


static int sgs_open(struct sgs_state *sgs);

/***********************************************************************
 * SGs state per subscriber
 ***********************************************************************/

struct sgs_ue_context {
	/* FSM representing SGs VLR state machine as per 29.118 4.2.2 */
	struct osmo_fsm *fi;
	/* MME address serving the UE */
};


/***********************************************************************
 * SGsAP transmit functions
 ***********************************************************************/

#include <osmocom/gsm/apn.h>

static struct msgb *sgs_msgb_alloc(void)
{
	/* by far sufficient for the maximum size message of 298 bytes
	 * (9+7+5+3+10+253+10+1) SGsAP-UP-UD */
	return msgb_alloc_headroom(1024, 128, "SGsAP");
}

/*! Encode VLR/MME name from string and append to SGsAP msg */
static void msgb_sgsap_name_put(struct msgb *msg, enum sgsap_iei iei, const char *name)
{
	uint8_t buf[64];
	uint8_t len;

	/* encoding is like DNS names, which is like APN fields */
	memset(buf, 0, sizeof(buf));
	len = osmo_apn_from_str(buf, sizeof(buf), name);
	if (iei == SGSAP_IE_MME_NAME)
		len = 55;
	msgb_tlv_put(msg, iei, len, buf);
}

/*! Encode IMSI from string representation and append to SGSaAP msg */
static void msgb_sgsap_imsi_put(struct msgb *msg, const char *imsi)
{
	uint8_t buf[16];
	uint8_t len;

	/* encoding is just like TS 04.08 */
	len = gsm48_generate_mid_from_imsi(buf, imsi);
	/* skip first two bytes (tag+length) so we can use msgb_tlv_put */
	msgb_tlv_put(msg, SGSAP_IE_IMSI, len-2, buf+2);
}

/*! Encode IMSI from string representation and append to SGSaAP msg */
static void msgb_sgsap_imsi_push(struct msgb *msg, const char *imsi)
{
	uint8_t buf[16];
	uint8_t len;

	/* encoding is just like TS 04.08 */
	len = gsm48_generate_mid_from_imsi(buf, imsi);
	/* skip first two bytes (tag+length) so we can use msgb_tlv_put */
	msgb_tlv_push(msg, SGSAP_IE_IMSI, len-2, buf+2);
}

static void sgs_tx(struct sgs_connection *sgc, enum sgsap_msg_type msg_type, struct msgb *msg)
{
	uint8_t *cur = msgb_push(msg, 1);
	*cur = msg_type;
	msgb_sctp_ppid(msg) = 0;
	if (!sgc) {
		LOGSGC(sgc, LOGL_NOTICE, "Cannot transmit %s: connection dead. Discarding\n",
			sgsap_msg_type_name(msg_type));
		msgb_free(msg);
		return;
	}
	osmo_stream_srv_send(sgc->srv, msg);
}

/*! Transmit simple SGsAP message (only IE: IMSI) */
static void sgs_tx_simple(struct sgs_connection *sgc, enum sgsap_msg_type msgt, const char *imsi)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	sgs_tx(sgc, msgt, msg);
}


/* 8.3 */
void sgs_tx_alert_req(struct sgs_connection *sgc, const char *imsi)
{
	sgs_tx_simple(sgc, SGSAP_MSGT_ALERT_REQ, imsi);
}

/* 8.4 */
void sgs_tx_dl_ud(struct sgs_connection *sgc, const char *imsi, struct msgb *msg)
{
	msgb_sgsap_imsi_push(msg, imsi);
	sgs_tx(sgc, SGSAP_MSGT_DL_UD, msg);
}

/* 8.5 */
void sgs_tx_eps_det_ack(struct sgs_connection *sgc, const char *imsi)
{
	sgs_tx_simple(sgc, SGSAP_MSGT_EPS_DET_ACK, imsi);
}

/* 8.8 */
void sgs_tx_imsi_det_ind(struct sgs_connection *sgc, const char *imsi)
{
	sgs_tx_simple(sgc, SGSAP_MSGT_IMSI_DET_IND, imsi);
}

/*! 8.9 SGsAP-LOCATION-UPDATE-ACCEPT
 *  \param[in] sgc SGs Connection 
 *  \param[in] imsi IMSI of the subscriber
 *  \param[in] lai Location Area Identity (optional, may be NULL)
 *  \param[in] new_id value part of new Mobile Identity (optional, may be NULL)
 *  \param[in] new_id_len length of \a new_id in octets
 */
void sgs_tx_lu_ack(struct sgs_connection *sgc, const char *imsi,
		  const struct osmo_location_area_id *lai,
		  const uint8_t *new_id, unsigned int new_id_len)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	if (lai) {
		struct gsm48_loc_area_id lai_enc;
		gsm48_generate_lai2(&lai_enc, lai);
		msgb_tlv_put(msg, SGSAP_IE_LAI, 5, (uint8_t *) &lai_enc);
	}
	if (new_id)
		msgb_tlv_put(msg, SGSAP_IE_MOBILE_ID, new_id_len, new_id);
	sgs_tx(sgc, SGSAP_MSGT_LOC_UPD_ACK, msg);
}

/* 8.10 */
void sgs_tx_lu_rej(struct sgs_connection *sgc, const char *imsi, uint8_t rej_cause,
		  const struct osmo_location_area_id *lai)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_tlv_put(msg, SGSAP_IE_REJECT_CAUSE, 1, &rej_cause);
	if (lai) {
		struct gsm48_loc_area_id lai_enc;
		gsm48_generate_lai2(&lai_enc, lai);
		msgb_tlv_put(msg, SGSAP_IE_LAI, 5, (uint8_t *) &lai_enc);
	}
	sgs_tx(sgc, SGSAP_MSGT_LOC_UPD_REJ, msg);
}

/* 8.12 */
void sgs_tx_mm_info_req(struct sgs_connection *sgc, const char *imsi, const uint8_t *mm_info, uint8_t len)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	msgb_tlv_put(msg, SGSAP_IE_MM_INFO, len, mm_info);
	sgs_tx(sgc, SGSAP_MSGT_MM_INFO_REQ, msg);
}

/* 8.15 */
void sgs_tx_reset_ack_vlr(struct sgs_connection *sgc, const char *vlr_name)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_name_put(msg, SGSAP_IE_VLR_NAME, vlr_name);
	sgs_tx(sgc, SGSAP_MSGT_RESET_ACK, msg);
}

/* 8.16 */
void sgs_tx_reset_ind_vlr(struct sgs_connection *sgc, const char *vlr_name)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_name_put(msg, SGSAP_IE_VLR_NAME, vlr_name);
	sgs_tx(sgc, SGSAP_MSGT_RESET_IND, msg);
}

/* 8.18 */
void sgs_tx_status(struct sgs_connection *sgc, enum sgsap_sgs_cause cause,
		  const char *imsi, const struct msgb *err_msg)
{
	struct msgb *msg = sgs_msgb_alloc();
	uint8_t c8 = cause;

	msgb_tlv_put(msg, SGSAP_IE_SGS_CAUSE, 1, &c8);
	if (imsi)
		msgb_sgsap_imsi_put(msg, imsi);
	if (err_msg)
		msgb_tlv_put(msg, SGSAP_IE_ERR_MSG, msgb_l2len(msg), msgb_l2(msg));
	sgs_tx(sgc, SGSAP_MSGT_STATUS, msg);
}
/* same as above, but get IMSI from tlv_parsed */
void sgs_tx_status_tp(struct sgs_connection *sgc, enum sgsap_sgs_cause cause,
		      const struct tlv_parsed *tp, const struct msgb *err_msg)
{
	struct msgb *msg = sgs_msgb_alloc();
	uint8_t c8 = cause;

	msgb_tlv_put(msg, SGSAP_IE_SGS_CAUSE, 1, &c8);
	if (tp && TLVP_PRESENT(tp, SGSAP_IE_IMSI)) {
		msgb_tlv_put(msg, SGSAP_IE_IMSI, TLVP_LEN(tp, SGSAP_IE_IMSI),
			     TLVP_VAL(tp, SGSAP_IE_IMSI));
	}
	if (err_msg)
		msgb_tlv_put(msg, SGSAP_IE_ERR_MSG, msgb_l2len(msg), msgb_l2(msg));
	sgs_tx(sgc, SGSAP_MSGT_STATUS, msg);
}

/* 8.23 */
void sgs_tx_release_req(struct sgs_connection *sgc, const char *imsi, const uint8_t *sgs_cause)
{
	struct msgb *msg = sgs_msgb_alloc();
	msgb_sgsap_imsi_put(msg, imsi);
	if (sgs_cause)
		msgb_tlv_put(msg, SGSAP_IE_SGS_CAUSE, 1, sgs_cause);
	sgs_tx(sgc, SGSAP_MSGT_RELEASE_REQ, msg);
}

/* 8.24 */
void sgs_tx_service_abort_req(struct sgs_connection *sgc, const char *imsi)
{
	sgs_tx_simple(sgc, SGSAP_MSGT_SERVICE_ABORT_REQ, imsi);
}


/***********************************************************************
 * SGs UE FSM, VLR side
 ***********************************************************************/

#include <osmocom/core/fsm.h>

enum sgs_ue_fsm_state {
	SGS_UE_ST_NULL,
	SGS_UE_ST_ASSOCIATED,
	SGS_UE_ST_LA_UPD_PRES,
};

enum sgs_ue_fsm_event {
	SGS_UE_E_VLR_FAILURE,
	SGS_UE_E_RX_RESET_FROM_MME,
	SGS_UE_E_RX_DETACH_IND_FROM_MME,
	SGS_UE_E_RX_DETACH_IND_FROM_UE,
	SGS_UE_E_RX_LU_FROM_A_IU_GS,
	SGS_UE_E_RX_PAGING_FAILURE,
	SGS_UE_E_RX_ALERT_FAILURE,
	SGS_UE_E_RX_LU_FROM_MME,
	SGS_UE_E_TX_LU_REJECT,
	SGS_UE_E_TX_LU_ACCEPT,
	SGS_UE_E_TX_PAGING,
	SGS_UE_E_RX_SGSAP_UE_UNRECHABLE,
	SGS_UE_E_RX_TMSI_REALLOC,
};

static const struct value_string sgs_ue_fsm_event_names[] = {
	{ SGS_UE_E_VLR_FAILURE,			"VLR_FAILURE" },
	{ SGS_UE_E_RX_RESET_FROM_MME,		"RX_RESET_FROM_MME" },
	{ SGS_UE_E_RX_DETACH_IND_FROM_MME,	"RX_DETACH_IND_FROM_MME" },
	{ SGS_UE_E_RX_DETACH_IND_FROM_UE,	"RX_DETACH_IND_FROM_UE" },
	{ SGS_UE_E_RX_LU_FROM_A_IU_GS,		"RX_LU_FROM_A_Iu_Gs" },
	{ SGS_UE_E_RX_PAGING_FAILURE,		"RX_PAGING_FAILURE" },
	{ SGS_UE_E_RX_ALERT_FAILURE,		"RX_ALERT_FAILURE" },
	{ SGS_UE_E_RX_LU_FROM_MME,		"RX_LU_FROM_MME" },
	{ SGS_UE_E_TX_LU_REJECT,		"TX_LU_REJECT" },
	{ SGS_UE_E_TX_LU_ACCEPT,		"TX_LU_ACCEPT" },
	{ SGS_UE_E_TX_PAGING,			"TX_PAGING" },
	{ SGS_UE_E_RX_SGSAP_UE_UNRECHABLE,	"RX_SGSAP_UE_UNREACH" },
	{ SGS_UE_E_RX_TMSI_REALLOC,		"RX_TMSI_REALLOC" },
	{ 0, NULL }
};

/* Figure 4.2.2.1 SGs-NULL */
static void sgs_ue_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_UE_E_RX_LU_FROM_MME:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_LA_UPD_PRES, 0, 0);
		break;
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	case SGS_UE_E_RX_PAGING_FAILURE:
		/* do nothing */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 4.2.2.1 SGs-LA-UPDATE-PRESENT */
static void sgs_ue_fsm_lau_present(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_UE_E_TX_LU_ACCEPT:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_ASSOCIATED, 0, 0);
		break;
	case SGS_UE_E_TX_LU_REJECT:
	case SGS_UE_E_RX_PAGING_FAILURE:
	case SGS_UE_E_RX_ALERT_FAILURE:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_NULL, 0, 0);
		break;
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 4.2.2.1 SGs-ASSOCIATED */
static void sgs_ue_fsm_associated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_UE_E_TX_PAGING:
		/* do nothing */
		break;
	case SGS_UE_E_RX_TMSI_REALLOC:
		/* do nothing */
		break;
	case SGS_UE_E_RX_SGSAP_UE_UNRECHABLE:
		/* do nothing */
		break;
	case SGS_UE_E_RX_PAGING_FAILURE:
	case SGS_UE_E_RX_ALERT_FAILURE:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_NULL, 0, 0);
		break;
	case SGS_UE_E_RX_LU_FROM_MME:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_LA_UPD_PRES, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 4.2.2.1 From any of the three states (at the VLR) */
static void sgs_ue_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_UE_E_VLR_FAILURE:
	case SGS_UE_E_RX_RESET_FROM_MME:
	case SGS_UE_E_RX_DETACH_IND_FROM_MME:
	case SGS_UE_E_RX_DETACH_IND_FROM_UE:
	case SGS_UE_E_RX_LU_FROM_A_IU_GS:
		osmo_fsm_inst_state_chg(fi, SGS_UE_ST_NULL, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int sgs_ue_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 0;
}

static const struct osmo_fsm_state sgs_ue_fsm_states[] = {
	[SGS_UE_ST_NULL] = {
		.name = "SGs-NULL",
		.action = sgs_ue_fsm_null,
		.in_event_mask = S(SGS_UE_E_RX_LU_FROM_MME) |
				 S(SGS_UE_E_TX_PAGING) |
				 S(SGS_UE_E_RX_PAGING_FAILURE),
		.out_state_mask = S(SGS_UE_ST_NULL) |
				  S(SGS_UE_ST_LA_UPD_PRES),
	},
	[SGS_UE_ST_ASSOCIATED] = {
		.name = "SGs-ASSOCIATED",
		.action = sgs_ue_fsm_associated,
		.in_event_mask = S(SGS_UE_E_TX_PAGING) |
				 S(SGS_UE_E_RX_TMSI_REALLOC) |
				 S(SGS_UE_E_RX_SGSAP_UE_UNRECHABLE) |
				 S(SGS_UE_E_RX_PAGING_FAILURE) |
				 S(SGS_UE_E_RX_ALERT_FAILURE) |
				 S(SGS_UE_E_RX_LU_FROM_MME),
		.out_state_mask = S(SGS_UE_ST_NULL) |
				  S(SGS_UE_ST_ASSOCIATED) |
				  S(SGS_UE_ST_LA_UPD_PRES),
	},
	[SGS_UE_ST_LA_UPD_PRES] = {
		.name = "SGs-LA-UPDATE-PRESENT",
		.action = sgs_ue_fsm_lau_present,
		.in_event_mask = S(SGS_UE_E_TX_LU_ACCEPT) |
				 S(SGS_UE_E_TX_LU_REJECT) |
				 S(SGS_UE_E_TX_PAGING) |
				 S(SGS_UE_E_RX_PAGING_FAILURE) |
				 S(SGS_UE_E_RX_ALERT_FAILURE),
		.out_state_mask = S(SGS_UE_ST_NULL) |
				  S(SGS_UE_ST_ASSOCIATED) |
				  S(SGS_UE_ST_LA_UPD_PRES),
	},
};

static struct osmo_fsm sgs_ue_fsm = {
	.name = "SGs-UE",
	.states = sgs_ue_fsm_states,
	.allstate_event_mask =	S(SGS_UE_E_RX_RESET_FROM_MME) |
				S(SGS_UE_E_VLR_FAILURE) |
				S(SGS_UE_E_RX_DETACH_IND_FROM_MME) |
				S(SGS_UE_E_RX_DETACH_IND_FROM_UE) |
				S(SGS_UE_E_RX_LU_FROM_A_IU_GS),
	.allstate_action = sgs_ue_fsm_allstate,
	.timer_cb = sgs_ue_fsm_timer_cb,
	.log_subsys = DSGS,
	.event_names = sgs_ue_fsm_event_names,
};





/***********************************************************************
 * SGs utility functions
 ***********************************************************************/

struct sgs_state *sgs_state_alloc(void *ctx)
{
	struct sgs_state *sgs = talloc_zero(ctx, struct sgs_state);

	INIT_LLIST_HEAD(&sgs->mme_list);
	INIT_LLIST_HEAD(&sgs->conn_list);

	memcpy(sgs->cfg.timer, sgs_state_timer_defaults, sizeof(sgs->cfg.timer));
	memcpy(sgs->cfg.counter, sgs_state_counter_defaults, sizeof(sgs->cfg.counter));

	return sgs;
}

struct sgs_mme_ctx *sgs_mme_by_fqdn(struct sgs_state *sgs, const char *mme_fqdn)
{
	struct sgs_mme_ctx *mme;

	llist_for_each_entry(mme, &sgs->mme_list, list) {
		if (!strcasecmp(mme_fqdn, mme->fqdn))
			return mme;
	}
	return NULL;
}

static struct sgs_mme_ctx *sgs_mme_alloc(struct sgs_state *sgs, const char *mme_fqdn,
					 const struct osmo_gummei *gummei)
{
	struct sgs_mme_ctx *mme;

	OSMO_ASSERT(sgs_mme_by_fqdn(sgs, mme_fqdn) == NULL);

	mme = talloc_zero(sgs, struct sgs_mme_ctx);
	if (!mme)
		return NULL;
	mme->sgs = sgs;
	OSMO_STRLCPY_ARRAY(mme->fqdn, mme_fqdn);
	mme->fi = osmo_fsm_inst_alloc(&sgs_vlr_reset_fsm, mme, mme, LOGL_INFO, osmo_gummei_name(gummei));
	if (!mme->fi) {
		talloc_free(mme);
		return NULL;
	}
	llist_add_tail(&mme->list, &sgs->mme_list);
	return mme;
}

/* A MME FQDN was received (e.g. RESET-IND/RESET-ACK/LU-REQ) */
static int sgs_mme_fqdn_received(struct sgs_connection *sgc, const char *mme_fqdn)
{
	struct sgs_mme_ctx *mme;
	struct osmo_gummei gummei;

	/* caller must pass in a valid FQDN string syntax */
	OSMO_ASSERT(osmo_parse_mme_domain(&gummei, mme_fqdn) == 0);

	if (!sgc->mme) {
		/* attempt to find MME with given name */
		mme = sgs_mme_by_fqdn(sgc->sgs, mme_fqdn);
		if (!mme)
			mme = sgs_mme_alloc(sgc->sgs, mme_fqdn, &gummei);
		OSMO_ASSERT(mme);

		if (mme->conn) {
			/* The MME context has another connection !?! */
			LOGSGC(sgc, LOGL_ERROR, "Rx MME name %s, but that MME already has other "
				"SCTP connection?!?\n", mme_fqdn);
			return -1;
		} else {
			/* associate the two */
			mme->conn = sgc;
			sgc->mme = mme;
		}
	} else {
		mme = sgc->mme;
		if (!strcasecmp(mme->fqdn, mme_fqdn)) {
			LOGMME(mme, LOGL_ERROR, "Rx MME name %s in packet from MME %s ?!?\n",
				mme_fqdn, mme->fqdn);
			return -2;
		}
	}
	return 0;
}







/***********************************************************************
 * SGs incoming messages from the MME
 ***********************************************************************/

static void sgs_rx_status(struct sgs_connection *sgc, struct msgb *msg, struct tlv_parsed *tp)
{
	uint8_t cause = *TLVP_VAL_MINLEN(tp, SGSAP_IE_SGS_CAUSE, 1);
	const uint8_t *err_msg;
	char imsi[32];

	if (TLVP_PRESENT(tp, SGSAP_IE_IMSI)) {
		gsm48_mi_to_string(imsi, sizeof(imsi),
				TLVP_VAL(tp, SGSAP_IE_IMSI), TLVP_LEN(tp, SGSAP_IE_IMSI));
	} else
		OSMO_STRLCPY_ARRAY(imsi, "<none>");

	if (TLVP_PRESENT(tp, SGSAP_IE_ERR_MSG))
		err_msg = TLVP_VAL(tp, SGSAP_IE_ERR_MSG);
	else
		err_msg = NULL;

	LOGSGC(sgc, LOGL_NOTICE, "Rx STATUS cause=%s, IMSI=%s, orig_msg=%s\n",
		sgsap_sgs_cause_name(cause), imsi,
		err_msg ? osmo_hexdump(err_msg, TLVP_LEN(tp, SGSAP_IE_ERR_MSG)) : "");
}

static void sgs_rx_reset_ind(struct sgs_connection *sgc, struct msgb *msg, const struct tlv_parsed *tp)
{
	const uint8_t *mme_name_enc = TLVP_VAL_MINLEN(tp, SGSAP_IE_MME_NAME, 55);
	struct osmo_gummei gummei;
	char mme_name[55+1];

	if (!mme_name_enc) {
		LOGSGC(sgc, LOGL_NOTICE, "Rx SGsAP-RESET-IND with no/short MME name\n");
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MISSING_MAND_IE, tp, msg);
		return;
	}
	/* decode the MME name from DNS labels to string */
	osmo_apn_to_str(mme_name, TLVP_VAL(tp, SGSAP_IE_MME_NAME), TLVP_LEN(tp, SGSAP_IE_MME_NAME));
	/* try to parse the MME name into a GUMMEI as a test for the format */
	if (osmo_parse_mme_domain(&gummei, mme_name) < 0) {
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_INVALID_MAND_IE, tp, msg);
		return;
	}

	if (sgs_mme_fqdn_received(sgc, mme_name) < 0) {
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MSG_INCOMP_STATE, tp, msg);
		return;
	}

	/* FIXME: actually reset the per-UE state to SGs-NULL for all UE served by this MME! */

	sgs_tx_reset_ack_vlr(sgc, sgc->sgs->cfg.vlr_name);
}

static void sgs_rx_reset_ack(struct sgs_connection *sgc, struct msgb *msg, const struct tlv_parsed *tp)
{
	const uint8_t *mme_name_enc = TLVP_VAL_MINLEN(tp, SGSAP_IE_MME_NAME, 55);
	struct osmo_gummei gummei;
	char mme_name[55+1];

	if (!mme_name_enc) {
		LOGSGC(sgc, LOGL_NOTICE, "Rx SGsAP-RESET-ACK with no/short MME name\n");
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MISSING_MAND_IE, tp, msg);
		return;
	}
	/* decode the MME name from DNS labels to string */
	osmo_apn_to_str(mme_name, TLVP_VAL(tp, SGSAP_IE_MME_NAME), TLVP_LEN(tp, SGSAP_IE_MME_NAME));
	/* try to parse the MME name into a GUMMEI as a test for the format */
	if (osmo_parse_mme_domain(&gummei, mme_name) < 0) {
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_INVALID_MAND_IE, tp, msg);
		return;
	}

	if (sgs_mme_fqdn_received(sgc, mme_name) < 0)
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MSG_INCOMP_STATE, tp, msg);

	/* dispatch even to VLR reset FSM for this MME */
	if (sgc->mme && sgc->mme->fi)
		osmo_fsm_inst_dispatch(sgc->mme->fi, SGS_VLRR_E_RX_RESET_ACK, msg);
}


int sgs_rx(struct sgs_connection *sgc, struct msgb *msg)
{
	uint8_t msg_type = msg->l2h[0];
	struct tlv_parsed tp;
	int rc;

	if (msgb_l2len(msg) < 1) {
		/* When the receiving entity receives a message that is too short to contain a complete
		 * message type information element, the receiving entity shall ignore that message. */
		sgs_tx_status(sgc, SGSAP_SGS_CAUSE_MISSING_MAND_IE, NULL, msg);
		msgb_free(msg);
		return 0;
	}

	rc = tlv_parse(&tp, &sgsap_ie_tlvdef, msgb_l2(msg)+1, msgb_l2len(msg)-1, 0, 0);
	if (rc < 0) {
		LOGSGC(sgc, LOGL_NOTICE, "SGsAP Message %s parsing error\n",
			sgsap_msg_type_name(msg_type));
		sgs_tx_status(sgc, SGSAP_SGS_CAUSE_SEMANT_INCORR_MSG, NULL, msg);
		msgb_free(msg);
		return 0;
	}

	if (!TLVP_PRESENT(&tp, SGSAP_IE_IMSI) &&
	    msg_type != SGSAP_MSGT_STATUS &&
	    msg_type != SGSAP_MSGT_RESET_IND &&
	    msg_type != SGSAP_MSGT_RESET_ACK) {
		/* reject the message; all but the three above have mandatory IMSI */
		LOGSGC(sgc, LOGL_NOTICE, "SGsAP Message %s without IMSI, dropping\n",
			sgsap_msg_type_name(msg_type));
		sgs_tx_status(sgc, SGSAP_SGS_CAUSE_MISSING_MAND_IE, NULL, msg);
		msgb_free(msg);
		return 0;
	}

	/* dispatch msg to various handler functions.  msgb ownership remains here! */
	switch (msg_type) {
	case SGSAP_MSGT_STATUS:
		sgs_rx_status(sgc, msg, &tp);
		break;
	case SGSAP_MSGT_RESET_IND:
		sgs_rx_reset_ind(sgc, msg, &tp);
		break;
	case SGSAP_MSGT_RESET_ACK:
		sgs_rx_reset_ack(sgc, msg, &tp);
		break;
	case SGSAP_MSGT_LOC_UPD_REQ:
	case SGSAP_MSGT_TMSI_REALL_CMPL:
	case SGSAP_MSGT_EPS_DET_IND:
	case SGSAP_MSGT_IMSI_DET_IND:
	case SGSAP_MSGT_ALERT_ACK:
	case SGSAP_MSGT_ALERT_REJ:
	case SGSAP_MSGT_PAGING_REJ:
	case SGSAP_MSGT_UE_ACT_IND:
	case SGSAP_MSGT_UE_UNREACHABLE:
	case SGSAP_MSGT_UL_UD:
	case SGSAP_MSGT_SERVICE_REQ:
	case SGSAP_MSGT_MO_CSFB_IND:
		LOGSGC(sgc, LOGL_NOTICE, "Rx unmplemented SGsAP %s: %s\n",
			sgsap_msg_type_name(msg_type), msgb_hexdump(msg));
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MSG_UNKNOWN, &tp, msg);
		break;
	default:
		LOGSGC(sgc, LOGL_NOTICE, "Rx unknown SGsAP message type 0x%02x: %s\n",
			msg_type, msgb_hexdump(msg));
		sgs_tx_status_tp(sgc, SGSAP_SGS_CAUSE_MSG_UNKNOWN, &tp, msg);
		break;
	}
	msgb_free(msg);
	return 0;
}



/***********************************************************************
 * SGs connection "VLR Reset Procedure" FSM
 ***********************************************************************/

static const struct value_string sgs_vlr_reset_fsm_event_names[] = {
	{ SGS_VLRR_E_START_RESET, "START-RESET" },
	{ SGS_VLRR_E_RX_RESET_ACK, "RX-RESET-ACK" },
	{ 0, NULL }
};

static void sgs_vlr_reset_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_VLRR_E_RX_RESET_ACK:
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void sgs_vlr_reset_fsm_wait_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_VLRR_E_RX_RESET_ACK:
		osmo_fsm_inst_state_chg(fi, SGS_VLRR_ST_COMPLETE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void sgs_vlr_reset_fsm_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SGS_VLRR_E_RX_RESET_ACK:
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void sgs_vlr_reset_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgs_mme_ctx *mme = (struct sgs_mme_ctx *) fi->priv;
	struct sgs_connection *sgc = mme->conn;
	struct sgs_state *sgs = mme->sgs;

	switch (event) {
	case SGS_VLRR_E_START_RESET:
		osmo_fsm_inst_state_chg(fi, SGS_VLRR_ST_NULL, 0, 0);
		mme->ns11_remaining = sgs->cfg.counter[SGS_STATE_NS11];
		/* send a reset message and enter WAIT_ACK state */
		sgs_tx_reset_ind_vlr(sgc, sgs->cfg.vlr_name);
		osmo_fsm_inst_state_chg(fi, SGS_VLRR_ST_WAIT_ACK, sgs->cfg.timer[SGS_STATE_TS11], 11);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static int sgs_vlr_reset_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct sgs_mme_ctx *mme = (struct sgs_mme_ctx *) fi->priv;
	struct sgs_connection *sgc = mme->conn;
	struct sgs_state *sgs = mme->sgs;

	switch (fi->T) {
	case 11:
		if (mme->ns11_remaining >= 1) {
			sgs_tx_reset_ind_vlr(sgc, sgc->sgs->cfg.vlr_name);
			osmo_fsm_inst_state_chg(fi, SGS_VLRR_ST_WAIT_ACK, sgs->cfg.timer[SGS_STATE_TS11], 11);
			mme->ns11_remaining--;
		} else {
			LOGMME(mme, LOGL_ERROR, "Ts11 expired more than Ns11 times, giving up\n");
			osmo_fsm_inst_state_chg(fi, SGS_VLRR_ST_NULL, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
	return 0;
}


static const struct osmo_fsm_state sgs_vlr_reset_fsm_states[] = {
	[SGS_VLRR_ST_NULL] = {
		/* We haven't even tried yet to send a RESET */
		.name = "NULL",
		.action = sgs_vlr_reset_fsm_null,
		.in_event_mask = S(SGS_VLRR_E_RX_RESET_ACK),
		.out_state_mask = S(SGS_VLRR_ST_NULL) |
				  S(SGS_VLRR_ST_WAIT_ACK),
	},
	[SGS_VLRR_ST_WAIT_ACK] = {
		/* We're waiting for a SGsAP_RESET_ACK */
		.name = "WAIT-ACK",
		.action = sgs_vlr_reset_fsm_wait_ack,
		.in_event_mask = S(SGS_VLRR_E_RX_RESET_ACK),
		.out_state_mask = S(SGS_VLRR_ST_NULL) |
				  S(SGS_VLRR_ST_COMPLETE) |
				  S(SGS_VLRR_ST_WAIT_ACK),
	},
	[SGS_VLRR_ST_COMPLETE] = {
		/* Reset procedure to this MME has been completed */
		.name = "COMPLETE",
		.action = sgs_vlr_reset_fsm_complete,
		.in_event_mask = S(SGS_VLRR_E_RX_RESET_ACK),
		.out_state_mask = S(SGS_VLRR_ST_NULL) |
				  S(SGS_VLRR_ST_COMPLETE),
	},
};

static struct osmo_fsm sgs_vlr_reset_fsm = {
	.name = "SGs-VLR-RESET",
	.states = sgs_vlr_reset_fsm_states,
	.allstate_event_mask =	S(SGS_VLRR_E_START_RESET),
	.allstate_action = sgs_vlr_reset_fsm_allstate,
	.timer_cb = sgs_vlr_reset_fsm_timer_cb,
	.log_subsys = DSGS,
	.event_names = sgs_vlr_reset_fsm_event_names,
};







/***********************************************************************
 * SGs VTY
 ***********************************************************************/

#include <osmocom/msc/vty.h>

struct cmd_node cfg_sgs_node = {
	CFG_SGS_NODE,
	"%s(config-sgs)# ",
	1
};

DEFUN(cfg_sgs, cfg_sgs_cmd, "sgs", "Configure the SGs interface\n")
{
	vty->index = g_sgs;
	vty->node = CFG_SGS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_local_ip, cfg_sgs_local_ip_cmd,
	"local-ip A.B.C.D",
	"Set the Local IP Address of the SGs interface\n"
	"Local IP Address of the SGs interface\n")
{
	struct sgs_state *sgs = vty->index;
	int rc;

	osmo_stream_srv_link_set_addr(sgs->srv_link, argv[0]);

	rc = sgs_open(sgs);
	if (rc < 0) {
		vty_out(vty, "%% SGs socket cannot be opened: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_local_port, cfg_sgs_local_port_cmd,
	"local-port <0-65535>",
	"Set the local SCTP port of the SGs interface\n"
	"Local SCTP port of the SGs interface\n")
{
	struct sgs_state *sgs = vty->index;
	int rc;

	osmo_stream_srv_link_set_port(sgs->srv_link, atoi(argv[0]));

	rc = sgs_open(sgs);
	if (rc < 0) {
		vty_out(vty, "%% SGs socket cannot be opened: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_vlr_name, cfg_sgs_vlr_name_cmd,
	"vlr-name FQDN",
	"Set the SGs VLR Name as per TS 29.118 9.4.22\n"
	"Fully-Qualified Domain Name of this VLR\n")
{
	struct sgs_state *sgs = vty->index;
	osmo_talloc_replace_string(sgs, &sgs->cfg.vlr_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_sgs_timer, cfg_sgs_timer_cmd,
	"timer (Ts5|TS6-2|Ts7|Ts11|Ts14|Ts15) <1-120>",
	"Configure SGs Timer\n"
	"Paging procedure guard timer\n"
	"TMSI reallocation guard timer\n"
	"Non-EPS alert procedure guard timer\n"
	"VLR reset guard timer\n"
	"UE fallback prcoedure timer\n"
	"MO UE fallback procedure guard timer\n"
	"Time in seconds\n")
{
	struct sgs_state *sgs = vty->index;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.timer); i++) {
		if (!strcmp(argv[0], sgs_state_timer_names[i])) {
			sgs->cfg.timer[i] = atoi(argv[1]);
			return CMD_SUCCESS;
		}
	}

	return CMD_WARNING;
}

DEFUN(cfg_sgs_counter, cfg_sgs_counter_cmd,
	"counter (Ns7|Ns11) <0-255>",
	"Configure SGs Counter\n"
	"Non-EPS alert request retry counter\n"
	"VLR reset retry counter\n"
	"Counter value\n")
{
	struct sgs_state *sgs = vty->index;
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.counter); i++) {
		if (!strcmp(argv[0], sgs_state_counter_names[i])) {
			sgs->cfg.counter[i] = atoi(argv[1]);
			return CMD_SUCCESS;
		}
	}

	return CMD_WARNING;
}


DEFUN(show_sgs_conn, show_sgs_conn_cmd,
	"show sgs-connections",
	SHOW_STR "Show SGs interface connections / MMEs\n")
{
	struct sgs_connection *sgc;

	llist_for_each_entry(sgc, &g_sgs->conn_list, list) {
		vty_out(vty, " %s %s%s", sgc->sockname, sgc->mme ? sgc->mme->fqdn: "", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int config_write_sgs(struct vty *vty)
{
	struct sgs_state *sgs = vty->index;
	unsigned int i;

	vty_out(vty, "sgs%s", VTY_NEWLINE);
	if (sgs->cfg.local_port != 29118)
		vty_out(vty, " local-port %u%s", sgs->cfg.local_port, VTY_NEWLINE);
	if (sgs->cfg.local_addr)
		vty_out(vty, " local-ip %s%s", sgs->cfg.local_addr, VTY_NEWLINE);
	if (sgs->cfg.vlr_name)
		vty_out(vty, " vlr-name %s%s", sgs->cfg.vlr_name, VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.timer); i++) {
		if (sgs->cfg.timer[i] == sgs_state_timer_defaults[i])
			continue;
		vty_out(vty, " timer %s %u%s", sgs_state_timer_names[i],
			sgs->cfg.timer[i], VTY_NEWLINE);
	}

	for (i = 0; i < ARRAY_SIZE(sgs->cfg.counter); i++) {
		if (sgs->cfg.timer[i] == sgs_state_counter_defaults[i])
			continue;
		vty_out(vty, " counter %s %u%s", sgs_state_counter_names[i],
			sgs->cfg.counter[i], VTY_NEWLINE);
	}

	return 1;
}

void sgs_vty_init(void)
{
	/* configuration commands / nodes */
	install_element(CONFIG_NODE, &cfg_sgs_cmd);
	install_node(&cfg_sgs_node, config_write_sgs);
	install_element(CFG_SGS_NODE, &cfg_sgs_local_ip_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_local_port_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_timer_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_counter_cmd);
	install_element(CFG_SGS_NODE, &cfg_sgs_vlr_name_cmd);

	install_element_ve(&show_sgs_conn_cmd);
}

/***********************************************************************
 * SGs connection server
 ***********************************************************************/

#include <netinet/sctp.h>

static int sgs_conn_readable_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct sgs_connection *sgc = osmo_stream_srv_get_data(conn);
	struct msgb *msg = sgs_msgb_alloc();
	struct sctp_sndrcvinfo sinfo;
	int flags = 0;
	int rc;

	/* we cannot use osmo_stream_srv_recv() here, as we might get some out-of-band info from
	 * SCTP.  FIXME: add something like osmo_stream_srv_recv_sctp() to libosmo-netif and use
	 * it here as well as in libosmo-sigtran */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg), NULL, NULL, &sinfo, &flags);
	if (rc < 0) {
		osmo_stream_srv_destroy(conn);
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			break;
		case SCTP_ASSOC_CHANGE:
			/* do we have to notify the SGs code about this? */
			break;
		default:
			break;
		}
		rc = 0;
		goto out;
	}

	/* set l2 header, as that's what we use in SGs code */
	msg->l2h = msgb_data(msg);

	if (msgb_sctp_ppid(msg) != 0) {
		LOGSGC(sgc, LOGL_NOTICE, "Ignoring SCTP PPID %ld (spec violation)\n",
			msgb_sctp_ppid(msg));
		msgb_free(msg);
		return 0;
	}
	/* handle message */
	sgs_rx(sgc, msg);

	return 0;
out:
	msgb_free(msg);
	return rc;
}

static int sgs_conn_closed_cb(struct osmo_stream_srv *conn)
{
	struct sgs_connection *sgc = osmo_stream_srv_get_data(conn);

	LOGSGC(sgc, LOGL_NOTICE, "Connection lost\n");
	if (sgc->mme) {
		/* unlink ourselves from the MME context */
		if (sgc->mme->conn == sgc)
			sgc->mme->conn = NULL;
	}
	llist_del(&sgc->list);
	return 0;
}


/* call-back when new connection is accept() ed on SGs */
static int sgs_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct sgs_state *sgs = osmo_stream_srv_link_get_data(link);
	struct sgs_connection *sgc = talloc_zero(link, struct sgs_connection);
	OSMO_ASSERT(sgc);
	sgc->sgs = sgs;
	sgc->sockname = osmo_sock_get_name(sgc, fd);
	sgc->srv = osmo_stream_srv_create(sgc, link, fd, sgs_conn_readable_cb, sgs_conn_closed_cb, sgc);
	if (!sgc->srv) {
		talloc_free(sgc);
		return -1;
	}
	LOGSGC(sgc, LOGL_INFO, "Accepted new SGs connection\n");
	llist_add_tail(&sgc->list, &sgs->conn_list);

	return 0;
}

/* global init function */
struct sgs_state *sgs_init(void *ctx)
{
	struct sgs_state *sgs;
	struct osmo_stream_srv_link *link;

	sgs = sgs_state_alloc(ctx);
	OSMO_ASSERT(sgs);

	/* We currently only support one SGs instance */
	OSMO_ASSERT(!g_sgs);
	g_sgs = sgs;

	osmo_fsm_register(&sgs_vlr_reset_fsm);
	osmo_fsm_register(&sgs_ue_fsm);

	sgs->srv_link = link = osmo_stream_srv_link_create(ctx);
	OSMO_ASSERT(sgs->srv_link);
	osmo_stream_srv_link_set_nodelay(link, true);
	//osmo_stream_srv_link_set_addr(link, local_ip);
	osmo_stream_srv_link_set_port(link, 29118);
	osmo_stream_srv_link_set_proto(link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(link, sgs);
	osmo_stream_srv_link_set_accept_cb(link, sgs_accept_cb);
	sgs_open(sgs);

	return sgs;
}

static int sgs_open(struct sgs_state *sgs)
{
	int rc;
	struct osmo_fd *ofd = osmo_stream_srv_link_get_ofd(sgs->srv_link);
	char *name;

	rc = osmo_stream_srv_link_open(sgs->srv_link);
	if (rc < 0) {
		LOGP(DSGS, LOGL_ERROR, "SGs socket cannot be opened: %s\n", strerror(errno));
		return rc;
	}
	name = osmo_sock_get_name(sgs, ofd->fd);
	LOGP(DSGS, LOGL_NOTICE, "SGs socket bound to %s\n", name);
	talloc_free(name);
	return 0;
}

