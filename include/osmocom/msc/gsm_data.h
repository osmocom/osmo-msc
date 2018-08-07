#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>
#include <regex.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/msc/common.h>
#include <osmocom/msc/common_cs.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include "gsm_data_shared.h"

/* TS 48.008 DLCI containing DCCH/ACCH + SAPI */
#define OMSC_LINKID_CB(__msgb)   (__msgb)->cb[3]

#include "../../bscconfig.h"
#if BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

/** annotations for msgb ownership */
#define __uses

struct mncc_sock_state;
struct vlr_instance;
struct vlr_subscr;
struct ranap_ue_conn_ctx;

#define tmsi_from_string(str) strtoul(str, NULL, 10)

struct msgb;
typedef int gsm_cbfn(unsigned int hooknum,
		     unsigned int event,
		     struct msgb *msg,
		     void *data, void *param);

struct gsm_auth_tuple {
	int use_count;
	int key_seq;
	struct osmo_auth_vector vec;
};
#define GSM_KEY_SEQ_INVAL	7	/* GSM 04.08 - 10.5.1.2 */

enum ran_type {
       RAN_UNKNOWN,
       RAN_GERAN_A,	/* 2G / A-interface */
       RAN_UTRAN_IU,	/* 3G / Iu-interface (IuCS or IuPS) */
};

extern const struct value_string ran_type_names[];
static inline const char *ran_type_name(enum ran_type val)
{	return get_value_string(ran_type_names, val);	}

struct gsm_classmark {
	bool classmark1_set;
	struct gsm48_classmark1 classmark1;
	uint8_t classmark2_len;
	uint8_t classmark2[3];
	uint8_t classmark3_len;
	uint8_t classmark3[14]; /* if cm3 gets extended by spec, it will be truncated */
};

enum integrity_protection_state {
	INTEGRITY_PROTECTION_NONE	= 0,
	INTEGRITY_PROTECTION_IK		= 1,
	INTEGRITY_PROTECTION_IK_CK	= 2,
};

enum complete_layer3_type {
	COMPLETE_LAYER3_NONE,
	COMPLETE_LAYER3_LU,
	COMPLETE_LAYER3_CM_SERVICE_REQ,
	COMPLETE_LAYER3_PAGING_RESP,
};

extern const struct value_string complete_layer3_type_names[];
static inline const char *complete_layer3_type_name(enum complete_layer3_type val)
{
	return get_value_string(complete_layer3_type_names, val);
}

/* active radio connection of a mobile subscriber */
struct gsm_subscriber_connection {
	/* global linked list of subscriber_connections */
	struct llist_head entry;

	/* FSM instance to control the subscriber connection's permissions and lifetime. */
	struct osmo_fsm_inst *fi;
	enum complete_layer3_type complete_layer3_type;

	/* usage count. If this drops to zero, we start the release
	 * towards A/Iu */
	uint32_t use_count;
	uint32_t use_tokens;

	/* The MS has opened the conn with a CM Service Request, and we shall
	 * keep it open for an actual request (or until timeout). */
	bool received_cm_service_request;

	/* libmsc/libvlr subscriber information (if available) */
	struct vlr_subscr *vsub;

	/* LU expiration handling */
	uint8_t expire_timer_stopped;
	/* SMS helpers for libmsc */
	uint8_t next_rp_ref;

	/* Are we part of a special "silent" call */
	int silent_call;

	/* MNCC rtp bridge markers */
	int mncc_rtp_bridge;

	/* back pointers */
	struct gsm_network *network;

	/* connected via 2G or 3G? */
	enum ran_type via_ran;

	struct gsm_classmark classmark;

	uint16_t lac;
	struct gsm_encr encr;

	/* N(SD) expected in the received frame, per flow (TS 24.007 11.2.3.2.3.2.2) */
	uint8_t n_sd_next[4];

	struct {
		struct mgcp_ctx *mgcp_ctx;
		unsigned int mgcp_rtp_endpoint;

		uint16_t local_port_ran;
		char local_addr_ran[INET_ADDRSTRLEN];
		uint16_t remote_port_ran;
		char remote_addr_ran[INET_ADDRSTRLEN];
		enum mgcp_codecs codec_ran;

		uint16_t local_port_cn;
		char local_addr_cn[INET_ADDRSTRLEN];
		uint16_t remote_port_cn;
		char remote_addr_cn[INET_ADDRSTRLEN];
		enum mgcp_codecs codec_cn;
	} rtp;

	/* which Iu-CS connection, if any. */
	struct {
		struct ranap_ue_conn_ctx *ue_ctx;
		uint8_t rab_id;
		bool waiting_for_release_complete;
	} iu;

	struct {
		/* A pointer to the SCCP user that handles
		 * the SCCP connections for this subscriber
		 * connection */
		struct osmo_sccp_user *scu;

		/* The address of the BSC that is associated
		 * with this subscriber connection */
		struct osmo_sccp_addr bsc_addr;

		/* The connection identifier that is used
		 * to reference the SCCP connection that is
		 * associated with this subscriber connection */
		uint32_t conn_id;

		bool waiting_for_clear_complete;
	} a;
};


enum {
	MSC_CTR_LOC_UPDATE_TYPE_ATTACH,
	MSC_CTR_LOC_UPDATE_TYPE_NORMAL,
	MSC_CTR_LOC_UPDATE_TYPE_PERIODIC,
	MSC_CTR_LOC_UPDATE_TYPE_DETACH,
	MSC_CTR_LOC_UPDATE_FAILED,
	MSC_CTR_LOC_UPDATE_COMPLETED,
	MSC_CTR_CM_SERVICE_REQUEST_REJECTED,
	MSC_CTR_CM_SERVICE_REQUEST_ACCEPTED,
	MSC_CTR_PAGING_RESP_REJECTED,
	MSC_CTR_PAGING_RESP_ACCEPTED,
	MSC_CTR_SMS_SUBMITTED,
	MSC_CTR_SMS_NO_RECEIVER,
	MSC_CTR_SMS_DELIVERED,
	MSC_CTR_SMS_RP_ERR_MEM,
	MSC_CTR_SMS_RP_ERR_OTHER,
	MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR,
	MSC_CTR_CALL_MO_SETUP,
	MSC_CTR_CALL_MO_CONNECT_ACK,
	MSC_CTR_CALL_MT_SETUP,
	MSC_CTR_CALL_MT_CONNECT,
	MSC_CTR_CALL_ACTIVE,
	MSC_CTR_CALL_COMPLETE,
	MSC_CTR_CALL_INCOMPLETE,
	MSC_CTR_NC_SS_MO_REQUESTS,
	MSC_CTR_NC_SS_MO_ESTABLISHED,
	MSC_CTR_NC_SS_MT_REQUESTS,
	MSC_CTR_NC_SS_MT_ESTABLISHED,
};

static const struct rate_ctr_desc msc_ctr_description[] = {
	[MSC_CTR_LOC_UPDATE_TYPE_ATTACH] = 		{"loc_update_type:attach", "Received location update imsi attach requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_NORMAL] = 		{"loc_update_type:normal", "Received location update normal requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC] = 		{"loc_update_type:periodic", "Received location update periodic requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_DETACH] = 		{"loc_update_type:detach", "Received location update detach indication."},
	[MSC_CTR_LOC_UPDATE_FAILED] = 		{"loc_update_resp:failed", "Rejected location updates."},
	[MSC_CTR_LOC_UPDATE_COMPLETED] = 	{"loc_update_resp:completed", "Successful location updates."},
	[MSC_CTR_CM_SERVICE_REQUEST_REJECTED] = {"cm_service_request:rejected", "Rejected CM Service Request."},
	[MSC_CTR_CM_SERVICE_REQUEST_ACCEPTED] = {"cm_service_request:accepted", "Accepted CM Service Request."},
	[MSC_CTR_PAGING_RESP_REJECTED] = 	{"paging_resp:rejected", "Rejected Paging Response."},
	[MSC_CTR_PAGING_RESP_ACCEPTED] = 	{"paging_resp:accepted", "Accepted Paging Response."},
	[MSC_CTR_SMS_SUBMITTED] = 		{"sms:submitted", "Received a RPDU from a MS (MO)."},
	[MSC_CTR_SMS_NO_RECEIVER] = 		{"sms:no_receiver", "Counts SMS which couldn't routed because no receiver found."},
	[MSC_CTR_SMS_DELIVERED] = 		{"sms:delivered", "Global SMS Deliver attempts."},
	[MSC_CTR_SMS_RP_ERR_MEM] = 		{"sms:rp_err_mem", "CAUSE_MT_MEM_EXCEEDED errors of MS responses on a sms deliver attempt."},
	[MSC_CTR_SMS_RP_ERR_OTHER] = 		{"sms:rp_err_other", "Other error of MS responses on a sms delive attempt."},
	[MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR] =	{"sms:deliver_unknown_error", "Unknown error occured during sms delivery."},
	/* FIXME: count also sms delivered */
	[MSC_CTR_CALL_MO_SETUP] = 		{"call:mo_setup", "Received setup requests from a MS to init a MO call."},
	[MSC_CTR_CALL_MO_CONNECT_ACK] = 		{"call:mo_connect_ack", "Received a connect ack from MS of a MO call. Call is now succesful connected up."},
	[MSC_CTR_CALL_MT_SETUP] = 		{"call:mt_setup", "Sent setup requests to the MS (MT)."},
	[MSC_CTR_CALL_MT_CONNECT] = 		{"call:mt_connect", "Sent a connect to the MS (MT)."},
	[MSC_CTR_CALL_ACTIVE] =			{"call:active", "Count total amount of calls that ever reached active state."},
	[MSC_CTR_CALL_COMPLETE] = 		{"call:complete", "Count total amount of calls which got terminated by disconnect req or ind after reaching active state."},
	[MSC_CTR_CALL_INCOMPLETE] = 		{"call:incomplete", "Count total amount of call which got terminated by any other reason after reaching active state."},
	[MSC_CTR_NC_SS_MO_REQUESTS] = 		{"nc_ss:mo_requests", "Received MS-initiated call independent SS/USSD requests."},
	[MSC_CTR_NC_SS_MO_ESTABLISHED] = 	{"nc_ss:mo_established", "Established MS-initiated call independent SS/USSD sessions."},
	[MSC_CTR_NC_SS_MT_REQUESTS] = 		{"nc_ss:mt_requests", "Received network-initiated call independent SS/USSD requests."},
	[MSC_CTR_NC_SS_MT_ESTABLISHED] = 	{"nc_ss:mt_established", "Established network-initiated call independent SS/USSD sessions."},
};

static const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"mobile switching center",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(msc_ctr_description),
	msc_ctr_description,
};

#define MSC_PAGING_RESPONSE_TIMER_DEFAULT 10

struct gsm_tz {
	int override; /* if 0, use system's time zone instead. */
	int hr; /* hour */
	int mn; /* minute */
	int dst; /* daylight savings */
};

struct gsm_network {
	/* TODO MSCSPLIT the gsm_network struct is basically a kitchen sink for
	 * global settings and variables, "madly" mixing BSC and MSC stuff. Split
	 * this in e.g. struct osmo_bsc and struct osmo_msc, with the things
	 * these have in common, like country and network code, put in yet
	 * separate structs and placed as members in osmo_bsc and osmo_msc. */

	struct osmo_plmn_id plmn;

	char *name_long;
	char *name_short;

	/* bit-mask of permitted encryption algorithms. LSB=A5/0, MSB=A5/7 */
	uint8_t a5_encryption_mask;
	bool authentication_required;
	int send_mm_info;
	struct {
		int active;
	} handover;

	struct rate_ctr_group *msc_ctrs;
	struct osmo_counter *active_calls;
	struct osmo_counter *active_nc_ss;

	/* layer 4 */
	struct mncc_sock_state *mncc_state;
	mncc_recv_cb_t mncc_recv;
	struct llist_head upqueue;
	/*
	 * TODO: Move the trans_list into the subscriber connection and
	 * create a pending list for MT transactions. These exist before
	 * we have a subscriber connection.
	 */
	struct llist_head trans_list;

	unsigned int paging_response_timer;

	/* Radio Resource Location Protocol (TS 04.31) */
	struct {
		enum rrlp_mode mode;
	} rrlp;

	struct gsm_sms_queue *sms_queue;

	/* control interface */
	struct ctrl_handle *ctrl;

	/* all active subscriber connections. */
	struct llist_head subscr_conns;

	/* if override is nonzero, this timezone data is used for all MM
	 * contexts. */
	/* TODO: in OsmoNITB, tz-override used to be BTS-specific. To enable
	 * BTS|RNC specific timezone overrides for multi-tz networks in
	 * OsmoMSC, this should be tied to the location area code (LAC). */
	struct gsm_tz tz;

	/* MSC: GSUP server address of the HLR */
	const char *gsup_server_addr_str;
	uint16_t gsup_server_port;

	struct vlr_instance *vlr;

	/* Periodic location update default value */
	uint8_t t3212;

	struct {
		struct mgcp_client_conf conf;
		struct mgcp_client *client;
	} mgw;

#if BUILD_IU
	struct {
		/* CS7 instance id number (set via VTY) */
		uint32_t cs7_instance;
		enum ranap_nsap_addr_enc rab_assign_addr_enc;
		struct osmo_sccp_instance *sccp;
	} iu;
#endif

	struct {
		/* CS7 instance id number (set via VTY) */
		uint32_t cs7_instance;
		/* A list with the context information about
		 * all BSCs we have connections with */
		struct llist_head bscs;
		struct osmo_sccp_instance *sccp;
	} a;

	struct {
		/* MSISDN to which to route MO emergency calls */
		char *route_to_msisdn;
	} emergency;
};

struct osmo_esme;

enum gsm_sms_source_id {
	SMS_SOURCE_UNKNOWN = 0,
	SMS_SOURCE_MS,		/* received from MS */
	SMS_SOURCE_VTY,		/* received from VTY */
	SMS_SOURCE_SMPP,	/* received via SMPP */
};

#define SMS_HDR_SIZE	128
#define SMS_TEXT_SIZE	256

struct gsm_sms_addr {
	uint8_t ton;
	uint8_t npi;
	char addr[21+1];
};

struct gsm_sms {
	unsigned long long id;
	struct vlr_subscr *receiver;
	struct gsm_sms_addr src, dst;
	enum gsm_sms_source_id source;

	struct {
		uint8_t transaction_id;
		uint32_t msg_ref;
	} gsm411;

	struct {
		struct osmo_esme *esme;
		uint32_t sequence_nr;
		int transaction_mode;
		char msg_id[16];
	} smpp;

	unsigned long validity_minutes;
	time_t created;
	bool is_report;
	uint8_t reply_path_req;
	uint8_t status_rep_req;
	uint8_t ud_hdr_ind;
	uint8_t protocol_id;
	uint8_t data_coding_scheme;
	uint8_t msg_ref;
	uint8_t user_data_len;
	uint8_t user_data[SMS_TEXT_SIZE];

	char text[SMS_TEXT_SIZE];
};

/* control interface handling */
int bsc_base_ctrl_cmds_install(void);
int msc_ctrl_cmds_install(struct gsm_network *net);

#endif /* _GSM_DATA_H */
