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
#include <osmocom/core/stat_item.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/crypt/utran_cipher.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include <osmocom/msc/msc_common.h>
#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/sms_queue.h>

#include "gsm_data_shared.h"
#include "osmux.h"

/** annotations for msgb ownership */
#define __uses

struct mncc_sock_state;
struct vlr_instance;
struct vlr_subscr;
struct gsup_client_mux;

#define SMS_DEFAULT_DB_FILE_PATH "sms.db"
#define tmsi_from_string(str) strtoul(str, NULL, 10)

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
	MSC_CTR_CM_RE_ESTABLISH_REQ_REJECTED,
	MSC_CTR_CM_RE_ESTABLISH_REQ_ACCEPTED,
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
	MSC_CTR_BSSMAP_CIPHER_MODE_REJECT,
	MSC_CTR_BSSMAP_CIPHER_MODE_COMPLETE,
};

static const struct rate_ctr_desc msc_ctr_description[] = {
	[MSC_CTR_LOC_UPDATE_TYPE_ATTACH] = 		{"loc_update_type:attach", "Received Location Update (IMSI Attach) requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_NORMAL] = 		{"loc_update_type:normal", "Received Location Update (LAC change) requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC] = 		{"loc_update_type:periodic", "Received (periodic) Location Update requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_DETACH] = 		{"loc_update_type:detach", "Received IMSI Detach indications."},
	[MSC_CTR_LOC_UPDATE_FAILED] = 		{"loc_update_resp:failed", "Rejected Location Update requests."},
	[MSC_CTR_LOC_UPDATE_COMPLETED] = 	{"loc_update_resp:completed", "Successful Location Update procedures."},
	[MSC_CTR_CM_SERVICE_REQUEST_REJECTED] = {"cm_service_request:rejected", "Rejected CM Service Requests."},
	[MSC_CTR_CM_SERVICE_REQUEST_ACCEPTED] = {"cm_service_request:accepted", "Accepted CM Service Requests."},
	[MSC_CTR_PAGING_RESP_REJECTED] = 	{"paging_resp:rejected", "Rejected Paging Responses."},
	[MSC_CTR_PAGING_RESP_ACCEPTED] = 	{"paging_resp:accepted", "Accepted Paging Responses."},
	[MSC_CTR_CM_RE_ESTABLISH_REQ_REJECTED] = {"cm_re_establish_request:rejected", "Rejected CM Re-Establishing Requests."},
	[MSC_CTR_CM_RE_ESTABLISH_REQ_ACCEPTED] = {"cm_re_establish_request:accepted", "Accepted CM Re-Establishing Requests."},
	[MSC_CTR_SMS_SUBMITTED] = 		{"sms:submitted", "Total MO SMS received from the MS."},
	[MSC_CTR_SMS_NO_RECEIVER] = 		{"sms:no_receiver", "Failed MO SMS delivery attempts (no receiver found)."},
	[MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR] =	{"sms:deliver_unknown_error", "Failed MO SMS delivery attempts (other reason)."},
	/* FIXME: "sms:delivered" should actually count number of _successfully_ delivered MT SMS.
	 * The current description reflects its current (errorneous) behaviour.  */
	[MSC_CTR_SMS_DELIVERED] = 		{"sms:delivered", "Total MT SMS delivery attempts."},
	[MSC_CTR_SMS_RP_ERR_MEM] = 		{"sms:rp_err_mem", "Failed MT SMS delivery attempts (no memory)."},
	[MSC_CTR_SMS_RP_ERR_OTHER] = 		{"sms:rp_err_other", "Failed MT SMS delivery attempts (other reason)."},
	[MSC_CTR_CALL_MO_SETUP] = 		{"call:mo_setup", "Received MO SETUP messages (MO call establishment)."},
	[MSC_CTR_CALL_MO_CONNECT_ACK] = 	{"call:mo_connect_ack", "Received MO CONNECT messages (MO call establishment)."},
	[MSC_CTR_CALL_MT_SETUP] = 		{"call:mt_setup", "Sent MT SETUP messages (MT call establishment)."},
	[MSC_CTR_CALL_MT_CONNECT] = 		{"call:mt_connect", "Sent MT CONNECT messages (MT call establishment)."},
	[MSC_CTR_CALL_ACTIVE] =			{"call:active", "Calls that ever reached the active state."},
	[MSC_CTR_CALL_COMPLETE] = 		{"call:complete", "Calls terminated by DISCONNECT message after reaching the active state."},
	[MSC_CTR_CALL_INCOMPLETE] = 		{"call:incomplete", "Calls terminated by any other reason after reaching the active state."},
	[MSC_CTR_NC_SS_MO_REQUESTS] = 		{"nc_ss:mo_requests", "Received MS-initiated call independent SS/USSD requests."},
	[MSC_CTR_NC_SS_MO_ESTABLISHED] = 	{"nc_ss:mo_established", "Established MS-initiated call independent SS/USSD sessions."},
	[MSC_CTR_NC_SS_MT_REQUESTS] = 		{"nc_ss:mt_requests", "Received network-initiated call independent SS/USSD requests."},
	[MSC_CTR_NC_SS_MT_ESTABLISHED] = 	{"nc_ss:mt_established", "Established network-initiated call independent SS/USSD sessions."},
	[MSC_CTR_BSSMAP_CIPHER_MODE_REJECT] =	{"bssmap:cipher_mode_reject", "Number of CIPHER MODE REJECT messages processed by BSSMAP layer"},
	[MSC_CTR_BSSMAP_CIPHER_MODE_COMPLETE] =	{"bssmap:cipher_mode_complete", "Number of CIPHER MODE COMPLETE messages processed by BSSMAP layer"},
};

enum {
	MSC_STAT_ACTIVE_CALLS,
	MSC_STAT_ACTIVE_NC_SS,
};

static const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"mobile switching center",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(msc_ctr_description),
	msc_ctr_description,
};

static const struct osmo_stat_item_desc msc_stat_item_description[] = {
	[MSC_STAT_ACTIVE_CALLS] = { "msc.active_calls", "Currently active calls "          , OSMO_STAT_ITEM_NO_UNIT, 4, 0},
	[MSC_STAT_ACTIVE_NC_SS]        = { "msc.active_nc_ss", "Currently active SS/USSD sessions", OSMO_STAT_ITEM_NO_UNIT, 4, 0},
};

static const struct osmo_stat_item_group_desc msc_statg_desc = {
	"net",
	"network statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(msc_stat_item_description),
	msc_stat_item_description,
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

	/* bit-mask of permitted encryption algorithms. LSB=UEA0, MSB=UEA7 */
	uint8_t uea_encryption_mask;

	struct rate_ctr_group *msc_ctrs;
	struct osmo_stat_item_group *statg;

	/* layer 4 */
	char *mncc_sock_path;
	struct mncc_sock_state *mncc_state;
	mncc_recv_cb_t mncc_recv;
	struct llist_head upqueue;
	struct osmo_tdef *mncc_tdefs;
	/*
	 * TODO: Move the trans_list into the RAN connection and
	 * create a pending list for MT transactions. These exist before
	 * we have a RAN connection.
	 */
	struct llist_head trans_list;

	/* Radio Resource Location Protocol (TS 04.31) */
	struct {
		enum rrlp_mode mode;
	} rrlp;

	struct gsm_sms_queue *sms_queue;

	/* The "SMS over GSUP" kill-switch that basically breaks internal
	 * SMS routing (i.e. SQLite DB and SMPP), and enables forwarding
	 * of short messages over GSUP towards ESME (through VLR and HLR).
	 * Please see OS#3587 for details. This is a temporary solution,
	 * so it should be removed as soon as we move the SMS processing
	 * logic to an external process (OsmoSMSC?). REMOVE ME! */
	bool sms_over_gsup;

	/* control interface */
	struct ctrl_handle *ctrl;

	/* if override is nonzero, this timezone data is used for all MM
	 * contexts. */
	/* TODO: in OsmoNITB, tz-override used to be BTS-specific. To enable
	 * BTS|RNC specific timezone overrides for multi-tz networks in
	 * OsmoMSC, this should be tied to the location area code (LAC). */
	struct gsm_tz tz;

	/* MSC: GSUP server address of the HLR */
	const char *gsup_server_addr_str;
	uint16_t gsup_server_port;
	struct gsup_client_mux *gcm;

	struct vlr_instance *vlr;

	/* Global MNCC guard timer value */
	int mncc_guard_timeout;
	/* Global guard timer value for NCSS sessions */
	int ncss_guard_timeout;

	struct {
		struct osmo_tdef *tdefs;
		struct mgcp_client_conf *conf;
		/* MGW pool, also includes the single MGCP client as fallback if no
		 * pool is configured. */
		struct mgcp_client_pool *mgw_pool;
	} mgw;

	struct {
		/* CS7 instance id number (set via VTY) */
		uint32_t cs7_instance;
		enum nsap_addr_enc rab_assign_addr_enc;

		struct sccp_ran_inst *sri;
	} iu;

	struct {
		/* CS7 instance id number (set via VTY) */
		uint32_t cs7_instance;

		struct sccp_ran_inst *sri;
	} a;

	struct {
		/* MSISDN to which to route MO emergency calls */
		char *route_to_msisdn;
	} emergency;

	/* This is transmitted as IPA Serial Number tag, which is used for GSUP routing (e.g. in OsmoHLR).
         * For inter-MSC handover, the remote MSC's neighbor configuration requires to match this name.
	 * If no name is set, the IPA Serial Number will be the same as the Unit Name,
	 * and will be of the form 'MSC-00-00-00-00-00-00' */
	char *msc_ipa_name;

	/* A list of neighbor BSCs. This list is defined statically via VTY and does not
	* necessarily correspond to BSCs attached to the A interface at a given moment. */
	struct llist_head neighbor_ident_list;

	struct {
		uint64_t range_start;
		uint64_t range_end;
		uint64_t next;
	} handover_number;

	/* Whether we want to use Osmux against BSCs. Controlled via VTY */
	enum osmux_usage use_osmux;

	/* Whether to use call waiting on the network */
	bool call_waiting;

	/* Whether to use lcls on the network */
	bool lcls_permitted;

	/* SMS queue config parameters */
	struct sms_queue_config *sms_queue_cfg;

	/* ASCI feature support */
	struct {
		bool enable;
		struct llist_head gcr_lists;
	} asci;
};

struct smpp_esme;

enum gsm_sms_source_id {
	SMS_SOURCE_UNKNOWN = 0,
	SMS_SOURCE_MS,		/* received from MS */
	SMS_SOURCE_VTY,		/* received from VTY */
	SMS_SOURCE_SMPP,	/* received via SMPP */
};

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
		struct smpp_esme *esme;
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
