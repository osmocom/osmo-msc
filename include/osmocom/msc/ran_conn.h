#pragma once
/* MSC RAN connection implementation */

#include <stdint.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/gsm/gsm_utils.h>

#define LOG_RAN_CONN(conn, level, fmt, args ...) \
	LOG_RAN_CONN_CAT(conn, (conn) ? (conn)->log_subsys : DMSC, level, fmt, ## args)

#define LOG_RAN_CONN_CAT(conn, subsys, level, fmt, args ...) \
	LOGPFSMSL((conn)? (conn)->fi : NULL, subsys, level, fmt, ## args)

#define VSUB_USE_CONN "conn"

enum ran_conn_fsm_event {
	/* Accepted the initial Complete Layer 3 (starting to evaluate Authentication and Ciphering) */
	RAN_CONN_E_COMPLETE_LAYER_3,
	/* Received Classmark Update, typically neede for Ciphering Mode Command */
	RAN_CONN_E_CLASSMARK_UPDATE,
	/* LU or Process Access FSM has determined that this conn is good */
	RAN_CONN_E_ACCEPTED,
	/* received first reply from MS in "real" CC, SMS, USSD communication */
	RAN_CONN_E_COMMUNICATING,
	/* Some async action has completed, check again whether all is done */
	RAN_CONN_E_RELEASE_WHEN_UNUSED,
	/* MS/BTS/BSC originated close request */
	RAN_CONN_E_MO_CLOSE,
	/* MSC originated close request, e.g. failed authentication */
	RAN_CONN_E_CN_CLOSE,
	/* The usage count for the conn has reached zero */
	RAN_CONN_E_UNUSED,
};

enum ran_conn_fsm_state {
	RAN_CONN_S_NEW,
	RAN_CONN_S_AUTH_CIPH,
	RAN_CONN_S_WAIT_CLASSMARK_UPDATE,
	RAN_CONN_S_ACCEPTED,
	RAN_CONN_S_COMMUNICATING,
	RAN_CONN_S_RELEASING,
	RAN_CONN_S_RELEASED,
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

#define MAX_A5_KEY_LEN	(128/8)

struct geran_encr {
	uint8_t alg_id;
	uint8_t key_len;
	uint8_t key[MAX_A5_KEY_LEN];
};

extern const struct value_string complete_layer3_type_names[];
static inline const char *complete_layer3_type_name(enum complete_layer3_type val)
{
	return get_value_string(complete_layer3_type_names, val);
}

struct gsm_classmark {
	bool classmark1_set;
	struct gsm48_classmark1 classmark1;
	uint8_t classmark2_len;
	uint8_t classmark2[3];
	uint8_t classmark3_len;
	uint8_t classmark3[14]; /* if cm3 gets extended by spec, it will be truncated */
};

/* active radio connection of a mobile subscriber */
struct ran_conn {
	/* global linked list of ran_conn instances */
	struct llist_head entry;

	/* FSM instance to control the RAN connection's permissions and lifetime. */
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

	/* Are we part of a special "silent" call */
	int silent_call;

	/* back pointers */
	struct gsm_network *network;

	/* connected via 2G or 3G? */
	enum osmo_rat_type via_ran;
	/* whether to log on DBSSAP, DIUCS, ... */
	int log_subsys;

	uint16_t lac;
	struct geran_encr geran_encr;

	/* "Temporary" storage for the case the VLR asked for Cipher Mode Command, but the MSC still
	 * wants to request a Classmark Update first. */
	struct {
		bool umts_aka;
		bool retrieve_imeisv;
	} geran_set_cipher_mode;

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
		 * with this RAN connection */
		struct osmo_sccp_addr bsc_addr;

		/* The connection identifier that is used
		 * to reference the SCCP connection that is
		 * associated with this RAN connection */
		uint32_t conn_id;

		bool waiting_for_clear_complete;
	} a;

	/* Temporary storage for Classmark Information for times when a connection has no VLR subscriber
	 * associated yet. It will get copied to the VLR subscriber upon msc_vlr_subscr_assoc(). */
	struct gsm_classmark temporary_classmark;
};

struct ran_conn *ran_conn_alloc(struct gsm_network *network, enum osmo_rat_type via_ran, uint16_t lac);

void ran_conn_update_id_from_mi(struct ran_conn *conn, const uint8_t *mi, uint8_t mi_len);
void ran_conn_update_id(struct ran_conn *conn);
const char *ran_conn_get_conn_id(struct ran_conn *conn);
void ran_conn_update_id_for_vsub(struct vlr_subscr *for_vsub);

void ran_conn_complete_layer_3(struct ran_conn *conn);

void ran_conn_sapi_n_reject(struct ran_conn *conn, int dlci);
int ran_conn_clear_request(struct ran_conn *conn, uint32_t cause);
void ran_conn_compl_l3(struct ran_conn *conn,
		       struct msgb *msg, uint16_t chosen_channel);
void ran_conn_dtap(struct ran_conn *conn, struct msgb *msg);
int ran_conn_classmark_request_then_cipher_mode_cmd(struct ran_conn *conn, bool umts_aka,
						    bool retrieve_imeisv);
int ran_conn_geran_set_cipher_mode(struct ran_conn *conn, bool umts_aka, bool retrieve_imeisv);
void ran_conn_cipher_mode_compl(struct ran_conn *conn, struct msgb *msg, uint8_t alg_id);
void ran_conn_rx_sec_mode_compl(struct ran_conn *conn);
void ran_conn_classmark_chg(struct ran_conn *conn,
			    const uint8_t *cm2, uint8_t cm2_len,
			    const uint8_t *cm3, uint8_t cm3_len);
void ran_conn_assign_fail(struct ran_conn *conn, uint8_t cause, uint8_t *rr_cause);

void ran_conn_init(void);
bool ran_conn_is_accepted(const struct ran_conn *conn);
bool ran_conn_is_establishing_auth_ciph(const struct ran_conn *conn);
void ran_conn_communicating(struct ran_conn *conn);
void ran_conn_close(struct ran_conn *conn, uint32_t cause);
void ran_conn_mo_close(struct ran_conn *conn, uint32_t cause);
bool ran_conn_in_release(struct ran_conn *conn);

void ran_conn_rx_bssmap_clear_complete(struct ran_conn *conn);
void ran_conn_rx_iu_release_complete(struct ran_conn *conn);
void ran_conn_sgs_release_sent(struct ran_conn *conn);

enum ran_conn_use {
	RAN_CONN_USE_UNTRACKED = -1,
	RAN_CONN_USE_COMPL_L3,
	RAN_CONN_USE_DTAP,
	RAN_CONN_USE_AUTH_CIPH,
	RAN_CONN_USE_CM_SERVICE,
	RAN_CONN_USE_TRANS_CC,
	RAN_CONN_USE_TRANS_SMS,
	RAN_CONN_USE_TRANS_NC_SS,
	RAN_CONN_USE_SILENT_CALL,
	RAN_CONN_USE_RELEASE,
};

extern const struct value_string ran_conn_use_names[];
static inline const char *ran_conn_use_name(enum ran_conn_use val)
{ return get_value_string(ran_conn_use_names, val); }

#define ran_conn_get(conn, balance_token) \
	_ran_conn_get(conn, balance_token, __FILE__, __LINE__)
#define ran_conn_put(conn, balance_token) \
	_ran_conn_put(conn, balance_token, __FILE__, __LINE__)
struct ran_conn * _ran_conn_get(struct ran_conn *conn, enum ran_conn_use balance_token,
				const char *file, int line);
void _ran_conn_put(struct ran_conn *conn, enum ran_conn_use balance_token,
		   const char *file, int line);
bool ran_conn_used_by(struct ran_conn *conn, enum ran_conn_use token);
