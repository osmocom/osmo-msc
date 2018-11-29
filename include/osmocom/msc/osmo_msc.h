/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/msc/gsm_data.h>

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

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

struct ran_conn *ran_conn_alloc(struct gsm_network *network, enum ran_type via_ran, uint16_t lac);

void ran_conn_update_id(struct ran_conn *conn, enum complete_layer3_type from, const char *id);
char *ran_conn_get_conn_id(struct ran_conn *conn);

void ran_conn_complete_layer_3(struct ran_conn *conn);

int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);

void msc_sapi_n_reject(struct ran_conn *conn, int dlci);
int msc_clear_request(struct ran_conn *conn, uint32_t cause);
void msc_compl_l3(struct ran_conn *conn,
		  struct msgb *msg, uint16_t chosen_channel);
void msc_dtap(struct ran_conn *conn, struct msgb *msg);
int msc_classmark_request_then_cipher_mode_cmd(struct ran_conn *conn, bool umts_aka,
					       bool retrieve_imeisv);
int msc_geran_set_cipher_mode(struct ran_conn *conn, bool umts_aka, bool retrieve_imeisv);
void msc_cipher_mode_compl(struct ran_conn *conn,
			   struct msgb *msg, uint8_t alg_id);
void msc_rx_sec_mode_compl(struct ran_conn *conn);
void msc_classmark_chg(struct ran_conn *conn,
		       const uint8_t *cm2, uint8_t cm2_len,
		       const uint8_t *cm3, uint8_t cm3_len);
void msc_assign_fail(struct ran_conn *conn,
		     uint8_t cause, uint8_t *rr_cause);

void ran_conn_init(void);
bool ran_conn_is_accepted(const struct ran_conn *conn);
bool ran_conn_is_establishing_auth_ciph(const struct ran_conn *conn);
void ran_conn_communicating(struct ran_conn *conn);
void ran_conn_close(struct ran_conn *conn, uint32_t cause);
void ran_conn_mo_close(struct ran_conn *conn, uint32_t cause);
bool ran_conn_in_release(struct ran_conn *conn);

void ran_conn_rx_bssmap_clear_complete(struct ran_conn *conn);
void ran_conn_rx_iu_release_complete(struct ran_conn *conn);

enum ran_conn_use {
	MSC_CONN_USE_UNTRACKED = -1,
	MSC_CONN_USE_COMPL_L3,
	MSC_CONN_USE_DTAP,
	MSC_CONN_USE_AUTH_CIPH,
	MSC_CONN_USE_CM_SERVICE,
	MSC_CONN_USE_TRANS_CC,
	MSC_CONN_USE_TRANS_SMS,
	MSC_CONN_USE_TRANS_NC_SS,
	MSC_CONN_USE_SILENT_CALL,
	MSC_CONN_USE_RELEASE,
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

void msc_stop_paging(struct vlr_subscr *vsub);

#endif
