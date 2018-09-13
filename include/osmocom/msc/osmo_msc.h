/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/msc/gsm_data.h>

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

enum subscr_conn_fsm_event {
	/* Mark 0 as invalid to catch uninitialized vars */
	SUBSCR_CONN_E_INVALID = 0,
	/* Accepted the initial Complete Layer 3 (starting to evaluate Authentication and Ciphering) */
	SUBSCR_CONN_E_COMPLETE_LAYER_3,
	/* Received Classmark Update, typically neede for Ciphering Mode Command */
	SUBSCR_CONN_E_CLASSMARK_UPDATE,
	/* LU or Process Access FSM has determined that this conn is good */
	SUBSCR_CONN_E_ACCEPTED,
	/* received first reply from MS in "real" CC, SMS, USSD communication */
	SUBSCR_CONN_E_COMMUNICATING,
	/* Some async action has completed, check again whether all is done */
	SUBSCR_CONN_E_RELEASE_WHEN_UNUSED,
	/* MS/BTS/BSC originated close request */
	SUBSCR_CONN_E_MO_CLOSE,
	/* MSC originated close request, e.g. failed authentication */
	SUBSCR_CONN_E_CN_CLOSE,
	/* The usage count for the conn has reached zero */
	SUBSCR_CONN_E_UNUSED,
};

enum subscr_conn_fsm_state {
	SUBSCR_CONN_S_NEW,
	SUBSCR_CONN_S_AUTH_CIPH,
	SUBSCR_CONN_S_WAIT_CLASSMARK_UPDATE,
	SUBSCR_CONN_S_ACCEPTED,
	SUBSCR_CONN_S_COMMUNICATING,
	SUBSCR_CONN_S_RELEASING,
	SUBSCR_CONN_S_RELEASED,
};

enum msc_compl_l3_rc {
	MSC_CONN_ACCEPT = 0,
	MSC_CONN_REJECT = 1,
};

struct gsm_subscriber_connection *msc_subscr_conn_alloc(struct gsm_network *network,
							enum ran_type via_ran, uint16_t lac);

void msc_subscr_conn_update_id(struct gsm_subscriber_connection *conn,
			       enum complete_layer3_type from, const char *id);
char *msc_subscr_conn_get_conn_id(struct gsm_subscriber_connection *conn);

void msc_subscr_conn_complete_layer_3(struct gsm_subscriber_connection *conn);

int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);

void msc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci);
int msc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);
int msc_compl_l3(struct gsm_subscriber_connection *conn,
		 struct msgb *msg, uint16_t chosen_channel);
void msc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id,
	      struct msgb *msg);
int msc_classmark_request_then_cipher_mode_cmd(struct gsm_subscriber_connection *conn, bool umts_aka,
					       bool retrieve_imeisv);
int msc_geran_set_cipher_mode(struct gsm_subscriber_connection *conn, bool umts_aka, bool retrieve_imeisv);
void msc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, uint8_t alg_id);
void msc_rx_sec_mode_compl(struct gsm_subscriber_connection *conn);
void msc_classmark_chg(struct gsm_subscriber_connection *conn,
		       const uint8_t *cm2, uint8_t cm2_len,
		       const uint8_t *cm3, uint8_t cm3_len);
void msc_assign_fail(struct gsm_subscriber_connection *conn,
		     uint8_t cause, uint8_t *rr_cause);

void msc_subscr_conn_init(void);
bool msc_subscr_conn_is_accepted(const struct gsm_subscriber_connection *conn);
bool msc_subscr_conn_is_establishing_auth_ciph(const struct gsm_subscriber_connection *conn);
void msc_subscr_conn_communicating(struct gsm_subscriber_connection *conn);
void msc_subscr_conn_close(struct gsm_subscriber_connection *conn,
			   uint32_t cause);
void msc_subscr_conn_mo_close(struct gsm_subscriber_connection *conn, uint32_t cause);
bool msc_subscr_conn_in_release(struct gsm_subscriber_connection *conn);

void msc_subscr_conn_rx_bssmap_clear_complete(struct gsm_subscriber_connection *conn);
void msc_subscr_conn_rx_iu_release_complete(struct gsm_subscriber_connection *conn);

enum msc_subscr_conn_use {
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

extern const struct value_string msc_subscr_conn_use_names[];
static inline const char *msc_subscr_conn_use_name(enum msc_subscr_conn_use val)
{ return get_value_string(msc_subscr_conn_use_names, val); }

#define msc_subscr_conn_get(conn, balance_token) \
	_msc_subscr_conn_get(conn, balance_token, __FILE__, __LINE__)
#define msc_subscr_conn_put(conn, balance_token) \
	_msc_subscr_conn_put(conn, balance_token, __FILE__, __LINE__)
struct gsm_subscriber_connection *
_msc_subscr_conn_get(struct gsm_subscriber_connection *conn,
		     enum msc_subscr_conn_use balance_token,
		     const char *file, int line);
void _msc_subscr_conn_put(struct gsm_subscriber_connection *conn,
			  enum msc_subscr_conn_use balance_token,
			  const char *file, int line);
bool msc_subscr_conn_used_by(struct gsm_subscriber_connection *conn,
			     enum msc_subscr_conn_use token);

void msc_stop_paging(struct vlr_subscr *vsub);

#endif
