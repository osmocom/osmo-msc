#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/msc_common.h>
#include <osmocom/gsupclient/gsup_client.h>

#define LOGGSUPP(level, gsup, fmt, args...)				\
	LOGP(DVLR, level, "GSUP(%s) " fmt, (gsup)->imsi, ## args)

#define LOGVSUBP(level, vsub, fmt, args...)				\
	LOGP(DVLR, level, "SUBSCR(%s) " fmt, vlr_subscr_name(vsub), ## args)

struct log_target;

#define VLR_SUBSCRIBER_NO_EXPIRATION	0
#define VLR_SUBSCRIBER_LU_EXPIRATION_INTERVAL	60	/* in seconds */

/* from 3s to 10s */
#define GSM_29002_TIMER_S	10
/* from 15s to 30s */
#define GSM_29002_TIMER_M	30
/* from 1min to 10min */
#define GSM_29002_TIMER_ML	(10*60)
/* from 28h to 38h */
#define GSM_29002_TIMER_L	(32*60*60)

/* VLR subscriber authentication state */
enum vlr_subscr_auth_state {
	/* subscriber needs to be autenticated */
	VLR_SUB_AS_NEEDS_AUTH,
	/* waiting for AuthInfo from HLR/AUC */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
	/* waiting for response from subscriber */
	VLR_SUB_AS_WAIT_RESP,
	/* successfully authenticated */
	VLR_SUB_AS_AUTHENTICATED,
	/* subscriber needs re-sync */
	VLR_SUB_AS_NEEDS_RESYNC,
	/* waiting for AuthInfo with ReSync */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
	/* waiting for response from subscr, resync case */
	VLR_SUB_AS_WAIT_RESP_RESYNC,
	/* waiting for IMSI from subscriber */
	VLR_SUB_AS_WAIT_ID_IMSI,
	/* authentication has failed */
	VLR_SUB_AS_AUTH_FAILED,
};

enum vlr_lu_event {
	VLR_ULA_E_UPDATE_LA,	/* Initial trigger (LU from MS) */
	VLR_ULA_E_SEND_ID_ACK,	/* Result of Send-ID from PVLR */
	VLR_ULA_E_SEND_ID_NACK,	/* Result of Send-ID from PVLR */
	VLR_ULA_E_AUTH_RES,	/* Result of auth procedure */
	VLR_ULA_E_CIPH_RES,	/* Result of Ciphering Mode Command */
	VLR_ULA_E_ID_IMSI,	/* IMSI recieved from MS */
	VLR_ULA_E_ID_IMEI,	/* IMEI received from MS */
	VLR_ULA_E_ID_IMEISV,	/* IMEISV received from MS */
	VLR_ULA_E_HLR_IMEI_ACK,	/* Check_IMEI_VLR result from HLR */
	VLR_ULA_E_HLR_IMEI_NACK,/* Check_IMEI_VLR result from HLR */
	VLR_ULA_E_HLR_LU_RES,	/* HLR UpdateLocation result */
	VLR_ULA_E_UPD_HLR_COMPL,/* UpdatE_HLR_VLR result */
	VLR_ULA_E_LU_COMPL_SUCCESS,/* Location_Update_Completion_VLR result */
	VLR_ULA_E_LU_COMPL_FAILURE,/* Location_Update_Completion_VLR result */
	VLR_ULA_E_NEW_TMSI_ACK,	/* TMSI Reallocation Complete */
};

enum vlr_ciph_result_cause {
	VLR_CIPH_REJECT, /* ? */
	VLR_CIPH_COMPL,
};

struct vlr_auth_tuple {
	int use_count;
	int key_seq;
	struct osmo_auth_vector vec;
};
#define VLR_KEY_SEQ_INVAL	7	/* GSM 04.08 - 10.5.1.2 */


struct vlr_ciph_result {
	enum vlr_ciph_result_cause cause;
	char imeisv[GSM48_MI_SIZE];
};

enum vlr_subscr_security_context {
	VLR_SEC_CTX_NONE,
	VLR_SEC_CTX_GSM,
	VLR_SEC_CTX_UMTS,
};

enum vlr_lu_type {
	VLR_LU_TYPE_PERIODIC,
	VLR_LU_TYPE_IMSI_ATTACH,
	VLR_LU_TYPE_REGULAR,
};

#define OSMO_LBUF_DECL(name, xlen)		\
	struct {				\
		uint8_t buf[xlen];		\
		size_t len;			\
	} name

struct sgsn_mm_ctx;
struct vlr_instance;

#define VLR_NAME_LENGTH 160
#define VLR_MSISDN_LENGTH 15

/* The VLR subscriber is the part of the GSM subscriber state in VLR (CS) or
 * SGSN (PS), particularly while interacting with the HLR via GSUP */
struct vlr_subscr {
	struct llist_head list;
	struct vlr_instance *vlr;

	/* TODO either populate from HLR or drop this completely? */
	long long unsigned int id;

	/* Data from HLR */				/* 3GPP TS 23.008 */
	/* Always use vlr_subscr_set_imsi() to write to imsi[] */
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];		/* 2.1.1.1 */
	char msisdn[VLR_MSISDN_LENGTH+1];		/* 2.1.2 */
	char name[VLR_NAME_LENGTH+1];			/* proprietary */
	OSMO_LBUF_DECL(hlr, 16);			/* 2.4.7 */
	uint32_t periodic_lu_timer;			/* 2.4.24 */
	uint32_t age_indicator;				/* 2.17.1 */

	/* Authentication Data */
	struct vlr_auth_tuple auth_tuples[5];		/* 2.3.1-2.3.4 */
	struct vlr_auth_tuple *last_tuple;
	enum vlr_subscr_security_context sec_ctx;

	/* Data local to VLR is below */
	uint32_t tmsi;					/* 2.1.4 */
	/* Newly allocated TMSI that was not yet acked by MS */
	uint32_t tmsi_new;

	struct osmo_cell_global_id cgi;			/* 2.4.16 */

	char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.2.3 */
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.1.9 */
	bool imsi_detached_flag;			/* 2.7.1 */
	bool conf_by_radio_contact_ind;			/* 2.7.4.1 */
	bool sub_dataconf_by_hlr_ind;			/* 2.7.4.2 */
	bool loc_conf_in_hlr_ind;			/* 2.7.4.3 */
	bool dormant_ind;				/* 2.7.8 */
	bool cancel_loc_rx;				/* 2.7.8A */
	bool ms_not_reachable_flag;			/* 2.10.2 (MNRF) */
	bool la_allowed;

	int use_count;

	struct osmo_fsm_inst *lu_fsm;
	struct osmo_fsm_inst *auth_fsm;
	struct osmo_fsm_inst *proc_arq_fsm;

	bool lu_complete;
	time_t expire_lu;

	void *msc_conn_ref;

	/* PS (SGSN) specific parts */
	struct {
		struct llist_head pdp_list;
	} ps;
	/* CS (NITB/CSCN) specific parts */
	struct {
		/* pending requests */
		bool is_paging;
		struct osmo_timer_list paging_response_timer;
		/* list of struct subscr_request */
		struct llist_head requests;
		uint8_t lac;
		enum osmo_rat_type attached_via_ran;
	} cs;

	struct gsm_classmark classmark;
};

enum vlr_ciph {
	VLR_CIPH_NONE, /*< A5/0, no encryption */
	VLR_CIPH_A5_1, /*< A5/1, encryption */
	VLR_CIPH_A5_2, /*< A5/2, deprecated export-grade encryption */
	VLR_CIPH_A5_3, /*< A5/3, 'new secure' encryption */
};

static inline uint8_t vlr_ciph_to_gsm0808_alg_id(enum vlr_ciph ciph)
{
	switch (ciph) {
	default:
	case VLR_CIPH_NONE:
		return GSM0808_ALG_ID_A5_0;
	case VLR_CIPH_A5_1:
		return GSM0808_ALG_ID_A5_1;
	case VLR_CIPH_A5_2:
		return GSM0808_ALG_ID_A5_2;
	case VLR_CIPH_A5_3:
		return GSM0808_ALG_ID_A5_3;
	}
}

struct vlr_ops {
	/* encode + transmit an AUTH REQ towards the MS.
	 * \param[in] at  auth tuple providing rand, key_seq and autn.
	 * \param[in] send_autn  True to send AUTN, for r99 UMTS auth.
	 */
	int (*tx_auth_req)(void *msc_conn_ref, struct vlr_auth_tuple *at,
			   bool send_autn);
	/* encode + transmit an AUTH REJECT towards the MS */
	int (*tx_auth_rej)(void *msc_conn_ref);

	/* encode + transmit an IDENTITY REQUEST towards the MS */
	int (*tx_id_req)(void *msc_conn_ref, uint8_t mi_type);

	int (*tx_lu_acc)(void *msc_conn_ref, uint32_t send_tmsi);
	int (*tx_lu_rej)(void *msc_conn_ref, enum gsm48_reject_value cause);
	int (*tx_cm_serv_acc)(void *msc_conn_ref);
	int (*tx_cm_serv_rej)(void *msc_conn_ref, enum gsm48_reject_value cause);

	int (*set_ciph_mode)(void *msc_conn_ref, bool umts_aka, bool retrieve_imeisv);

	/* UTRAN: send Common Id (when auth+ciph are complete) */
	int (*tx_common_id)(void *msc_conn_ref);

	int (*tx_mm_info)(void *msc_conn_ref);

	/* notify MSC/SGSN that the subscriber data in VLR has been updated */
	void (*subscr_update)(struct vlr_subscr *vsub);
	/* notify MSC/SGSN that the given subscriber has been associated
	 * with this msc_conn_ref */
	int (*subscr_assoc)(void *msc_conn_ref, struct vlr_subscr *vsub);

	/* Forward a parsed GSUP message towards MSC message router */
	int (*forward_gsup_msg)(struct vlr_subscr *vsub, struct osmo_gsup_message *gsup_msg);
};

enum vlr_timer {
	VLR_T_3250,
	VLR_T_3260,
	VLR_T_3270,
	_NUM_VLR_TIMERS
};

/* An instance of the VLR codebase */
struct vlr_instance {
	struct llist_head subscribers;
	struct llist_head operations;
	struct osmo_gsup_client *gsup_client;
	struct vlr_ops ops;
	struct osmo_timer_list lu_expire_timer;
	struct {
		bool retrieve_imeisv_early;
		bool retrieve_imeisv_ciphered;
		bool assign_tmsi;
		bool check_imei_rqd;
		int auth_tuple_max_reuse_count;
		bool auth_reuse_old_sets_on_error;
		bool parq_retrieve_imsi;
		bool is_ps;
		uint32_t timer[_NUM_VLR_TIMERS];
	} cfg;
	/* A free-form pointer for use by the caller */
	void *user_ctx;
};

extern const struct value_string vlr_ciph_names[];
static inline const char *vlr_ciph_name(enum vlr_ciph val)
{
	return get_value_string(vlr_ciph_names, val);
}

/* Location Updating request */
struct osmo_fsm_inst *
vlr_loc_update(struct osmo_fsm_inst *parent,
	       uint32_t parent_event_success,
	       uint32_t parent_event_failure,
	       void *parent_event_data,
	       struct vlr_instance *vlr, void *msc_conn_ref,
	       enum vlr_lu_type type, uint32_t tmsi, const char *imsi,
	       const struct osmo_location_area_id *old_lai,
	       const struct osmo_location_area_id *new_lai,
	       bool authentication_required,
	       bool ciphering_required,
	       bool is_r99, bool is_utran,
	       bool assign_tmsi);

void vlr_loc_update_cancel(struct osmo_fsm_inst *fi,
			   enum osmo_fsm_term_cause fsm_cause,
			   uint8_t gsm48_cause);

/* tell the VLR that the RAN connection is gone */
int vlr_subscr_disconnected(struct vlr_subscr *vsub);
bool vlr_subscr_expire(struct vlr_subscr *vsub);
int vlr_subscr_rx_id_resp(struct vlr_subscr *vsub, const uint8_t *mi, size_t mi_len);
int vlr_subscr_rx_auth_resp(struct vlr_subscr *vsub, bool is_r99, bool is_utran,
			    const uint8_t *res, uint8_t res_len);
int vlr_subscr_rx_auth_fail(struct vlr_subscr *vsub, const uint8_t *auts);
int vlr_subscr_tx_auth_fail_rep(const struct vlr_subscr *vsub) __attribute__((warn_unused_result));
void vlr_subscr_rx_ciph_res(struct vlr_subscr *vsub, struct vlr_ciph_result *res);
int vlr_subscr_rx_tmsi_reall_compl(struct vlr_subscr *vsub);
int vlr_subscr_rx_imsi_detach(struct vlr_subscr *vsub);

struct vlr_instance *vlr_alloc(void *ctx, const struct vlr_ops *ops);
int vlr_start(struct ipaccess_unit *ipa_dev, struct vlr_instance *vlr,
	      const char *gsup_server_addr_str, uint16_t gsup_server_port);

/* internal use only */

void sub_pres_vlr_fsm_start(struct osmo_fsm_inst **fsm,
			    struct osmo_fsm_inst *parent,
			    struct vlr_subscr *vsub,
			    uint32_t term_event);
struct osmo_fsm_inst *
upd_hlr_vlr_proc_start(struct osmo_fsm_inst *parent,
		       struct vlr_subscr *vsub,
		       uint32_t parent_event);

struct osmo_fsm_inst *
lu_compl_vlr_proc_start(struct osmo_fsm_inst *parent,
			struct vlr_subscr *vsub,
			void *msc_conn_ref,
			uint32_t parent_event_success,
			uint32_t parent_event_failure);


const char *vlr_subscr_name(const struct vlr_subscr *vsub);
const char *vlr_subscr_msisdn_or_name(const struct vlr_subscr *vsub);

#define vlr_subscr_find_by_imsi(vlr, imsi) \
	_vlr_subscr_find_by_imsi(vlr, imsi, __FILE__, __LINE__)
#define vlr_subscr_find_or_create_by_imsi(vlr, imsi, created) \
	_vlr_subscr_find_or_create_by_imsi(vlr, imsi, created, \
					   __FILE__, __LINE__)

#define vlr_subscr_find_by_tmsi(vlr, tmsi) \
	_vlr_subscr_find_by_tmsi(vlr, tmsi, __FILE__, __LINE__)
#define vlr_subscr_find_or_create_by_tmsi(vlr, tmsi, created) \
	_vlr_subscr_find_or_create_by_tmsi(vlr, tmsi, created, \
					   __FILE__, __LINE__)

#define vlr_subscr_find_by_msisdn(vlr, msisdn) \
	_vlr_subscr_find_by_msisdn(vlr, msisdn, __FILE__, __LINE__)

struct vlr_subscr *_vlr_subscr_find_by_imsi(struct vlr_instance *vlr,
					    const char *imsi,
					    const char *file, int line);
struct vlr_subscr *_vlr_subscr_find_or_create_by_imsi(struct vlr_instance *vlr,
						      const char *imsi,
						      bool *created,
						      const char *file,
						      int line);

struct vlr_subscr *_vlr_subscr_find_by_tmsi(struct vlr_instance *vlr,
					    uint32_t tmsi,
					    const char *file, int line);
struct vlr_subscr *_vlr_subscr_find_or_create_by_tmsi(struct vlr_instance *vlr,
						      uint32_t tmsi,
						      bool *created,
						      const char *file,
						      int line);

struct vlr_subscr *_vlr_subscr_find_by_msisdn(struct vlr_instance *vlr,
					      const char *msisdn,
					      const char *file, int line);

#define vlr_subscr_get(sub) _vlr_subscr_get(sub, __FILE__, __LINE__)
#define vlr_subscr_put(sub) _vlr_subscr_put(sub, __FILE__, __LINE__)
struct vlr_subscr *_vlr_subscr_get(struct vlr_subscr *sub, const char *file, int line);
struct vlr_subscr *_vlr_subscr_put(struct vlr_subscr *sub, const char *file, int line);

struct vlr_subscr *vlr_subscr_alloc(struct vlr_instance *vlr);
void vlr_subscr_free(struct vlr_subscr *vsub);
int vlr_subscr_alloc_tmsi(struct vlr_subscr *vsub);

void vlr_subscr_set_imsi(struct vlr_subscr *vsub, const char *imsi);
void vlr_subscr_set_imei(struct vlr_subscr *vsub, const char *imei);
void vlr_subscr_set_imeisv(struct vlr_subscr *vsub, const char *imeisv);
void vlr_subscr_set_msisdn(struct vlr_subscr *vsub, const char *msisdn);

bool vlr_subscr_matches_imsi(struct vlr_subscr *vsub, const char *imsi);
bool vlr_subscr_matches_tmsi(struct vlr_subscr *vsub, uint32_t tmsi);
bool vlr_subscr_matches_msisdn(struct vlr_subscr *vsub, const char *msisdn);
bool vlr_subscr_matches_imei(struct vlr_subscr *vsub, const char *imei);

uint32_t vlr_timer(struct vlr_instance *vlr, uint32_t timer);

int vlr_subscr_changed(struct vlr_subscr *vsub);
int vlr_subscr_purge(struct vlr_subscr *vsub) __attribute__((warn_unused_result));
void vlr_subscr_cancel_attach_fsm(struct vlr_subscr *vsub,
				  enum osmo_fsm_term_cause fsm_cause,
				  uint8_t gsm48_cause);

void vlr_subscr_enable_expire_lu(struct vlr_subscr *vsub);

/* Process Acccess Request FSM */

enum proc_arq_vlr_event {
	PR_ARQ_E_START,
	PR_ARQ_E_ID_IMSI,
	PR_ARQ_E_AUTH_RES,
	PR_ARQ_E_CIPH_RES,
	PR_ARQ_E_UPD_LOC_RES,
	PR_ARQ_E_TRACE_RES,
	PR_ARQ_E_IMEI_RES,
	PR_ARQ_E_PRES_RES,
	PR_ARQ_E_TMSI_ACK,
};

enum vlr_parq_type {
	VLR_PR_ARQ_T_INVALID = 0, /* to guard against unset vars */
	VLR_PR_ARQ_T_CM_SERV_REQ,
	VLR_PR_ARQ_T_PAGING_RESP,
	/* FIXME: differentiate between services of 24.008 10.5.3.3 */
};

/* Process Access Request (CM SERV REQ / PAGING RESP) */
void
vlr_proc_acc_req(struct osmo_fsm_inst *parent,
		 uint32_t parent_event_success,
		 uint32_t parent_event_failure,
		 void *parent_event_data,
		 struct vlr_instance *vlr, void *msc_conn_ref,
		 enum vlr_parq_type type, const uint8_t *mi_lv,
		 const struct osmo_location_area_id *lai,
		 bool authentication_required,
		 bool ciphering_required,
		 bool is_r99, bool is_utran);

void vlr_parq_cancel(struct osmo_fsm_inst *fi,
		     enum osmo_fsm_term_cause fsm_cause,
		     enum gsm48_reject_value gsm48_cause);

void vlr_parq_fsm_init(void);

int vlr_set_ciph_mode(struct vlr_instance *vlr,
		      struct osmo_fsm_inst *fi,
		      void *msc_conn_ref,
		      bool ciph_required,
		      bool umts_aka,
		      bool retrieve_imeisv);

bool vlr_use_umts_aka(struct osmo_auth_vector *vec, bool is_r99);

void log_set_filter_vlr_subscr(struct log_target *target,
			       struct vlr_subscr *vlr_subscr);
