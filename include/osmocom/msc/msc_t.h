#pragma once

#include <osmocom/msc/msc_roles.h>

struct ran_conn;
struct ran_infra;
struct ran_peer;
struct gsm_mncc;
struct mncc_call;

#define LOG_MSC_T(MSC_T, LEVEL, FMT, ARGS ...) \
		LOG_MSC_T_CAT(MSC_T, (MSC_T) ? (MSC_T)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_T_CAT(MSC_T, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_T) ? (MSC_T)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_T_CAT_SRC(MSC_T, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_T) ? (MSC_T)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

struct msc_t {
	/* struct msc_role_common must remain at start */
	struct msc_role_common c;

	struct ran_conn *ran_conn;

	struct {
		uint8_t chosen_channel;
		uint8_t chosen_encr_alg;
		uint8_t chosen_speech_version;
	} geran;

	struct {
		struct an_apdu ho_request;
		struct gsm0808_cell_id cell_id_target;
		uint32_t call_id;
		char handover_number[16]; /* No libosmocore definition for MSISDN_MAXLEN? */
		struct call_leg *call_leg;
		struct mncc_call *mncc_forwarding_to_remote_cn;
	} inter_msc;

	struct osmo_gsm48_classmark classmark;
	bool ho_success;
	bool ho_fail_sent;
};

enum msc_t_state {
	MSC_T_ST_PENDING_FIRST_CO_INITIAL_MSG,
	MSC_T_ST_WAIT_LOCAL_RTP,
	MSC_T_ST_WAIT_HO_REQUEST_ACK,
	MSC_T_ST_WAIT_HO_COMPLETE,
};

struct msc_t *msc_t_alloc_without_ran_peer(struct msub *msub, struct ran_infra *ran);
int msc_t_set_ran_peer(struct msc_t *msc_t, struct ran_peer *ran_peer);
struct msc_t *msc_t_alloc(struct msub *msub, struct ran_peer *ran_peer);
int msc_t_down_l2_co(struct msc_t *msc_t, const struct an_apdu *an_apdu, bool initial);
void msc_t_clear(struct msc_t *msc_t);

struct gsm_network *msc_t_net(const struct msc_t *msc_t);
struct vlr_subscr *msc_t_vsub(const struct msc_t *msc_t);

struct mncc_call *msc_t_check_call_to_handover_number(const struct gsm_mncc *msg);
