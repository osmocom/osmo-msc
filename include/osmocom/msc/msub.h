#pragma once

#include <osmocom/gsm/gsm48.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/msc_roles.h>

struct vlr_subscr;
struct gsm_network;
enum gsm48_gsm_cause;
enum complete_layer3_type;
enum osmo_gsup_access_network_protocol;

#define VSUB_USE_MSUB "active-conn"

struct msub {
	struct llist_head entry;
	struct osmo_fsm_inst *fi;

	struct vlr_subscr *vsub;

	/* role = {MSC_ROLE_A, MSC_ROLE_I, MSC_ROLE_T} */
	struct osmo_fsm_inst *role[MSC_ROLES_COUNT];
	struct gsm_network *net;
};

extern struct llist_head msub_list;

#define LOG_MSUB_CAT_SRC(msub, cat, level, file, line, fmt, args ...) \
	LOGPSRC(cat, level, file, line, "(%s) " fmt, msub_name(msub), ## args)

#define LOG_MSUB_CAT(msub, cat, level, fmt, args ...) \
	LOGP(cat, level, "msub(%s) " fmt, msub_name(msub), ## args)

#define LOG_MSUB(msub, level, fmt, args ...) \
	LOG_MSUB_CAT(msub, DMSC, level, fmt, ## args)

struct msub *msub_alloc(struct gsm_network *net);

#define msub_role_alloc(MSUB, ROLE, FSM, ROLE_STRUCT, RAN) \
	(ROLE_STRUCT*)_msub_role_alloc(MSUB, ROLE, FSM, sizeof(ROLE_STRUCT), #ROLE_STRUCT ":" #FSM, RAN)
struct msc_role_common *_msub_role_alloc(struct msub *msub, enum msc_role role, struct osmo_fsm *role_fsm,
					 size_t struct_size, const char *struct_name, struct ran_infra *ran);

const char *msub_name(const struct msub *msub);

struct msub *msub_for_vsub(const struct vlr_subscr *for_vsub);

void msub_set_role(struct msub *msub, struct osmo_fsm_inst *msc_role);
void msub_remove_role(struct msub *msub, struct osmo_fsm_inst *fi);

struct msc_a *msub_msc_a(const struct msub *msub);
struct msc_i *msub_msc_i(const struct msub *msub);
struct msc_t *msub_msc_t(const struct msub *msub);
struct ran_conn *msub_ran_conn(const struct msub *msub);
const char *msub_ran_conn_name(const struct msub *msub);

int msub_set_vsub(struct msub *msub, struct vlr_subscr *vsub);
struct vlr_subscr *msub_vsub(const struct msub *msub);
struct gsm_network *msub_net(const struct msub *msub);

int msub_role_to_role_event(struct msub *msub, enum msc_role from_role, enum msc_role to_role);
#define msub_role_dispatch(MSUB, TO_ROLE, TO_ROLE_EVENT, AN_APDU) \
	_msub_role_dispatch(MSUB, TO_ROLE, TO_ROLE_EVENT, AN_APDU, __FILE__, __LINE__)
int _msub_role_dispatch(struct msub *msub, enum msc_role to_role, uint32_t to_role_event, const struct an_apdu *an_apdu,
			const char *file, int line);
int msub_tx_an_apdu(struct msub *msub, enum msc_role from_role, enum msc_role to_role, struct an_apdu *an_apdu);

void msub_update_id_from_mi(struct msub *msub, const struct osmo_mobile_identity *mi);
void msub_update_id(struct msub *msub);
void msub_update_id_for_vsub(struct vlr_subscr *for_vsub);

void msub_pending_cm_service_req_add(struct msub *msub, enum osmo_cm_service_type type);
unsigned int msub_pending_cm_service_req_count(struct msub *msub, enum osmo_cm_service_type type);
void msub_pending_cm_service_req_del(struct msub *msub, enum osmo_cm_service_type type);

void msc_role_forget_conn(struct osmo_fsm_inst *role, struct ran_conn *conn);

struct msgb *msc_role_ran_encode(struct osmo_fsm_inst *role, const struct ran_msg *ran_msg);
int msc_role_ran_decode(struct osmo_fsm_inst *fi, const struct an_apdu *an_apdu,
			ran_decode_cb_t decode_cb, void *decode_cb_data);
