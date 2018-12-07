#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/gsm/mncc.h>

#include <osmocom/msc/msc_roles.h>

struct ran_infra;
struct mncc_call;

#define LOG_MSC_I(MSC_I, LEVEL, FMT, ARGS ...) \
		LOG_MSC_I_CAT(MSC_I, (MSC_I) ? (MSC_I)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_I_CAT(MSC_I, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_I) ? (MSC_I)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_I_CAT_SRC(MSC_I, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_I) ? (MSC_I)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

struct msc_i {
	/* struct msc_role_common must remain at start */
	struct msc_role_common c;
	struct ran_conn *ran_conn;

	struct {
		struct call_leg *call_leg;
		struct mncc_call *mncc_forwarding_to_remote_cn;
	} inter_msc;
};

osmo_static_assert(offsetof(struct msc_i, c) == 0, msc_role_common_first_member_of_msc_i);

enum msc_i_state {
	MSC_I_ST_READY,
	MSC_I_ST_CLEARING,
	MSC_I_ST_CLEARED,
};

struct msc_i *msc_i_alloc(struct msub *msub, struct ran_infra *ran);
void msc_i_set_ran_conn(struct msc_i *msc_i, struct ran_conn *ran_conn);

void msc_i_clear(struct msc_i *msc_i);
void msc_i_cleared(struct msc_i *msc_i);

int msc_i_down_l2(struct msc_i *msc_i, struct msgb *l2);

struct gsm_network *msc_i_net(const struct msc_i *msc_i);
struct vlr_subscr *msc_i_vsub(const struct msc_i *msc_i);
