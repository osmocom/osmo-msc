#pragma once

#define LOG_MSC_I_REMOTE(MSC_I_REMOTE, LEVEL, FMT, ARGS ...) \
		LOG_MSC_I_REMOTE_CAT(MSC_I_REMOTE, (MSC_I_REMOTE) ? (MSC_I_REMOTE)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_I_REMOTE_CAT(MSC_I_REMOTE, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_I_REMOTE) ? (MSC_I_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_I_REMOTE_CAT_SRC(MSC_I_REMOTE, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_I_REMOTE) ? (MSC_I_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

struct msub;
struct ran_infra;
struct e_link;

struct msc_i *msc_i_remote_alloc(struct msub *msub, struct ran_infra *ran, struct e_link *e);
