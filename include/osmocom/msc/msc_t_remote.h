#pragma once

#define LOG_MSC_T_REMOTE(MSC_T_REMOTE, LEVEL, FMT, ARGS ...) \
		LOG_MSC_T_REMOTE_CAT(MSC_T_REMOTE, (MSC_T_REMOTE) ? (MSC_T_REMOTE)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_T_REMOTE_CAT(MSC_T_REMOTE, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_T_REMOTE) ? (MSC_T_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_T_REMOTE_CAT_SRC(MSC_T_REMOTE, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_T_REMOTE) ? (MSC_T_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

struct msub;
struct ran_infra;

struct msc_t *msc_t_remote_alloc(struct msub *msub, struct ran_infra *ran,
				 const uint8_t *remote_msc_name, size_t remote_msc_name_len);
