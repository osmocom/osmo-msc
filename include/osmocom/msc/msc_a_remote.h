#pragma once

#define LOG_MSC_A_REMOTE(MSC_A_REMOTE, LEVEL, FMT, ARGS ...) \
		LOG_MSC_A_REMOTE_CAT(MSC_A_REMOTE, (MSC_A_REMOTE) ? (MSC_A_REMOTE)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_A_REMOTE_CAT(MSC_A_REMOTE, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_A_REMOTE) ? (MSC_A_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_A_REMOTE_CAT_SRC(MSC_A_REMOTE, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_A_REMOTE) ? (MSC_A_REMOTE)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

struct msub;
struct ran_infra;

struct msc_a *msc_a_remote_alloc(struct msub *msub, struct ran_infra *ran,
				 const uint8_t *remote_msc_name, size_t remote_msc_name_len);

int msc_a_remote_assign_handover_number(struct msc_a *msc_a);
struct msc_a *msc_a_remote_find_by_handover_number(const char *handover_number);
