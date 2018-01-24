#ifndef _GSM_DATA_SHAREDH
#define _GSM_DATA_SHAREDH

#include <regex.h>
#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/statistics.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/msc/common_cs.h>

struct osmo_bsc_data;

struct osmo_bsc_sccp_con;
struct gsm_sms_queue;

/* RRLP mode of operation */
enum rrlp_mode {
	RRLP_MODE_NONE,
	RRLP_MODE_MS_BASED,
	RRLP_MODE_MS_PREF,
	RRLP_MODE_ASS_PREF,
};

enum gsm_hooks {
	GSM_HOOK_NM_SWLOAD,
	GSM_HOOK_RR_PAGING,
	GSM_HOOK_RR_SECURITY,
};

enum gsm_paging_event {
	GSM_PAGING_SUCCEEDED,
	GSM_PAGING_EXPIRED,
	GSM_PAGING_OOM,
	GSM_PAGING_BUSY,
};

struct gsm_mncc;
struct osmo_rtp_socket;
struct rtp_socket;
struct bsc_api;

/*
 * help with parsing regexps
 */
int gsm_parse_reg(void *ctx, regex_t *reg, char **str,
		int argc, const char **argv) __attribute__ ((warn_unused_result));

#endif
