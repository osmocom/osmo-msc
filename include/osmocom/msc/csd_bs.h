/* 3GPP TS 122.002 Bearer Services */
#pragma once

#include <osmocom/gsm/mncc.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

enum csd_bs {
	CSD_BS_NONE,

	/* 3.1.1.1.2 */
	CSD_BS_21_T_V110_0k3,
	CSD_BS_22_T_V110_1k2,
	CSD_BS_24_T_V110_2k4,
	CSD_BS_25_T_V110_4k8,
	CSD_BS_26_T_V110_9k6,

	/* 3.1.1.2.2 */
	CSD_BS_21_NT_V110_0k3,
	CSD_BS_22_NT_V110_1k2,
	CSD_BS_24_NT_V110_2k4,
	CSD_BS_25_NT_V110_4k8,
	CSD_BS_26_NT_V110_9k6,

	/* 3.1.2.1.2 */
	CSD_BS_31_T_V110_1k2,
	CSD_BS_32_T_V110_2k4,
	CSD_BS_33_T_V110_4k8,
	CSD_BS_34_T_V110_9k6,

	CSD_BS_MAX,
};

struct csd_bs_list {
	unsigned int count;
	enum csd_bs bs[CSD_BS_MAX];
};

void csd_bs_list_add_bs(struct csd_bs_list *list, enum csd_bs bs);
int csd_bs_list_to_bearer_cap(struct gsm_mncc_bearer_cap *cap, const struct csd_bs_list *list);
void csd_bs_list_from_bearer_cap(struct csd_bs_list *list, const struct gsm_mncc_bearer_cap *cap);

int csd_bs_to_str_buf(char *buf, size_t buflen, enum csd_bs bs);
char *csd_bs_to_str_c(void *ctx, enum csd_bs bs);
const char *csd_bs_to_str(enum csd_bs bs);

int csd_bs_list_to_str_buf(char *buf, size_t buflen, const struct csd_bs_list *list);
char *csd_bs_list_to_str_c(void *ctx, const struct csd_bs_list *list);
const char *csd_bs_list_to_str(const struct csd_bs_list *list);

void csd_bs_list_add_bs(struct csd_bs_list *list, enum csd_bs bs);
void csd_bs_list_remove(struct csd_bs_list *list, enum csd_bs bs);
void csd_bs_list_intersection(struct csd_bs_list *dest, const struct csd_bs_list *other);

int csd_bs_list_to_gsm0808_channel_type(struct gsm0808_channel_type *ct, const struct csd_bs_list *list);
