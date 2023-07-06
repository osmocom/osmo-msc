#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/mncc.h>

#define _test_sdp_termination(LABEL, MNCC, MNCC_MSG_LEN, RC) do { \
		int sdp_len = ((int)(MNCC_MSG_LEN)) - ((MNCC)->sdp - (char*)MNCC); \
		size_t sdp_strlen = strnlen(MNCC->sdp, sizeof(MNCC->sdp)); \
		int rc = mncc_check_sdp_termination("<" LABEL ">", (struct gsm_mncc*)MNCC, MNCC_MSG_LEN, MNCC->sdp); \
		printf("%s: len=%d sdplen=%d sdp=%s rc=%d\n", \
		       LABEL, (int)(MNCC_MSG_LEN), sdp_len, \
		       sdp_len > 0? osmo_quote_str((MNCC)->sdp, OSMO_MIN(sdp_len, sdp_strlen+1)) : "-", rc); \
		if (RC != rc) \
			printf("ERROR!\n"); \
	} while (0)

#define test_sdp_termination_cases(MNCC) \
	_test_sdp_termination("empty SDP", MNCC, sizeof(*MNCC), 0); \
	_test_sdp_termination("empty SDP, shortest possible", MNCC, MNCC->sdp - ((char*)MNCC) + 1, 0); \
	_test_sdp_termination("empty SDP, zero len", MNCC, MNCC->sdp - ((char*)MNCC), -EINVAL); \
	OSMO_STRLCPY_ARRAY(MNCC->sdp, "Privacy is a desirable marketing option"); \
	_test_sdp_termination("terminated SDP str", MNCC, sizeof(*MNCC), 0); \
	_test_sdp_termination("terminated SDP str, shortest possible", MNCC, \
			      MNCC->sdp - ((char*)MNCC) + strlen(MNCC->sdp) + 1, 0); \
	_test_sdp_termination("terminated SDP str, but len excludes nul", MNCC, \
			      MNCC->sdp - ((char*)MNCC) + strlen(MNCC->sdp), -EINVAL); \
	_test_sdp_termination("terminated SDP str, but len too short", MNCC, \
			      MNCC->sdp - ((char*)MNCC) + 23, -EINVAL); \
	_test_sdp_termination("len way too short", MNCC, 10, -EINVAL); \
	_test_sdp_termination("len zero", MNCC, 0, -EINVAL);


void test_sdp_termination(void)
{
	struct gsm_mncc _mncc = {};
	struct gsm_mncc_rtp _mncc_rtp = {};

	struct gsm_mncc *mncc = &_mncc;
	struct gsm_mncc_rtp *mncc_rtp = &_mncc_rtp;

	printf("%s()\n", __func__);
	printf("\nstruct gsm_mncc:\n");
	test_sdp_termination_cases(mncc);

	_mncc = (struct gsm_mncc){};
	_mncc_rtp = (struct gsm_mncc_rtp){};
	printf("\nstruct gsm_mncc_rtp:\n");
	test_sdp_termination_cases(mncc_rtp);
}

static const struct log_info_cat default_categories[] = {
	[DMNCC] = {
		.name = "DMNCC",
		.description = "MNCC API for Call Control application",
		.color = "\033[1;39m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(void)
{
	void *ctx = talloc_named_const(NULL, 0, "mncc_test");
	osmo_init_logging2(ctx, &log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);

	test_sdp_termination();
	return 0;
}
