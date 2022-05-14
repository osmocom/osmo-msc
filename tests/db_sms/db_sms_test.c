/*
 * Test the storage API of the internal SMS Centre.
 *
 * (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>

#include <osmocom/gsm/protocol/gsm_03_40.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/db.h>

/* Talloc context of this unit test */
static void *talloc_ctx = NULL;

static const struct sms_tp_ud {
	/* Data Coding Scheme */
	uint8_t dcs;
	/* TP User-Data-Length (depends on DCS) */
	uint8_t length;
	/* Static TP User-Data filler (0 means disabled) */
	uint8_t filler_byte;
	/* TP User-Data */
	uint8_t data[GSM340_UDL_OCT_MAX];
	/* Decoded text (for 7-bit default alphabet only) */
	char dec_text[GSM340_UDL_SPT_MAX + 1];
} sms_tp_ud_set[] = {
	{
		.dcs = 0x00, /* Default GSM 7-bit alphabet */
		.length = 9, /* in septets */
		.dec_text = "Mahlzeit!",
		.data = {
			0xcd, 0x30, 0x9a, 0xad, 0x2f, 0xa7, 0xe9, 0x21,
		},
	},
	{
		.dcs = 0x08, /* UCS-2 (16-bit) / UTF-16 */
		.length = 120, /* in octets */
		.data = {
			0x04, 0x23, 0x04, 0x32, 0x04, 0x30, 0x04, 0x36,
			0x04, 0x30, 0x04, 0x35, 0x04, 0x3c, 0x04, 0x4b,
			0x04, 0x39, 0x00, 0x20, 0x04, 0x3a, 0x04, 0x3b,
			0x04, 0x38, 0x04, 0x35, 0x04, 0x3d, 0x04, 0x42,
			0x00, 0x21, 0x00, 0x20, 0x04, 0x1d, 0x04, 0x30,
			0x04, 0x41, 0x04, 0x42, 0x04, 0x40, 0x04, 0x3e,
			0x04, 0x39, 0x04, 0x3a, 0x04, 0x38, 0x00, 0x20,
			0x00, 0x49, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65,
			0x00, 0x72, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x74,
			0x00, 0x20, 0x04, 0x38, 0x00, 0x20, 0x00, 0x4d,
			0x00, 0x4d, 0x00, 0x53, 0x00, 0x20, 0x04, 0x31,
			0x04, 0x43, 0x04, 0x34, 0x04, 0x43, 0x04, 0x42,
			0x00, 0x20, 0x04, 0x34, 0x04, 0x3e, 0x04, 0x41,
			0x04, 0x42, 0x04, 0x30, 0x04, 0x32, 0x04, 0x3b,
			0x04, 0x35, 0x04, 0x3d, 0x04, 0x4b, 0x00, 0x2e,
		},
	},
	{
		.dcs = 0x04, /* 8-bit data */
		.length = 12, /* in octets */
		.data = {
			/* User-Data-Header */
			0x1e, /* Buffer-overflow! (should be 0x05) */
			/* Concatenated SM, 8-bit reference number */
			0x00, 0x03, 0x5a, 0x05, 0x01,

			/* Dummy payload... */
			0x05, 0x04, 0x0b, 0x84, 0x0b, 0x84,
		},
	},
	{
		.dcs = 0x00, /* Default GSM 7-bit alphabet */
		.length = 160, /* maximum, in septets */
		.filler_byte = 0x41,
	},
	{
		.dcs = 0x04, /* 8-bit data */
		.length = 140, /* maximum, in octets */
		.filler_byte = 0x42,
	},
	{
		.dcs = 0x00, /* Default GSM 7-bit alphabet */
		.length = 200, /* invalid, buffer overflow */
		.filler_byte = 0x41,
	},
	{
		.dcs = 0x04, /* 8-bit data */
		.length = 0xff, /* invalid, buffer overflow */
		.filler_byte = 0x42,
	},
};

#define SMS_ADDR(addr) \
	{ 0x00, 0x00, addr }

static struct sms_test {
	/* Human-readable name of particular test message */
	const char *name;
	/* Whether we expect db_sms_store() to fail */
	bool exp_db_sms_store_fail;
	/* Whether we expect db_sms_get() to fail */
	bool exp_db_sms_get_fail;
	/* SM TP-User-Data from sms_tp_ud_set[] */
	const struct sms_tp_ud *ud;
	/* The message itself */
	struct gsm_sms sms;
} sms_test_set[] = {
	{
		.name = "Regular MO SMS",
		.sms = {
			.msg_ref = 0xde,
			.src = SMS_ADDR("123456"),
			.dst = SMS_ADDR("654321"),
			.validity_minutes = 10,
			.protocol_id = 0x00,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[0],
	},
	{
		.name = "Regular MT SMS",
		.sms = {
			.msg_ref = 0xbe,
			.src = SMS_ADDR("654321"),
			.dst = SMS_ADDR("123456"),
			.validity_minutes = 180,
			.protocol_id = 0x00,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[1],
	},
	{
		.name = "Complete TP-UD (160 septets, 7-bit encoding)",
		.sms = {
			.msg_ref = 0xee,
			.src = SMS_ADDR("266753837248772"),
			.dst = SMS_ADDR("266753837248378"),
			.validity_minutes = 360,
			.protocol_id = 0x00,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[3],
	},
	{
		.name = "Complete TP-UD (140 octets, 8-bit encoding)",
		.sms = {
			.msg_ref = 0xee,
			.src = SMS_ADDR("266753838248772"),
			.dst = SMS_ADDR("266753838248378"),
			.validity_minutes = 360,
			.protocol_id = 0xaa,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[4],
	},
	{
		.name = "TP-UD buffer overflow (UDH-Length > UD-Length)",
		.sms = {
			.msg_ref = 0x88,
			.src = SMS_ADDR("834568373569772"),
			.dst = SMS_ADDR("834568373569378"),
			.validity_minutes = 200,
			.protocol_id = 0xbb,
			.ud_hdr_ind = 0x01,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[2],
	},
	{
		.name = "Truncated TP-UD (200 septets, 7-bit encoding)",
		.sms = {
			.msg_ref = 0xee,
			.src = { 0x01, 0x00, "8786228337248772" },
			.dst = { 0x00, 0x01, "8786228337248378" },
			.validity_minutes = 360,
			.protocol_id = 0xcc,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[5],
	},
	{
		.name = "Truncated TP-UD (255 octets, 8-bit encoding)",
		.sms = {
			.msg_ref = 0xee,
			.src = { 0x01, 0x01, "8786228338248772" },
			.dst = { 0xaa, 0xff, "8786228338248378" },
			.validity_minutes = 360,
			.protocol_id = 0xbb,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[6],
	},
	{
		.name = "Same MSISDN #1",
		.sms = {
			.msg_ref = 0x11,
			.src = SMS_ADDR("72631"),
			.dst = SMS_ADDR("72632"),
			.validity_minutes = 10,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[0],
	},
	{
		.name = "Same MSISDN #2",
		.sms = {
			.msg_ref = 0x12,
			.src = SMS_ADDR("72632"),
			.dst = SMS_ADDR("72631"),
			.validity_minutes = 10,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[0],
	},
	{
		.name = "Expired SMS",
		.sms = {
			.msg_ref = 0xde,
			.src = SMS_ADDR("3974733772"),
			.dst = SMS_ADDR("3974733378"),
			.validity_minutes = 0,
			/* SM TP-User-Data is taken from sms_tp_ud_set[] */
		},
		.ud = &sms_tp_ud_set[0],
	},
	{
		.name = "Empty TP-UD",
		.sms = {
			.msg_ref = 0x38,
			.src = SMS_ADDR("3678983772"),
			.dst = SMS_ADDR("3678983378"),
			.validity_minutes = 450,
			.is_report = true,
			.reply_path_req = 0x01,
			.status_rep_req = 0x01,
			.protocol_id = 0x55,
			.data_coding_scheme = 0x08,
			.ud_hdr_ind = 0x00,
			.user_data_len = 0x00,
			/* No TP-User-Data */
		},
		.ud = NULL,
	},
};

static void prepare_sms_test_set(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sms_test_set); i++) {
		struct sms_test *test = &sms_test_set[i];
		const struct sms_tp_ud *ud = test->ud;

		/* ID auto-increment */
		test->sms.id = i + 1;

		if (ud == NULL)
			continue;

		test->sms.data_coding_scheme = ud->dcs;
		test->sms.user_data_len = ud->length;

		if (ud->filler_byte) {
			memset(test->sms.user_data, ud->filler_byte,
			       sizeof(test->sms.user_data));
		} else {
			memcpy(test->sms.user_data, ud->data, sizeof(ud->data));
			if (ud->dec_text[0] != '\0')
				strcpy(test->sms.text, ud->dec_text);
		}
	}
}

static void test_db_sms_store(void)
{
	int rc, i;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_store()...\n");

	/* Store test SMS messages */
	for (i = 0; i < ARRAY_SIZE(sms_test_set); i++) {
		struct sms_test *test = &sms_test_set[i];

		LOGP(DDB, LOGL_NOTICE, "%s('%s'): ", __func__, test->name);

		rc = db_sms_store(&test->sms);
		if (!test->exp_db_sms_store_fail && rc == 0)
			LOGPC(DDB, LOGL_INFO, "success, as expected\n");
		else if (test->exp_db_sms_store_fail && rc != 0)
			LOGPC(DDB, LOGL_INFO, "failure, as expected\n");
		else
			LOGPC(DDB, LOGL_ERROR, "unexpected rc=%d\n", rc);
	}
}

static int verify_sms(const struct sms_test *test, const struct gsm_sms *sms)
{
	int rc;

	LOGP(DDB, LOGL_NOTICE, "%s('%s'): ", __func__, test->name);

#define MATCH_SMS_ADDR(ADDR) \
	if (strcmp(sms->ADDR.addr, test->sms.ADDR.addr) \
	    || sms->ADDR.npi != test->sms.ADDR.npi	\
	    || sms->ADDR.ton != test->sms.ADDR.ton) {	\
		LOGPC(DDB, LOGL_ERROR, #ADDR " address mismatch\n"); \
		return -EINVAL; \
	}

	MATCH_SMS_ADDR(src);
	MATCH_SMS_ADDR(dst);

#define MATCH_SMS_PARAM(PARAM, FMT) \
	if (sms->PARAM != test->sms.PARAM) { \
		LOGPC(DDB, LOGL_ERROR, \
		      #PARAM " mismatch: E%" FMT " vs A%" FMT "\n", \
		      test->sms.PARAM, sms->PARAM); \
		return -EINVAL; \
	}

	MATCH_SMS_PARAM(id, "llu");
	MATCH_SMS_PARAM(validity_minutes, "lu");
	MATCH_SMS_PARAM(is_report, "i");
	MATCH_SMS_PARAM(reply_path_req, PRIu8);
	MATCH_SMS_PARAM(status_rep_req, PRIu8);
	MATCH_SMS_PARAM(ud_hdr_ind, PRIu8);
	MATCH_SMS_PARAM(protocol_id, PRIu8);
	MATCH_SMS_PARAM(data_coding_scheme, PRIu8);
	MATCH_SMS_PARAM(msg_ref, PRIu8);
	MATCH_SMS_PARAM(user_data_len, PRIu8);

	/* Compare TP-User-Data */
	rc = memcmp(sms->user_data, test->sms.user_data,
                    sizeof(sms->user_data));
	if (rc) {
		LOGPC(DDB, LOGL_ERROR, "TP-User-Data mismatch\n");
		return -EINVAL;
	}

	/* Compare decoded text */
	rc = strncmp(sms->text, test->sms.text, sizeof(sms->text));
	if (rc) {
		LOGPC(DDB, LOGL_ERROR, "TP-User-Data (text) mismatch\n");
		return -EINVAL;
	}

	LOGPC(DDB, LOGL_NOTICE, "match\n");
	return 0;
}

static void test_db_sms_get(void)
{
	struct gsm_sms *sms;
	int i;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_get()...\n");

	/* Retrieve stored SMS messages */
	for (i = 0; i < ARRAY_SIZE(sms_test_set); i++) {
		const struct sms_test *test = &sms_test_set[i];

		LOGP(DDB, LOGL_NOTICE, "%s('%s'): ", __func__, test->name);

		sms = db_sms_get(NULL, test->sms.id);
		if (!test->exp_db_sms_get_fail && sms != NULL)
			LOGPC(DDB, LOGL_INFO, "success, as expected\n");
		else if (test->exp_db_sms_get_fail && sms == NULL)
			LOGPC(DDB, LOGL_INFO, "failure, as expected\n");
		else
			LOGPC(DDB, LOGL_ERROR, "unexpected result\n");

		if (sms) {
			verify_sms(test, sms);
			talloc_free(sms);
		}
	}
}

static void test_db_sms_delivery(void)
{
	struct gsm_sms *sms1, *sms2;
	struct gsm_sms *sms;
	int rc;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_get_next_unsent() "
			     "and db_sms_mark_delivered()...\n");

	/* Retrieve both #1 and #2 */
	sms1 = db_sms_get_next_unsent(NULL, 1, 0);
	LOGP(DDB, LOGL_NOTICE, "db_sms_get_next_unsent(#1): %s\n",
	     sms1 ? "found" : "not found");
	if (sms1 != NULL)
		verify_sms(&sms_test_set[0], sms1);

	sms2 = db_sms_get_next_unsent(NULL, 2, 0);
	LOGP(DDB, LOGL_NOTICE, "db_sms_get_next_unsent(#2): %s\n",
	     sms2 ? "found" : "not found");
	if (sms2 != NULL)
		verify_sms(&sms_test_set[1], sms2);

	/* Mark both #1 and #2 and delivered, release memory */
	if (sms1) {
		LOGP(DDB, LOGL_DEBUG, "Marking #%llu as delivered: ", sms1->id);
		rc = db_sms_mark_delivered(sms1);
		LOGPC(DDB, LOGL_DEBUG, "rc=%d\n", rc);
		talloc_free(sms1);
	}

	if (sms2) {
		LOGP(DDB, LOGL_DEBUG, "Marking #%llu as delivered: ", sms2->id);
		rc = db_sms_mark_delivered(sms2);
		LOGPC(DDB, LOGL_DEBUG, "rc=%d\n", rc);
		talloc_free(sms2);
	}

	/* Expect #3 as the next undelivered */
	sms = db_sms_get_next_unsent(NULL, 1, 0);
	LOGP(DDB, LOGL_NOTICE, "db_sms_get_next_unsent(starting from #1): %s\n",
	     sms ? "found" : "not found");
	if (sms) {
		verify_sms(&sms_test_set[2], sms);
		talloc_free(sms);
	}
}

static void test_db_sms_delete(void)
{
	int rc;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_delete_sent_message_by_id()...\n");

	/* Delete #1, which is marked as sent */
	LOGP(DDB, LOGL_NOTICE, "db_sms_delete_sent_message_by_id(#1, sent): ");
	rc = db_sms_delete_sent_message_by_id(1);
	LOGPC(DDB, LOGL_NOTICE, "rc=%d\n", rc);
	/* Don't expect to retrieve this message anymore */
	sms_test_set[0].exp_db_sms_get_fail = true;

	/* Try to delete #3, which is not marked as sent */
	LOGP(DDB, LOGL_NOTICE, "db_sms_delete_sent_message_by_id(#3, not sent): ");
	rc = db_sms_delete_sent_message_by_id(3);
	LOGPC(DDB, LOGL_NOTICE, "rc=%d\n", rc);
	/* Do expect to retrieve this message anyway */
	sms_test_set[2].exp_db_sms_get_fail = false;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_delete_by_msisdn()...\n");

	LOGP(DDB, LOGL_NOTICE, "db_sms_delete_by_msisdn('72631'): ");
	rc = db_sms_delete_by_msisdn("72631");
	LOGPC(DDB, LOGL_NOTICE, "rc=%d\n", rc);

	/* Don't expect both #8 and #9 anymore */
	sms_test_set[7].exp_db_sms_get_fail = true;
	sms_test_set[8].exp_db_sms_get_fail = true;

	LOGP(DDB, LOGL_INFO, "Testing db_sms_delete_oldest_expired_message()...\n");

	LOGP(DDB, LOGL_NOTICE, "db_sms_delete_oldest_expired_message()\n");
	db_sms_delete_oldest_expired_message();

	/* Don't expect #10 anymore */
	sms_test_set[9].exp_db_sms_get_fail = true;

	/* We need to make sure that we removed exactly what we expected to remove */
	LOGP(DDB, LOGL_INFO, "Expectations updated, retrieving all messages again\n");
	test_db_sms_get();
}

static struct log_info_cat db_sms_test_categories[] = {
	[DDB] = {
		.name = "DDB",
		.description = "Database Layer",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = db_sms_test_categories,
	.num_cat = ARRAY_SIZE(db_sms_test_categories),
};

int main(int argc, char **argv)
{
	void *logging_ctx;
	int rc;

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	talloc_ctx = talloc_named_const(NULL, 0, "db_sms_test");
	logging_ctx = talloc_named_const(talloc_ctx, 0, "logging");
	osmo_init_logging2(logging_ctx, &info);

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);

#if 0
	/* Having the database stored in a regular file may be useful
	 * for debugging, but this comes at the price of performance. */
	FILE *dbf = fopen("db_sms_test.db", "wb");
	OSMO_ASSERT(dbf != NULL);
	fclose(dbf);
#endif

	/* Init a volatile database in RAM */
	LOGP(DDB, LOGL_DEBUG, "Init a new database\n");

	/* HACK: db_init() prints libdbi version using LOGL_NOTICE, so
	 * the test output is not deterministic. Let's suppress this
	 * message by increasing the log level to LOGL_ERROR. */
	log_parse_category_mask(osmo_stderr_target, "DDB,7");
	rc = db_init(talloc_ctx, ":memory:", true);
	OSMO_ASSERT(rc == 0);

	/* HACK: relax log level back to LOGL_DEBUG (see note above) */
	log_parse_category_mask(osmo_stderr_target, "DDB,1");

	/* Prepare some tables */
	rc = db_prepare();
	OSMO_ASSERT(rc == 0);
	LOGP(DDB, LOGL_DEBUG, "Init complete\n");

	/* Prepare the test set */
	prepare_sms_test_set();

	test_db_sms_store();
	test_db_sms_get();

	test_db_sms_delivery();
	test_db_sms_delete();

	/* Close the database */
	db_fini();

	/* Deinit logging */
	log_fini();

	/* Check for memory leaks */
	rc = talloc_total_blocks(talloc_ctx);
	OSMO_ASSERT(rc == 2); /* db_sms_test + logging */
	talloc_free(talloc_ctx);

	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return 0;
}
