/* Test Osmocom SMS queue */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <osmocom/core/application.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/sms_queue.h>

static void *talloc_ctx = NULL;
extern void *tall_gsms_ctx;

struct gsm_sms *smsq_take_next_sms(struct gsm_network *net,
				   char *last_msisdn,
				   size_t last_msisdn_buflen);

static void _test_take_next_sms_print(int i,
				      struct gsm_sms *sms,
				      const char *last_msisdn)
{
	printf("#%d: ", i);
	if (sms)
		printf("sending SMS to %s", sms->text);
	else
		printf("no SMS to send");
	printf(" (last_msisdn='%s')\n", last_msisdn? last_msisdn : "NULL");
}

struct {
	const char *msisdn;
	int nr_of_sms;
	int failed_attempts;
	bool vsub_attached;
} fake_sms_db[] = {
	{
		.msisdn = "1111",
		.nr_of_sms = 0,
		.vsub_attached = true,
	},
	{
		.msisdn = "2222",
		.nr_of_sms = 2,
		.failed_attempts = 2,
		.vsub_attached = true,
	},
	{
		.msisdn = "3333",
		.nr_of_sms = 2,
		.failed_attempts = 3,
		.vsub_attached = true,
	},
	{
		.msisdn = "4444",
		.nr_of_sms = 0,
		.vsub_attached = true,
	},
	{
		.msisdn = "5555",
		.nr_of_sms = 2,
		.failed_attempts = 5,
		.vsub_attached = false,
	},
};

/* override, requires '-Wl,--wrap=db_sms_get_next_unsent_rr_msisdn' */
struct gsm_sms *__real_db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
							const char *last_msisdn,
							unsigned int max_failed);
struct gsm_sms *__wrap_db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
							const char *last_msisdn,
							unsigned int max_failed)
{
	static struct vlr_subscr arbitrary_vsub = {};
	static bool arbitrary_vsub_set_up = false;
	struct gsm_sms *sms;
	int i;
	printf("     hitting database: looking for MSISDN > '%s', failed_attempts <= %d\n",
	       last_msisdn, max_failed);

	if (!arbitrary_vsub_set_up) {
		osmo_use_count_make_static_entries(&arbitrary_vsub.use_count, arbitrary_vsub.use_count_buf,
						   ARRAY_SIZE(arbitrary_vsub.use_count_buf));
		arbitrary_vsub_set_up = true;
	}

	/* Every time we call sms_free(), the internal logic of libmsc
	 * may call vlr_subscr_put() on our arbitrary_vsub, what would
	 * lead to a segfault if its use_count <= 0. To prevent this,
	 * let's ensure a big enough initial value. */
	osmo_use_count_get_put(&arbitrary_vsub.use_count, VSUB_USE_SMS_RECEIVER, 1000);
	osmo_use_count_get_put(&arbitrary_vsub.use_count, VSUB_USE_SMS_PENDING, 1000);
	arbitrary_vsub.lu_complete = true;

	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		if (!fake_sms_db[i].nr_of_sms)
			continue;
		if (strcmp(fake_sms_db[i].msisdn, last_msisdn) <= 0)
			continue;
		if (fake_sms_db[i].failed_attempts > max_failed)
			continue;

		sms = sms_alloc();
		OSMO_ASSERT(sms);

		osmo_strlcpy(sms->dst.addr, fake_sms_db[i].msisdn,
			     sizeof(sms->dst.addr));
		sms->receiver = fake_sms_db[i].vsub_attached? &arbitrary_vsub : NULL;
		osmo_strlcpy(sms->text, fake_sms_db[i].msisdn, sizeof(sms->text));
		if (fake_sms_db[i].vsub_attached)
			fake_sms_db[i].nr_of_sms--;
		return sms;
	}

	return NULL;
}

void show_fake_sms_db()
{
	int i;
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		printf("  %s%s has %u SMS pending, %u failed attempts\n",
		       fake_sms_db[i].msisdn,
		       fake_sms_db[i].vsub_attached ? "" : " (NOT attached)",
		       fake_sms_db[i].nr_of_sms,
		       fake_sms_db[i].failed_attempts);
	}
	printf("-->\n");
}

/* sms_free() is not safe against NULL */
#define sms_free_safe(sms) \
	if (sms != NULL) sms_free(sms)

static void test_next_sms()
{
	int i;
	char last_msisdn[VLR_MSISDN_LENGTH+1] = "";

	printf("Testing smsq_take_next_sms()\n");

	printf("\n- vsub 2, 3 and 5 each have 2 SMS pending, but 5 is not attached\n");
	last_msisdn[0] = '\0';
	show_fake_sms_db();
	for (i = 0; i < 7; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(i >= 4 || sms);
		sms_free_safe(sms);
	}

	printf("\n- SMS are pending at various nr failed attempts (cutoff at >= 10)\n");
	last_msisdn[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = true;
		fake_sms_db[i].nr_of_sms = 1 + i;
		fake_sms_db[i].failed_attempts = i*5;

	}
	show_fake_sms_db();
	for (i = 0; i < 7; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(i >= 2 || sms);
		sms_free_safe(sms);
	}

	printf("\n- iterate the SMS DB at most once\n");
	osmo_strlcpy(last_msisdn, "2345", sizeof(last_msisdn));
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = false;
		fake_sms_db[i].nr_of_sms = 1;
		fake_sms_db[i].failed_attempts = 0;
	}
	show_fake_sms_db();
	for (i = 0; i < 3; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(!sms);
	}

	printf("\n- there are no SMS in the DB\n");
	last_msisdn[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = true;
		fake_sms_db[i].nr_of_sms = 0;
		fake_sms_db[i].failed_attempts = 0;
	}
	show_fake_sms_db();
	for (i = 0; i < 3; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(!sms);
	}
}


static struct log_info_cat sms_queue_test_categories[] = {
};

static struct log_info info = {
	.cat = sms_queue_test_categories,
	.num_cat = ARRAY_SIZE(sms_queue_test_categories),
};

int main(int argc, char **argv)
{
	void *msgb_ctx;
	void *logging_ctx;

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	talloc_ctx = talloc_named_const(NULL, 0, "sms_queue_test");
	msgb_ctx = msgb_talloc_ctx_init(talloc_ctx, 0);
	logging_ctx = talloc_named_const(talloc_ctx, 0, "logging");
	osmo_init_logging2(logging_ctx, &info);

	/* Share our talloc context with libmsc's GSM 04.11 code,
	 * so sms_alloc() would use it instead of NULL. */
	tall_gsms_ctx = talloc_ctx;

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_parse_category_mask(osmo_stderr_target, "DLOAP,1");

	test_next_sms();
	printf("Done\n");

	if (talloc_total_blocks(msgb_ctx) != 1
	    || talloc_total_size(msgb_ctx) != 0) {
		talloc_report_full(msgb_ctx, stderr);
		fflush(stderr);
	}

	OSMO_ASSERT(talloc_total_blocks(msgb_ctx) == 1);
	OSMO_ASSERT(talloc_total_size(msgb_ctx) == 0);
	talloc_free(msgb_ctx);
	talloc_free(logging_ctx);

	if (talloc_total_blocks(talloc_ctx) != 1
	    || talloc_total_size(talloc_ctx) != 0)
		talloc_report_full(talloc_ctx, stderr);

	OSMO_ASSERT(talloc_total_blocks(talloc_ctx) == 1);
	OSMO_ASSERT(talloc_total_size(talloc_ctx) == 0);
	talloc_free(talloc_ctx);

	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return 0;
}

void osmo_stream_srv_link_set_data(struct osmo_stream_srv_link *link, void *data) {}
struct osmo_fd *osmo_stream_srv_get_ofd(struct osmo_stream_srv *srv) { return NULL; }
void osmo_stream_srv_destroy(struct osmo_stream_srv *conn) {}
struct osmo_stream_srv *osmo_stream_srv_create(void *ctx, struct osmo_stream_srv_link *link,
					       int fd, int (*cb)(struct osmo_stream_srv *conn),
					       int (*closed_cb)(struct osmo_stream_srv *conn),
					       void *data) { return NULL; }
void osmo_stream_srv_send(struct osmo_stream_srv *conn, struct msgb *msg) {}
void osmo_stream_srv_link_set_proto(struct osmo_stream_srv_link *link, uint16_t proto) {}
struct osmo_fd *osmo_stream_srv_link_get_ofd(struct osmo_stream_srv_link *link) { return NULL; }
struct osmo_stream_srv_link *osmo_stream_srv_link_create(void *ctx) { return NULL; }
void *osmo_stream_srv_get_data(struct osmo_stream_srv *conn) { return NULL; }
void osmo_stream_srv_link_set_nodelay(struct osmo_stream_srv_link *link, bool nodelay) {}
void osmo_stream_srv_link_set_accept_cb(struct osmo_stream_srv_link *link, int (*accept_cb)
					(struct osmo_stream_srv_link *link, int fd)) {}
int osmo_stream_srv_link_open(struct osmo_stream_srv_link *link) { return 0; }
void *osmo_stream_srv_link_get_data(struct osmo_stream_srv_link *link) { return NULL; }
void osmo_stream_srv_link_set_port(struct osmo_stream_srv_link *link, uint16_t port) {}
void osmo_stream_srv_link_set_addr(struct osmo_stream_srv_link *link, const char *addr) {}
int sctp_recvmsg(int sd, void *msg, size_t len, void *from, void *fromlen, void *info, int *msg_flags) { return 0; }
