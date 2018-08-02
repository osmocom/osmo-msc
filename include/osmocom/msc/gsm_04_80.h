#pragma once

#include <stdint.h>

struct gsm_subscriber_connection;

int msc_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     uint8_t transaction_id, int invoke_id,
			     uint8_t problem_tag, uint8_t problem_code);

int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);
