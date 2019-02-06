#pragma once

#include <stdint.h>

struct ran_conn;

int msc_send_ussd_reject(struct ran_conn *conn,
			     uint8_t transaction_id, int invoke_id,
			     uint8_t problem_tag, uint8_t problem_code);

int msc_send_ussd_notify(struct ran_conn *conn, int level,
			 const char *text);
int msc_send_ussd_release_complete(struct ran_conn *conn,
				   uint8_t transaction_id);
int msc_send_ussd_release_complete_cause(struct ran_conn *conn,
					 uint8_t transaction_id,
					 uint8_t cause_loc, uint8_t cause_val);
