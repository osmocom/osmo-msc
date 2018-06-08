#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_subscriber_connection;

int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const char* response_text,
			       const struct ss_request *req);
int gsm0480_send_ussd_return_error(struct gsm_subscriber_connection *conn,
				   const struct ss_request *req,
				   uint8_t error_code);
int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct ss_request *req,
			     uint8_t error_tag, uint8_t error_code);

int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);
