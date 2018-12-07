#pragma once

#include <stdint.h>

struct msc_a;

int msc_send_ussd_reject(struct msc_a *msc_a, uint8_t transaction_id, int invoke_id,
			 uint8_t problem_tag, uint8_t problem_code);

int msc_send_ussd_notify(struct msc_a *msc_a, int level, const char *text);
int msc_send_ussd_release_complete(struct msc_a *msc_a, uint8_t transaction_id);
int msc_send_ussd_release_complete_cause(struct msc_a *msc_a,
					 uint8_t transaction_id,
					 uint8_t cause_loc, uint8_t cause_val);
