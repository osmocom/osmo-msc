#pragma once

#include <osmocom/gsm/protocol/gsm_04_14.h>

struct msc_a;

int gsm0414_tx_close_tch_loop_cmd(struct msc_a *msc_a,
				  enum gsm414_tch_loop_mode loop_mode);
int gsm0414_tx_open_loop_cmd(struct msc_a *msc_a);
int gsm0414_tx_act_emmi_cmd(struct msc_a *msc_a);
int gsm0414_tx_test_interface(struct msc_a *msc_a,
			      uint8_t tested_devs);
int gsm0414_tx_reset_ms_pos_store(struct msc_a *msc_a,
				  uint8_t technology);

int gsm0414_rcv_test(struct msc_a *msc_a,
		     struct msgb *msg);
