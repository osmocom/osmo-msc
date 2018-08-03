#pragma once

#include <osmocom/msc/gsm_data_shared.h>

enum rrlp_mode msc_rrlp_mode_parse(const char *arg);
const char *msc_rrlp_mode_name(enum rrlp_mode mode);

void msc_rrlp_init(void);
