#pragma once

#include <osmocom/sdp/sdp_msg.h>
#include <osmocom/msc/csd_bs.h>

void sdp_codecs_set_csd(void *ctx, struct osmo_sdp_codec_list **codecs);
