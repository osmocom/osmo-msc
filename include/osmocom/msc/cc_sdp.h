#pragma once

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/sdp_msg.h>

struct gsm0808_speech_codec_list;

struct cc_sdp {
	/* The fixed set of codecs available on the RAN type, per definition. */
	struct sdp_audio_codecs ran;
	/* The codecs advertised by the MS Bearer Capabilities */
	struct sdp_audio_codecs ms;
	/* If known, the set of codecs the current RAN cell allows / has available.
	 * This may not be available if the BSC does not issue this information early enough.
	 * Should be ignored if empty. */
	struct sdp_audio_codecs cell;

	/* SDP as last received from the remote call leg. */
	struct sdp_msg remote;

	/* After a channel was assigned, this reflects the chosen codec. */
	struct sdp_audio_codec assignment;

	/* Resulting choice of supported codecs, usually the intersection of the above,
	 * and the local RTP address to be sent to the remote call leg. */
	struct sdp_msg result;
};

void cc_sdp_init(struct cc_sdp *cc_sdp,
		 enum osmo_rat_type ran_type,
		 const struct gsm_mncc_bearer_cap *ms_bearer_cap,
		 const struct gsm0808_speech_codec_list *codec_list_bss_supported);
void cc_sdp_set_cell(struct cc_sdp *cc_sdp,
		     const struct gsm0808_speech_codec_list *codec_list_bss_supported);
int cc_sdp_filter(struct cc_sdp *cc_sdp);

int cc_sdp_name_buf(char *buf, size_t buflen, const struct cc_sdp *cc_sdp);
char *cc_sdp_name_c(void *ctx, const struct cc_sdp *cc_sdp);
const char *cc_sdp_name(const struct cc_sdp *cc_sdp);
