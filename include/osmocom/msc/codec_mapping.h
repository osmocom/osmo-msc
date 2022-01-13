/* Routines for translation between codec representations: SDP, CC/BSSMAP variants, MGCP, MNCC */
#pragma once

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/sdp_msg.h>
#include <osmocom/gsm/mncc.h>

#define NO_MGCP_CODEC 0xffffffff

extern const struct gsm_mncc_bearer_cap bearer_cap_empty;

enum codec_frhr {
	CODEC_FRHR_NONE = 0,
	CODEC_FRHR_FR,
	CODEC_FRHR_HR,
};

struct codec_mapping {
	/* The sdp.payload_type number in a mapping is not necessarily imperative, but may just reflect the usual
	 * payload type number for a given codec. */
	struct sdp_audio_codec sdp;
	/* The id that mgcp_client.h uses for this codec. Must be set in each mapping, because 0 means PCMU. */
	enum mgcp_codecs mgcp;
	/* Nr of used entries in speech_ver[] below. */
	unsigned int speech_ver_count;
	/* Entries to add to Speech Version lists when this codec is present, if any. */
	enum gsm48_bcap_speech_ver speech_ver[8];
	/* If applicable, one of GSM_TCHF_FRAME, GSM_TCHF_FRAME_EFR, GSM_TCHH_FRAME, GSM_TCH_FRAME_AMR; or zero. */
	uint32_t mncc_payload_msg_type;
	/* Set to true if gsm0808_speech_codec below reflects a meaningful value. */
	bool has_gsm0808_speech_codec;
	struct gsm0808_speech_codec gsm0808_speech_codec;
	/* If applicable, entries to add to Permitted Speech lists when this codec is present; or zero. */
	enum gsm0808_permitted_speech perm_speech;
	/* If applicable, indicator whether this codec can work on a GERAN half-rate lchan, or whether full-rate is
	 * required. Leave zero when this codec does not apply to GERAN. */
	enum codec_frhr frhr;
};

const struct codec_mapping *codec_mapping_by_speech_ver(enum gsm48_bcap_speech_ver speech_ver);
const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec_type(enum gsm0808_speech_codec_type sct);
const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec(const struct gsm0808_speech_codec *sc);
const struct codec_mapping *codec_mapping_by_perm_speech(enum gsm0808_permitted_speech perm_speech);
const struct codec_mapping *codec_mapping_by_subtype_name(const char *subtype_name);
const struct codec_mapping *codec_mapping_by_mgcp_codec(enum mgcp_codecs mgcp);

int bearer_cap_add_speech_ver(struct gsm_mncc_bearer_cap *bearer_cap, enum gsm48_bcap_speech_ver speech_ver);
int sdp_audio_codec_add_to_bearer_cap(struct gsm_mncc_bearer_cap *bearer_cap, const struct sdp_audio_codec *codec);
int sdp_audio_codecs_to_bearer_cap(struct gsm_mncc_bearer_cap *bearer_cap, const struct sdp_audio_codecs *ac);
int bearer_cap_set_radio(struct gsm_mncc_bearer_cap *bearer_cap);

struct sdp_audio_codec *sdp_audio_codecs_add_speech_ver(struct sdp_audio_codecs *ac,
							enum gsm48_bcap_speech_ver speech_ver);
struct sdp_audio_codec *sdp_audio_codecs_add_mgcp_codec(struct sdp_audio_codecs *ac, enum mgcp_codecs mgcp_codec);
void sdp_audio_codecs_from_bearer_cap(struct sdp_audio_codecs *ac, const struct gsm_mncc_bearer_cap *bc);

void sdp_audio_codecs_to_speech_codec_list(struct gsm0808_speech_codec_list *cl, const struct sdp_audio_codecs *ac);
void sdp_audio_codecs_from_speech_codec_list(struct sdp_audio_codecs *ac, const struct gsm0808_speech_codec_list *cl);

int sdp_audio_codecs_to_gsm0808_channel_type(struct gsm0808_channel_type *ct, const struct sdp_audio_codecs *ac);

enum mgcp_codecs sdp_audio_codec_to_mgcp_codec(const struct sdp_audio_codec *codec);
