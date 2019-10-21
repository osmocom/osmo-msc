/* Routines for translation ("t9n") between SDP codec names and CC/BSSMAP codec constants */
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
	struct sdp_audio_codec sdp;
	enum mgcp_codecs mgcp;
	unsigned int speech_ver_count;
	enum gsm48_bcap_speech_ver speech_ver[8];
	uint32_t mncc_payload_msg_type;
	/* gsm0808_speech_codec_type corresponds to gsm0808_speech_codec[_list]->type */
	bool has_gsm0808_speech_codec_type;
	enum gsm0808_speech_codec_type gsm0808_speech_codec_type;
	enum gsm0808_permitted_speech perm_speech;
	enum codec_frhr frhr;
};

extern const struct codec_mapping codec_map[];
#define foreach_codec_mapping(CODEC_MAPPING) \
	for ((CODEC_MAPPING) = codec_map; (CODEC_MAPPING) < codec_map + ARRAY_SIZE(codec_map); (CODEC_MAPPING)++)

const struct codec_mapping *codec_mapping_by_speech_ver(enum gsm48_bcap_speech_ver speech_ver);
const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec_type(enum gsm0808_speech_codec_type sct,
								       uint16_t cfg);
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

void sdp_audio_codecs_from_speech_codec_list(struct sdp_audio_codecs *ac, const struct gsm0808_speech_codec_list *cl);

int sdp_audio_codecs_to_gsm0808_channel_type(struct gsm0808_channel_type *ct, const struct sdp_audio_codecs *ac);

enum mgcp_codecs sdp_audio_codec_to_mgcp_codec(const struct sdp_audio_codec *codec);
