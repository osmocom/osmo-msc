/* Minimalistic SDP parse/compose API, focused on GSM audio codecs */
#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/sockaddr_str.h>

extern const struct value_string sdp_msg_payload_type_names[];
static inline const char *sdp_msg_payload_type_name(unsigned int payload_type)
{ return get_value_string(sdp_msg_payload_type_names, payload_type); }
int sdp_subtype_name_to_payload_type(const char *subtype_name);

struct sdp_audio_codec {
	unsigned int payload_type;
	/* Like "GSM", "AMR", "EFR", ... */
	char subtype_name[16];
	unsigned int rate;
	char fmtp[64];
};

struct sdp_audio_codecs {
	unsigned int count;
	struct sdp_audio_codec codec[16];
};

struct sdp_msg {
	struct osmo_sockaddr_str rtp;
	unsigned int ptime;
	struct sdp_audio_codecs audio_codecs;
};

#define foreach_sdp_audio_codec(/* struct sdp_audio_codec* */ CODEC, \
				/* struct sdp_audio_codecs* */ AC) \
	for (CODEC = (AC)->codec; \
	     (CODEC - (AC)->codec) < OSMO_MIN((AC)->count, ARRAY_SIZE((AC)->codec)); \
	     CODEC++)

const char *sdp_msg_line_end(const char *src);

int sdp_audio_codec_cmp(const struct sdp_audio_codec *a, const struct sdp_audio_codec *b,
			bool cmp_fmtp, bool cmp_payload_type);
int sdp_audio_codecs_cmp(const struct sdp_audio_codecs *a, const struct sdp_audio_codecs *b,
			 bool cmp_fmtp, bool cmp_payload_type);

struct sdp_audio_codec *sdp_audio_codec_add(struct sdp_audio_codecs *ac, unsigned int payload_type,
					    const char *subtype_name, unsigned int rate, const char *fmtp);
struct sdp_audio_codec *sdp_audio_codec_add_copy(struct sdp_audio_codecs *ac,
						 const struct sdp_audio_codec *codec);
int sdp_audio_codec_remove(struct sdp_audio_codecs *ac, const struct sdp_audio_codec *codec);
struct sdp_audio_codec *sdp_audio_codec_by_payload_type(struct sdp_audio_codecs *ac,
							unsigned int payload_type, bool create);
struct sdp_audio_codec *sdp_audio_codec_by_descr(struct sdp_audio_codecs *ac,
						 const struct sdp_audio_codec *codec);

void sdp_audio_codecs_intersection(struct sdp_audio_codecs *ac_dest, const struct sdp_audio_codecs *ac_other,
				   bool translate_payload_type_numbers);
void sdp_audio_codecs_select(struct sdp_audio_codecs *ac, struct sdp_audio_codec *codec);

int sdp_msg_to_str(char *dst, size_t dst_size, const struct sdp_msg *sdp);
int sdp_msg_from_str(struct sdp_msg *sdp, const char *src);

int sdp_audio_codec_name_buf(char *buf, size_t buflen, const struct sdp_audio_codec *codec);
char *sdp_audio_codec_name_c(void *ctx, const struct sdp_audio_codec *codec);
const char *sdp_audio_codec_name(const struct sdp_audio_codec *codec);

int sdp_audio_codecs_name_buf(char *buf, size_t buflen, const struct sdp_audio_codecs *ac);
char *sdp_audio_codecs_name_c(void *ctx, const struct sdp_audio_codecs *ac);
const char *sdp_audio_codecs_name(const struct sdp_audio_codecs *ac);

int sdp_msg_name_buf(char *buf, size_t buflen, const struct sdp_msg *sdp);
char *sdp_msg_name_c(void *ctx, const struct sdp_msg *sdp);
const char *sdp_msg_name(const struct sdp_msg *sdp);
