/* Minimalistic SDP parse/compose implementation, focused on GSM audio codecs */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Neels Hofmeyr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/sdp_msg.h>

bool sdp_audio_codec_is_set(const struct sdp_audio_codec *a)
{
	return a && a->subtype_name[0];
}

/* Compare name, rate and fmtp, returning typical cmp result: 0 on match, and -1 / 1 on mismatch.
 * If cmp_fmtp is false, do *not* compare the fmtp string; if true, compare fmtp 1:1 as strings.
 * If cmp_payload_type is false, do *not* compare the payload_type number.
 * The fmtp is only string-compared -- e.g. if AMR parameters appear in a different order, it amounts to a mismatch even
 * though all parameters are the same. */
int sdp_audio_codec_cmp(const struct sdp_audio_codec *a, const struct sdp_audio_codec *b,
			bool cmp_fmtp, bool cmp_payload_type)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	cmp = strncmp(a->subtype_name, b->subtype_name, sizeof(a->subtype_name));
	if (cmp)
		return cmp;
	cmp = OSMO_CMP(a->rate, b->rate);
	if (cmp)
		return cmp;
	if (cmp_fmtp) {
		cmp = strncmp(a->fmtp, b->fmtp, sizeof(a->fmtp));
		if (cmp)
			return cmp;
	}
	if (cmp_payload_type) {
		cmp = OSMO_CMP(a->payload_type, b->payload_type);
		if (cmp)
			return cmp;
	}
	return 0;
}

/* Compare two lists of audio codecs, returning typical cmp result: 0 on match, and -1 / 1 on mismatch.
 * The ordering in the two lists may differ, except that the first codec in 'a' must also be the first codec in 'b'.
 * This is because the first codec typically expresses the preferred codec to use.
 * If cmp_fmtp is false, do *not* compare the fmtp strings; if true, compare fmtp 1:1 as strings.
 * If cmp_payload_type is false, do *not* compare the payload_type numbers.
 * The fmtp is only string-compared -- e.g. if AMR parameters appear in a different order, it amounts to a mismatch even
 * though all parameters are the same. */
int sdp_audio_codecs_cmp(const struct sdp_audio_codecs *a, const struct sdp_audio_codecs *b,
			 bool cmp_fmtp, bool cmp_payload_type)
{
	const struct sdp_audio_codec *codec_a;
	const struct sdp_audio_codec *codec_b;
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	cmp = OSMO_CMP(a->count, b->count);
	if (cmp)
		return cmp;

	if (!a->count)
		return 0;

	/* The first codec is the "chosen" codec and should match. The others may appear in different order. */
	cmp = sdp_audio_codec_cmp(&a->codec[0], &b->codec[0], cmp_fmtp, cmp_payload_type);
	if (cmp)
		return cmp;

	/* See if each codec in a is also present in b */
	foreach_sdp_audio_codec(codec_a, a) {
		bool match_found = false;
		foreach_sdp_audio_codec(codec_b, b) {
			if (!sdp_audio_codec_cmp(codec_a, codec_b, cmp_fmtp, cmp_payload_type)) {
				match_found = true;
				break;
			}
		}
		if (!match_found)
			return -1;
	}

	return 0;
}

/* Given a predefined fixed payload_type number, add an SDP audio codec entry, if not present yet.
 * The payload_type must exist in sdp_msg_payload_type_names.
 * Return the audio codec created or already existing for this payload type number.
 */
struct sdp_audio_codec *sdp_audio_codecs_add(struct sdp_audio_codecs *ac, unsigned int payload_type,
					     const char *subtype_name, unsigned int rate, const char *fmtp)
{
	struct sdp_audio_codec *codec;

	/* Does an entry already exist? */
	codec = sdp_audio_codecs_by_payload_type(ac, payload_type, false);
	if (codec) {
		/* Already exists, sanity check */
		if (!codec->subtype_name[0])
			OSMO_STRLCPY_ARRAY(codec->subtype_name, subtype_name);
		else if (strcmp(codec->subtype_name, subtype_name)) {
			/* There already is an entry with this payload_type number but a mismatching subtype_name. That is
			 * weird, rather abort. */
			return NULL;
		}
		if (codec->rate != rate
		    || (fmtp && strcmp(fmtp, codec->fmtp))) {
			/* Mismatching details. Rather abort */
			return NULL;
		}
		return codec;
	}

	/* None exists, create codec entry for this payload type number */
	codec = sdp_audio_codecs_by_payload_type(ac, payload_type, true);
	/* NULL means unable to add an entry */
	if (!codec)
		return NULL;

	OSMO_STRLCPY_ARRAY(codec->subtype_name, subtype_name);
	if (fmtp)
		OSMO_STRLCPY_ARRAY(codec->fmtp, fmtp);
	codec->rate = rate;
	return codec;
}

struct sdp_audio_codec *sdp_audio_codecs_add_copy(struct sdp_audio_codecs *ac, const struct sdp_audio_codec *codec)
{
	return sdp_audio_codecs_add(ac, codec->payload_type, codec->subtype_name, codec->rate,
				    codec->fmtp[0] ? codec->fmtp : NULL);
}

/* Find or create an entry for the given payload_type number in the given list of codecs.
 * If the given payload_type number is already present in ac, return the first matching entry.
 * If no such payload_type number is present: a) return NULL if create == false;
 * b) If create == true, add a mostly empty codec entry to the end of ac with the given payload_type number, and return
 * the created entry.
 * If create == true, a NULL return value means that there was no unused entry left in ac to add this payload_type.
 */
struct sdp_audio_codec *sdp_audio_codecs_by_payload_type(struct sdp_audio_codecs *ac, unsigned int payload_type,
							 bool create)
{
	struct sdp_audio_codec *codec;
	foreach_sdp_audio_codec(codec, ac) {
		if (codec->payload_type == payload_type)
			return codec;
	}

	if (!create)
		return NULL;

	/* Not found; codec points after the last entry now. */
	if ((codec - ac->codec) >= ARRAY_SIZE(ac->codec))
		return NULL;

	*codec = (struct sdp_audio_codec){
		.payload_type = payload_type,
		.rate = 8000,
	};

	ac->count = (codec - ac->codec) + 1;
	return codec;
}

/* Return a given sdp_msg's codec entry that matches the subtype_name and rate of the given codec, or NULL if no
 * match is found. Comparison is made by sdp_audio_codec_cmp(cmp_payload_type=false). */
struct sdp_audio_codec *sdp_audio_codecs_by_descr(struct sdp_audio_codecs *ac, const struct sdp_audio_codec *codec)
{
	struct sdp_audio_codec *i;
	foreach_sdp_audio_codec(i, ac) {
		if (!sdp_audio_codec_cmp(i, codec, false, false))
			return i;
	}
	return NULL;
}

/* Remove the codec entry pointed at by 'codec'. 'codec' must point at an entry of 'sdp' (to use an external codec
 * instance, use sdp_audio_codecs_by_descr()).
 * Return 0 on success, -ENOENT if codec does not point at the sdp->codec array. */
int sdp_audio_codecs_remove(struct sdp_audio_codecs *ac, const struct sdp_audio_codec *codec)
{
	struct sdp_audio_codec *i;
	if ((codec < ac->codec)
	    || ((codec - ac->codec) >= OSMO_MIN(ac->count, ARRAY_SIZE(ac->codec))))
		return -ENOENT;

	/* Move all following entries one up */
	ac->count--;
	foreach_sdp_audio_codec(i, ac) {
		if (i < codec)
			continue;
		*i = *(i+1);
	}
	return 0;
}

static const char * const sdp_mode_str[] = {
	[SDP_MODE_UNSET] = "-",
	[SDP_MODE_SENDONLY] = "sendonly",
	[SDP_MODE_RECVONLY] = "recvonly",
	[SDP_MODE_SENDRECV] = "sendrecv",
	[SDP_MODE_INACTIVE] = "inactive",
};

/* Convert struct sdp_msg to the actual SDP protocol representation */
int sdp_msg_to_sdp_str_buf(char *dst, size_t dst_size, const struct sdp_msg *sdp)
{
	const struct sdp_audio_codec *codec;
	struct osmo_strbuf sb = { .buf = dst, .len = dst_size };
	const char *ip;
	char ipv;

	if (!sdp) {
		OSMO_STRBUF_PRINTF(sb, "%s", "");
		return sb.chars_needed;
	}

	ip = sdp->rtp.ip[0] ? sdp->rtp.ip : "0.0.0.0";
	ipv = (osmo_ip_str_type(ip) == AF_INET6) ? '6' : '4';

	OSMO_STRBUF_PRINTF(sb,
			   "v=0\r\n"
			   "o=OsmoMSC 0 0 IN IP%c %s\r\n"
			   "s=GSM Call\r\n"
			   "c=IN IP%c %s\r\n"
			   "t=0 0\r\n"
			   "m=audio %d RTP/AVP",
			   ipv, ip, ipv, ip,
			   sdp->rtp.port);

	/* Append all payload type numbers to 'm=audio <port> RTP/AVP 3 4 112' line */
	foreach_sdp_audio_codec(codec, &sdp->audio_codecs)
		OSMO_STRBUF_PRINTF(sb, " %d", codec->payload_type);
	OSMO_STRBUF_PRINTF(sb, "\r\n");

	/* Add details for all codecs */
	foreach_sdp_audio_codec(codec, &sdp->audio_codecs) {
		if (!sdp_audio_codec_is_set(codec))
			continue;
		OSMO_STRBUF_PRINTF(sb, "a=rtpmap:%d %s/%d\r\n", codec->payload_type, codec->subtype_name,
				   codec->rate > 0 ? codec->rate : 8000);
		if (codec->fmtp[0])
			OSMO_STRBUF_PRINTF(sb, "a=fmtp:%d %s\r\n", codec->payload_type, codec->fmtp);
	}

	OSMO_STRBUF_PRINTF(sb, "a=ptime:%d\r\n", sdp->ptime > 0? sdp->ptime : 20);

	if (sdp->mode != SDP_MODE_UNSET && sdp->mode < ARRAY_SIZE(sdp_mode_str))
		OSMO_STRBUF_PRINTF(sb, "a=%s\r\n", sdp_mode_str[sdp->mode]);

	return sb.chars_needed;
}

/* Return the first line ending (or the end of the string) at or after the given string position. */
const char *sdp_msg_line_end(const char *src)
{
	const char *line_end = strchr(src, '\r');
	if (!line_end)
		line_end = strchr(src, '\n');
	if (!line_end)
		line_end = src + strlen(src);
	return line_end;
}

/* parse a line like 'a=rtpmap:0 PCMU/8000', 'a=fmtp:112 octet-align=1; mode-set=4', 'a=ptime:20'.
 * The src should point at the character after 'a=', e.g. at the start of 'rtpmap', 'fmtp', 'ptime'
 */
int sdp_parse_attrib(struct sdp_msg *sdp, const char *src)
{
	unsigned int payload_type;
	struct sdp_audio_codec *codec;
#define A_RTPMAP "rtpmap:"
#define A_FMTP "fmtp:"
#define A_PTIME "ptime:"
#define A_RTCP "rtcp:"

	if (osmo_str_startswith(src, A_RTPMAP)) {
		/* "a=rtpmap:3 GSM/8000" */
		char *audio_name;
		unsigned int channels = 1;
		if (sscanf(src, A_RTPMAP "%u", &payload_type) != 1)
			return -EINVAL;

		audio_name = strchr(src, ' ');
		if (!audio_name || audio_name >= sdp_msg_line_end(src))
			return -EINVAL;

		codec = sdp_audio_codecs_by_payload_type(&sdp->audio_codecs, payload_type, true);
		if (!codec)
			return -ENOSPC;

		if (sscanf(audio_name, " %31[^/]/%u/%u", codec->subtype_name, &codec->rate, &channels) < 1)
			return -EINVAL;

		if (channels != 1)
			return -ENOTSUP;
	}

	else if (osmo_str_startswith(src, A_FMTP)) {
		/* "a=fmtp:112 octet-align=1;mode-set=0,1,2,3" */
		char *fmtp_str;
		const char *line_end = sdp_msg_line_end(src);
		if (sscanf(src, A_FMTP "%u", &payload_type) != 1)
			return -EINVAL;

		fmtp_str = strchr(src, ' ');
		if (!fmtp_str)
			return -EINVAL;
		fmtp_str++;
		if (fmtp_str >= line_end)
			return -EINVAL;

		codec = sdp_audio_codecs_by_payload_type(&sdp->audio_codecs, payload_type, true);
		if (!codec)
			return -ENOSPC;

		/* (+1 because osmo_strlcpy() interprets it as size including the '\0') */
		osmo_strlcpy(codec->fmtp, fmtp_str, line_end - fmtp_str + 1);
	}

	else if (osmo_str_startswith(src, A_PTIME)) {
		/* "a=ptime:20" */
		if (sscanf(src, A_PTIME "%u", &sdp->ptime) != 1)
			return -EINVAL;

	}

	else if (osmo_str_startswith(src, A_RTCP)) {
		/* TODO? */
	}

	else if (osmo_str_startswith(src, sdp_mode_str[SDP_MODE_SENDRECV])) {
		/* "a=sendrecv" */
		sdp->mode = SDP_MODE_SENDRECV;
	}

	else if (osmo_str_startswith(src, sdp_mode_str[SDP_MODE_SENDONLY])) {
		/* "a=sendonly" */
		sdp->mode = SDP_MODE_SENDONLY;
	}

	else if (osmo_str_startswith(src, sdp_mode_str[SDP_MODE_RECVONLY])) {
		/* "a=recvonly" */
		sdp->mode = SDP_MODE_RECVONLY;
	}

	else if (osmo_str_startswith(src, sdp_mode_str[SDP_MODE_INACTIVE])) {
		/* "a=inactive" */
		sdp->mode = SDP_MODE_INACTIVE;
	}

	return 0;
}

const struct value_string sdp_msg_payload_type_names[] = {
	{ 0, "PCMU" },
	{ 3, "GSM" },
	{ 8, "PCMA" },
	{ 18, "G729" },
	{ 110, "GSM-EFR" },
	{ 111, "GSM-HR-08" },
	{ 112, "AMR" },
	{ 113, "AMR-WB" },
	{}
};

/* Return payload type number matching given string ("AMR", "GSM", ...) or negative if not found. */
int sdp_subtype_name_to_payload_type(const char *subtype_name)
{
	return get_string_value(sdp_msg_payload_type_names, subtype_name);
}

/* Parse a line like 'm=audio 16398 RTP/AVP 0 3 8 96 112', starting after the '=' */
static int sdp_parse_media_description(struct sdp_msg *sdp, const char *src)
{
	unsigned int port;
	int i;
	const char *payload_type_str;
	const char *line_end = sdp_msg_line_end(src);
	if (sscanf(src, "audio %u RTP/AVP", &port) < 1)
		return -ENOTSUP;

	if (port > 0xffff)
		return -EINVAL;

	sdp->rtp.port = port;

	/* skip "audio 12345 RTP/AVP ", i.e. 3 spaces on */
	payload_type_str = src;
	for (i = 0; i < 3; i++) {
		payload_type_str = strchr(payload_type_str, ' ');
		if (!payload_type_str)
			return -EINVAL;
		while (*payload_type_str == ' ')
			payload_type_str++;
		if (payload_type_str >= line_end)
			return -EINVAL;
	}

	/* Parse listing of payload type numbers after "RTP/AVP" */
	while (payload_type_str < line_end) {
		unsigned int payload_type;
		struct sdp_audio_codec *codec;
		const char *subtype_name;
		if (sscanf(payload_type_str, "%u", &payload_type) < 1)
			return -EINVAL;

		codec = sdp_audio_codecs_by_payload_type(&sdp->audio_codecs, payload_type, true);
		if (!codec)
			return -ENOSPC;

		/* Fill in subtype name for fixed payload types */
		subtype_name = get_value_string_or_null(sdp_msg_payload_type_names, codec->payload_type);
		if (subtype_name)
			OSMO_STRLCPY_ARRAY(codec->subtype_name, subtype_name);

		payload_type_str = strchr(payload_type_str, ' ');
		if (!payload_type_str)
			payload_type_str = line_end;
		while (*payload_type_str == ' ')
			payload_type_str++;
	}

	return 0;
}

/* parse a line like 'c=IN IP4 192.168.11.151' starting after the '=' */
static int sdp_parse_connection_info(struct sdp_msg *sdp, const char *src)
{
	char ipv[10];
	char addr_str[INET6_ADDRSTRLEN];
	if (sscanf(src, "IN %s %s", ipv, addr_str) < 2)
		return -EINVAL;

	/* supporting only IPv4 */
	if (strcmp(ipv, "IP4"))
		return -ENOTSUP;

	osmo_sockaddr_str_from_str(&sdp->rtp, addr_str, sdp->rtp.port);
	return 0;
}

/* Parse SDP string into struct sdp_msg. Return 0 on success, negative on error. */
int sdp_msg_from_sdp_str(struct sdp_msg *sdp, const char *src)
{
	const char *pos;
	*sdp = (struct sdp_msg){};

	for (pos = src; pos && *pos; pos++) {
		char attrib;
		int rc = 0;

		if (*pos == '\r' || *pos == '\n')
			continue;

		/* Expecting only lines starting with 'X='. Not being too strict about it is probably alright. */
		if (pos[1] != '=')
			goto next_line;

		attrib = *pos;
		pos += 2;
		switch (attrib) {
			/* a=... */
			case 'a':
				rc = sdp_parse_attrib(sdp, pos);
				break;
			case 'm':
				rc = sdp_parse_media_description(sdp, pos);
				break;
			case 'c':
				rc = sdp_parse_connection_info(sdp, pos);
				break;
			default:
				/* ignore any other parameters */
				break;
		}

		if (rc) {
			size_t line_len;
			const char *line_end = sdp_msg_line_end(pos);
			pos -= 2;
			line_len = line_end - pos;
			switch (rc) {
			case -EINVAL:
				LOGP(DMNCC, LOGL_ERROR,
				     "Failed to parse SDP: invalid line: %s\n", osmo_quote_str(pos, line_len));
				break;
			case -ENOSPC:
				LOGP(DMNCC, LOGL_ERROR,
				     "Failed to parse SDP: no more space for: %s\n", osmo_quote_str(pos, line_len));
				break;
			case -ENOTSUP:
				LOGP(DMNCC, LOGL_ERROR,
				     "Failed to parse SDP: not supported: %s\n", osmo_quote_str(pos, line_len));
				break;
			default:
				LOGP(DMNCC, LOGL_ERROR,
				     "Failed to parse SDP: %s\n", osmo_quote_str(pos, line_len));
				break;
			}
			return rc;
		}
next_line:
		pos = strstr(pos, "\r\n");
		if (!pos)
			break;
	}

	return 0;
}

/* Leave only those codecs in 'ac_dest' that are also present in 'ac_other'.
 * The matching is made by sdp_audio_codec_cmp(cmp_payload_type=false), i.e. payload_type numbers are not compared and
 * fmtp parameters are compared 1:1 as plain strings.
 * If translate_payload_type_numbers has an effect if ac_dest and ac_other have mismatching payload_type numbers for the
 * same SDP codec descriptions. If translate_payload_type_numbers is true, take the payload_type numbers from ac_other.
 * If false, keep payload_type numbers in ac_dest unchanged. */
void sdp_audio_codecs_intersection(struct sdp_audio_codecs *ac_dest, const struct sdp_audio_codecs *ac_other,
				   bool translate_payload_type_numbers)
{
	int i;
	for (i = 0; i < ac_dest->count; i++) {
		struct sdp_audio_codec *codec = &ac_dest->codec[i];
		struct sdp_audio_codec *other;
		OSMO_ASSERT(i < ARRAY_SIZE(ac_dest->codec));

		other = sdp_audio_codecs_by_descr((struct sdp_audio_codecs *)ac_other, codec);

		if (!other) {
			OSMO_ASSERT(sdp_audio_codecs_remove(ac_dest, codec) == 0);
			i--;
			continue;
		}

		/* Doing payload_type number translation of part of the intersection because it makes the algorithm
		 * simpler: we already know ac_dest is a subset of ac_other, and there is no need to resolve payload
		 * type number conflicts. */
		if (translate_payload_type_numbers)
			codec->payload_type = other->payload_type;
	}
}

/* Make sure the given codec is listed as the first codec. 'codec' must be an actual codec entry of the given audio
 * codecs list. */
void sdp_audio_codecs_select(struct sdp_audio_codecs *ac, struct sdp_audio_codec *codec)
{
	struct sdp_audio_codec tmp;
	struct sdp_audio_codec *pos;
	OSMO_ASSERT((codec >= ac->codec)
		    && ((codec - ac->codec) < OSMO_MIN(ac->count, ARRAY_SIZE(ac->codec))));

	/* Already the first? */
	if (codec == ac->codec)
		return;

	tmp = *codec;
	for (pos = codec - 1; pos >= ac->codec; pos--)
		pos[1] = pos[0];

	ac->codec[0] = tmp;
	return;
}

/* Short single-line representation of an SDP audio codec, convenient for logging.
 * Like "AMR/8000:octet-align=1#122" */
int sdp_audio_codec_to_str_buf(char *buf, size_t buflen, const struct sdp_audio_codec *codec)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "%s", codec->subtype_name);
	if (codec->rate != 8000)
		OSMO_STRBUF_PRINTF(sb, "/%u", codec->rate);
	if (codec->fmtp[0])
		OSMO_STRBUF_PRINTF(sb, ":%s", codec->fmtp);
	OSMO_STRBUF_PRINTF(sb, "#%d", codec->payload_type);
	return sb.chars_needed;
}

char *sdp_audio_codec_to_str_c(void *ctx, const struct sdp_audio_codec *codec)
{
	OSMO_NAME_C_IMPL(ctx, 32, "sdp_audio_codec_to_str_c-ERROR", sdp_audio_codec_to_str_buf, codec)
}

const char *sdp_audio_codec_to_str(const struct sdp_audio_codec *codec)
{
	return sdp_audio_codec_to_str_c(OTC_SELECT, codec);
}

/* Short single-line representation of a list of SDP audio codecs, convenient for logging */
int sdp_audio_codecs_to_str_buf(char *buf, size_t buflen, const struct sdp_audio_codecs *ac)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	const struct sdp_audio_codec *codec;
	if (!ac->count)
		OSMO_STRBUF_PRINTF(sb, "(no-codecs)");
	foreach_sdp_audio_codec(codec, ac) {
		bool first = (codec == ac->codec);
		if (!first)
			OSMO_STRBUF_PRINTF(sb, ",");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codec_to_str_buf, codec);
	}
	return sb.chars_needed;
}

char *sdp_audio_codecs_to_str_c(void *ctx, const struct sdp_audio_codecs *ac)
{
	OSMO_NAME_C_IMPL(ctx, 128, "sdp_audio_codecs_to_str_c-ERROR", sdp_audio_codecs_to_str_buf, ac)
}

const char *sdp_audio_codecs_to_str(const struct sdp_audio_codecs *ac)
{
	return sdp_audio_codecs_to_str_c(OTC_SELECT, ac);
}

/* Short single-line representation of an SDP message, convenient for logging */
int sdp_msg_to_str_buf(char *buf, size_t buflen, const struct sdp_msg *sdp)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (!sdp) {
		OSMO_STRBUF_PRINTF(sb, "NULL");
		return sb.chars_needed;
	}

	OSMO_STRBUF_PRINTF(sb, OSMO_SOCKADDR_STR_FMT, OSMO_SOCKADDR_STR_FMT_ARGS(&sdp->rtp));
	OSMO_STRBUF_PRINTF(sb, "{");
	OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_to_str_buf, &sdp->audio_codecs);
	if (sdp->bearer_services.count) {
		OSMO_STRBUF_PRINTF(sb, ",");
		OSMO_STRBUF_APPEND(sb, csd_bs_list_to_str_buf, &sdp->bearer_services);
	}
	OSMO_STRBUF_PRINTF(sb, "}");
	return sb.chars_needed;
}

char *sdp_msg_to_str_c(void *ctx, const struct sdp_msg *sdp)
{
	OSMO_NAME_C_IMPL(ctx, 128, "sdp_msg_to_str_c-ERROR", sdp_msg_to_str_buf, sdp)
}

const char *sdp_msg_to_str(const struct sdp_msg *sdp)
{
	return sdp_msg_to_str_c(OTC_SELECT, sdp);
}

void sdp_audio_codecs_set_csd(struct sdp_audio_codecs *ac)
{
	*ac = (struct sdp_audio_codecs){
		.count = 1,
		.codec = {{
			.payload_type = 120,
			.subtype_name = "CLEARMODE",
			.rate = 8000,
		}},
	};
}
