/* Routines for translation between codec representations: SDP, CC/BSSMAP variants, MGCP, MNCC */
/*
 * (C) 2019-2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: AGPL-3.0+
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

#include <osmocom/gsm/mncc.h>

#include <osmocom/msc/sdp_msg.h>
#include <osmocom/msc/codec_mapping.h>
#include <osmocom/msc/mncc.h>

const struct codec_mapping codec_map[] = {
	/* FIXME: sdp.fmtp handling is not done properly yet, proper mode-set and octet-align handling will follow in
	 * separate patches. */
	{
		.sdp = {
			.payload_type = 0,
			.subtype_name = "PCMU",
			.rate = 8000,
		},
		.mgcp = CODEC_PCMU_8000_1,
	},
	{
		.sdp = {
			.payload_type = 3,
			.subtype_name = "GSM",
			.rate = 8000,
		},
		.mgcp = CODEC_GSM_8000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_FR },
		.mncc_payload_msg_type = GSM_TCHF_FRAME,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_FR1,
		},
		.perm_speech = GSM0808_PERM_FR1,
		.frhr = CODEC_FRHR_FR,
	},
	{
		.sdp = {
			.payload_type = 8,
			.subtype_name = "PCMA",
			.rate = 8000,
		},
		.mgcp = CODEC_PCMA_8000_1,
	},
	{
		.sdp = {
			.payload_type = 18,
			.subtype_name = "G729",
			.rate = 8000,
		},
		.mgcp = CODEC_G729_8000_1,
	},
	{
		.sdp = {
			.payload_type = 110,
			.subtype_name = "GSM-EFR",
			.rate = 8000,
		},
		.mgcp = CODEC_GSMEFR_8000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_EFR },
		.mncc_payload_msg_type = GSM_TCHF_FRAME_EFR,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_FR2,
		},
		.perm_speech = GSM0808_PERM_FR2,
		.frhr = CODEC_FRHR_FR,
	},
	{
		.sdp = {
			.payload_type = 111,
			.subtype_name = "GSM-HR-08",
			.rate = 8000,
		},
		.mgcp = CODEC_GSMHR_8000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_HR },
		.mncc_payload_msg_type = GSM_TCHH_FRAME,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_HR1,
			.cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR,
		},
		.perm_speech = GSM0808_PERM_HR1,
		.frhr = CODEC_FRHR_HR,
	},
	{
		.sdp = {
			.payload_type = 112,
			.subtype_name = "AMR",
			.rate = 8000,
			/* AMR is always octet-aligned in 2G and 3G RAN, so this fmtp is signalled to remote call legs.
			 * So far, fmtp is ignored in incoming SIP SDP, so an incoming SDP without 'octet-align=1' will
			 * match with this entry; we will still reply with 'octet-align=1', which often works out. */
			.fmtp = "octet-align=1",
		},
		.mgcp = CODEC_AMR_8000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_AMR_F },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_FR3,
			.cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR,
		},
		.perm_speech = GSM0808_PERM_FR3,
		.frhr = CODEC_FRHR_FR,
	},
	{
		/* Another entry like the above, to map HR3 to AMR, too. */
		.sdp = {
			.payload_type = 112,
			.subtype_name = "AMR",
			.rate = 8000,
			.fmtp = "octet-align=1",
		},
		.mgcp = CODEC_AMR_8000_1,
		.speech_ver_count = 2,
		.speech_ver = { GSM48_BCAP_SV_AMR_H, GSM48_BCAP_SV_AMR_OH },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_HR3,
			.cfg = GSM0808_SC_CFG_DEFAULT_HR_AMR,
		},
		.perm_speech = GSM0808_PERM_HR3,
		.frhr = CODEC_FRHR_HR,
	},
	{
		.sdp = {
			.payload_type = 113,
			.subtype_name = "AMR-WB",
			.rate = 16000,
			.fmtp = "octet-align=1",
		},
		.mgcp = CODEC_AMRWB_16000_1,
		.speech_ver_count = 2,
		.speech_ver = { GSM48_BCAP_SV_AMR_OFW, GSM48_BCAP_SV_AMR_FW },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_FR5,
			.cfg = GSM0808_SC_CFG_DEFAULT_FR_AMR_WB,
		},
		.perm_speech = GSM0808_PERM_FR5,
		.frhr = CODEC_FRHR_FR,
	},
	{
		/* Another entry like the above, to map HR4 to AMR-WB, too. */
		.sdp = {
			.payload_type = 113,
			.subtype_name = "AMR-WB",
			.rate = 16000,
			.fmtp = "octet-align=1",
		},
		.mgcp = CODEC_AMRWB_16000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_AMR_OHW },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.fi = true,
			.type = GSM0808_SCT_HR4,
			.cfg = GSM0808_SC_CFG_DEFAULT_OHR_AMR_WB,
		},
		.perm_speech = GSM0808_PERM_HR4,
		.frhr = CODEC_FRHR_HR,
	},
	{
		.sdp = {
			.payload_type = 96,
			.subtype_name = "VND.3GPP.IUFP",
			.rate = 16000,
		},
		.mgcp = CODEC_IUFP,
	},
	{
		.sdp = {
			.payload_type = 120,
			.subtype_name = "CLEARMODE",
			.rate = 8000,
		},
		.has_gsm0808_speech_codec = true,
		.gsm0808_speech_codec = {
			.pi = true, /* PI indicates CSDoIP is supported */
			.pt = false, /* PT indicates CSDoTDM is not supported */
			.type = GSM0808_SCT_CSD,
			.cfg = 0, /* R2/R3 not set (redundancy not supported) */
		},
		.mgcp = CODEC_CLEARMODE,
	},
};

#define foreach_codec_mapping(CODEC_MAPPING) \
	for ((CODEC_MAPPING) = codec_map; (CODEC_MAPPING) < codec_map + ARRAY_SIZE(codec_map); (CODEC_MAPPING)++)

const struct gsm_mncc_bearer_cap bearer_cap_empty = {
		.speech_ver = { -1 },
	};

const struct codec_mapping *codec_mapping_by_speech_ver(enum gsm48_bcap_speech_ver speech_ver)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		int i;
		for (i = 0; i < m->speech_ver_count; i++)
			if (m->speech_ver[i] == speech_ver)
				return m;
	}
	return NULL;
}

const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec_type(enum gsm0808_speech_codec_type sct)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (!m->has_gsm0808_speech_codec)
			continue;
		if (m->gsm0808_speech_codec.type == sct)
			return m;
	}
	return NULL;
}

const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec(const struct gsm0808_speech_codec *sc)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (!m->has_gsm0808_speech_codec)
			continue;
		if (m->gsm0808_speech_codec.type != sc->type)
			continue;
		/* Return only those where sc->cfg is a subset of m->gsm0808_speech_codec.cfg. */
		if ((m->gsm0808_speech_codec.cfg & sc->cfg) != sc->cfg)
			continue;
		return m;
	}
	return NULL;
}

const struct codec_mapping *codec_mapping_by_perm_speech(enum gsm0808_permitted_speech perm_speech)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (m->perm_speech == perm_speech)
			return m;
	}
	return NULL;
}

const struct codec_mapping *codec_mapping_by_subtype_name(const char *subtype_name)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (!strcmp(m->sdp.subtype_name, subtype_name))
			return m;
	}
	return NULL;
}

const struct codec_mapping *codec_mapping_by_mgcp_codec(enum mgcp_codecs mgcp)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (m->mgcp == mgcp)
			return m;
	}
	return NULL;
}

/* Append given Speech Version to the end of the Bearer Capabilities Speech Version array. Return 1 if added, zero
 * otherwise (as in, return the number of items added). */
int bearer_cap_add_speech_ver(struct gsm_mncc_bearer_cap *bearer_cap, enum gsm48_bcap_speech_ver speech_ver)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(bearer_cap->speech_ver) - 1; i++) {
		if (bearer_cap->speech_ver[i] == speech_ver)
			return 0;
		if (bearer_cap->speech_ver[i] == -1) {
			bearer_cap->speech_ver[i] = speech_ver;
			bearer_cap->speech_ver[i+1] = -1;
			return 1;
		}
	}
	return 0;
}

/* From the current speech_ver list present in the bearer_cap, set the bearer_cap.radio.
 * If a HR speech_ver is present, set to GSM48_BCAP_RRQ_DUAL_FR, otherwise set to GSM48_BCAP_RRQ_FR_ONLY. */
int bearer_cap_set_radio(struct gsm_mncc_bearer_cap *bearer_cap)
{
	bool hr_present = false;
	int i;
	for (i = 0; i < ARRAY_SIZE(bearer_cap->speech_ver) - 1; i++) {
		const struct codec_mapping *m;

		if (bearer_cap->speech_ver[i] == -1)
			break;

		m = codec_mapping_by_speech_ver(bearer_cap->speech_ver[i]);

		if (!m)
			continue;

		if (m->frhr == CODEC_FRHR_HR)
			hr_present = true;
	}

	if (hr_present)
		bearer_cap->radio = GSM48_BCAP_RRQ_DUAL_FR;
	else
		bearer_cap->radio = GSM48_BCAP_RRQ_FR_ONLY;

	return 0;
}

/* Try to convert the SDP audio codec name to Speech Versions to append to Bearer Capabilities.
 * Return the number of Speech Version entries added (some may add more than one, others may be unknown/unapplicable and
 * return 0). */
int sdp_audio_codec_add_to_bearer_cap(struct gsm_mncc_bearer_cap *bearer_cap, const struct sdp_audio_codec *codec)
{
	const struct codec_mapping *m;
	int added = 0;
	foreach_codec_mapping(m) {
		int i;
		if (strcmp(m->sdp.subtype_name, codec->subtype_name))
			continue;
		/* TODO also match rate and fmtp? */
		for (i = 0; i < m->speech_ver_count; i++)
			added += bearer_cap_add_speech_ver(bearer_cap, m->speech_ver[i]);
	}
	return added;
}

/* Append all audio codecs found in given sdp_msg to Bearer Capability, by traversing all codec entries with
 * sdp_audio_codec_add_to_bearer_cap(). Return the number of Speech Version entries added.
 * Note that Speech Version entries are only appended, no previous entries are removed.
 * Note that only the Speech Version entries are modified; to make a valid Bearer Capabiliy, at least bearer_cap->radio
 * must also be set (before or after this function); see also bearer_cap_set_radio(). */
int sdp_audio_codecs_to_bearer_cap(struct gsm_mncc_bearer_cap *bearer_cap, const struct sdp_audio_codecs *ac)
{
	const struct sdp_audio_codec *codec;
	int added = 0;

	foreach_sdp_audio_codec(codec, ac) {
		added += sdp_audio_codec_add_to_bearer_cap(bearer_cap, codec);
	}

	return added;
}

/* Convert Speech Version to SDP audio codec and append to SDP message struct. */
struct sdp_audio_codec *sdp_audio_codecs_add_speech_ver(struct sdp_audio_codecs *ac,
							enum gsm48_bcap_speech_ver speech_ver)
{
	const struct codec_mapping *m;
	struct sdp_audio_codec *ret = NULL;
	foreach_codec_mapping(m) {
		int i;
		for (i = 0; i < m->speech_ver_count; i++) {
			if (m->speech_ver[i] == speech_ver) {
				ret = sdp_audio_codecs_add_copy(ac, &m->sdp);
				break;
			}
		}
	}
	return ret;
}

struct sdp_audio_codec *sdp_audio_codecs_add_mgcp_codec(struct sdp_audio_codecs *ac, enum mgcp_codecs mgcp_codec)
{
	const struct codec_mapping *m = codec_mapping_by_mgcp_codec(mgcp_codec);
	if (!m)
		return NULL;
	return sdp_audio_codecs_add_copy(ac, &m->sdp);
}

void sdp_audio_codecs_from_bearer_cap(struct sdp_audio_codecs *ac, const struct gsm_mncc_bearer_cap *bc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bc->speech_ver); i++) {
		if (bc->speech_ver[i] == -1)
			break;
		sdp_audio_codecs_add_speech_ver(ac, bc->speech_ver[i]);
	}
}

void sdp_audio_codecs_to_speech_codec_list(struct gsm0808_speech_codec_list *scl, const struct sdp_audio_codecs *ac)
{
	const struct sdp_audio_codec *codec;

	*scl = (struct gsm0808_speech_codec_list){};

	foreach_sdp_audio_codec(codec, ac) {
		const struct codec_mapping *m = codec_mapping_by_subtype_name(codec->subtype_name);
		if (!m)
			continue;
		if (!m->has_gsm0808_speech_codec)
			continue;
		if (scl->len >= ARRAY_SIZE(scl->codec))
			break;
		scl->codec[scl->len] = m->gsm0808_speech_codec;
		/* FIXME: apply AMR configuration according to codec->fmtp */
		scl->len++;
	}
}

void sdp_audio_codecs_from_speech_codec_list(struct sdp_audio_codecs *ac, const struct gsm0808_speech_codec_list *cl)
{
	int i;
	for (i = 0; i < cl->len; i++) {
		const struct gsm0808_speech_codec *sc = &cl->codec[i];
		const struct codec_mapping *m = codec_mapping_by_gsm0808_speech_codec(sc);
		if (!m)
			continue;
		sdp_audio_codecs_add_copy(ac, &m->sdp);
		/* FIXME: for AMR, apply sc->cfg to the added codec's fmtp */
	}
}

int sdp_audio_codecs_to_gsm0808_channel_type(struct gsm0808_channel_type *ct, const struct sdp_audio_codecs *ac)
{
	const struct sdp_audio_codec *codec;
	bool fr_present = false;
	int first_fr_idx = -1;
	bool hr_present = false;
	int first_hr_idx = -1;
	int idx = -1;

	*ct = (struct gsm0808_channel_type){
		.ch_indctr = GSM0808_CHAN_SPEECH,
	};

	foreach_sdp_audio_codec(codec, ac) {
		const struct codec_mapping *m;
		int i;
		bool dup;
		idx++;
		foreach_codec_mapping(m) {
			if (strcmp(m->sdp.subtype_name, codec->subtype_name))
				continue;

			switch (m->perm_speech) {
			default:
				continue;

			case GSM0808_PERM_FR1:
			case GSM0808_PERM_FR2:
			case GSM0808_PERM_FR3:
			case GSM0808_PERM_FR4:
			case GSM0808_PERM_FR5:
				fr_present = true;
				if (first_fr_idx < 0)
					first_fr_idx = idx;
				break;

			case GSM0808_PERM_HR1:
			case GSM0808_PERM_HR2:
			case GSM0808_PERM_HR3:
			case GSM0808_PERM_HR4:
			case GSM0808_PERM_HR6:
				hr_present = true;
				if (first_hr_idx < 0)
					first_hr_idx = idx;
				break;
			}

			/* Avoid duplicates */
			dup = false;
			for (i = 0; i < ct->perm_spch_len; i++) {
				if (ct->perm_spch[i] == m->perm_speech) {
					dup = true;
					break;
				}
			}
			if (dup)
				continue;

			ct->perm_spch[ct->perm_spch_len] = m->perm_speech;
			ct->perm_spch_len++;
		}
	}

	if (fr_present && hr_present) {
		if (first_fr_idx <= first_hr_idx)
			ct->ch_rate_type = GSM0808_SPEECH_FULL_PREF;
		else
			ct->ch_rate_type = GSM0808_SPEECH_HALF_PREF;
	} else if (fr_present && !hr_present)
		ct->ch_rate_type = GSM0808_SPEECH_FULL_BM;
	else if (!fr_present && hr_present)
		ct->ch_rate_type = GSM0808_SPEECH_HALF_LM;
	else
		return -EINVAL;
	return 0;
}

enum mgcp_codecs sdp_audio_codec_to_mgcp_codec(const struct sdp_audio_codec *codec)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (!sdp_audio_codec_cmp(&m->sdp, codec, false, false))
			return m->mgcp;
	}
	return NO_MGCP_CODEC;
}
