#include <string.h>

#include <osmocom/gsm/mncc.h>

#include <osmocom/msc/sdp_msg.h>
#include <osmocom/msc/codec_sdp_cc_t9n.h>
#include <osmocom/msc/mncc.h>

const struct codec_mapping codec_map[] = {
	/* FIXME: I'm not sure about OFR, OHR -- O means octet-aligned?? */
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
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_FR1,
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
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_FR2,
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
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_HR1,
		.perm_speech = GSM0808_PERM_HR1,
		.frhr = CODEC_FRHR_HR,
	},
	{
		.sdp = {
			.payload_type = 112,
			.subtype_name = "AMR",
			.rate = 8000,
			/* It is important to send this fmtp parameter to a SIP peer in SDP,
			 * otherwise the voice audio is broken noise.
			 * However, a SIP peer may offer AMR without this parameter set in its SDP, so fmtp must be
			 * ignored during codec matching: otherwise an incoming AMR codec without this parameter fails
			 * to match this entry, and it ends in an aborted call due to no codec match.
			 * If the peer offers plain "AMR/8000" and we reply with "AMR/8000 fmtp:octet-align=1",
			 * then everything works out happily, */
			.fmtp = "octet-align=1",
		},
		.mgcp = CODEC_AMR_8000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_AMR_F },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_FR3,
		.perm_speech = GSM0808_PERM_FR3,
		.frhr = CODEC_FRHR_FR,
	},
	{
		.sdp = {
			.payload_type = 112,
			.subtype_name = "AMR",
			.rate = 8000,
			.fmtp = "octet-align=1;mode-set=0,1,2,3",
		},
		.mgcp = CODEC_AMR_8000_1,
		.speech_ver_count = 2,
		.speech_ver = { GSM48_BCAP_SV_AMR_H, GSM48_BCAP_SV_AMR_OH },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_HR3,
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
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_FR5,
		.perm_speech = GSM0808_PERM_FR5,
		.frhr = CODEC_FRHR_FR,
	},
	{
		.sdp = {
			.payload_type = 113,
			.subtype_name = "AMR-WB",
			.rate = 16000,
			.fmtp = "octet-align=1;mode-set=0,1,2,3", /* TODO: does this make sense?? */
		},
		.mgcp = CODEC_AMRWB_16000_1,
		.speech_ver_count = 1,
		.speech_ver = { GSM48_BCAP_SV_AMR_OHW },
		.mncc_payload_msg_type = GSM_TCH_FRAME_AMR,
		.has_gsm0808_speech_codec_type = true,
		.gsm0808_speech_codec_type = GSM0808_SCT_HR4,
		.perm_speech = GSM0808_PERM_HR4,
		.frhr = CODEC_FRHR_HR,
	},
};

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


const struct codec_mapping *codec_mapping_by_gsm0808_speech_codec_type(enum gsm0808_speech_codec_type sct, uint16_t cfg)
{
	const struct codec_mapping *m;
	foreach_codec_mapping(m) {
		if (!m->has_gsm0808_speech_codec_type)
			continue;
		if (m->gsm0808_speech_codec_type == sct)
			return m;
		/* TODO: evaluate cfg bits? */
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
	bool hr_present;
	int i;
	for (i = 0; i < ARRAY_SIZE(bearer_cap->speech_ver) - 1; i++) {
		const struct codec_mapping *m = codec_mapping_by_speech_ver(bearer_cap->speech_ver[i]);

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
		for (i = 0; i < m->speech_ver_count; i++) {
			added += bearer_cap_add_speech_ver(bearer_cap, m->speech_ver[i]);
		}
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
				ret = sdp_audio_codec_add_copy(ac, &m->sdp);
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
	return sdp_audio_codec_add_copy(ac, &m->sdp);
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

void sdp_audio_codecs_from_speech_codec_list(struct sdp_audio_codecs *ac, const struct gsm0808_speech_codec_list *cl)
{
	int i;
	for (i = 0; i < cl->len; i++) {
		const struct gsm0808_speech_codec *sc = &cl->codec[i];
		const struct codec_mapping *m = codec_mapping_by_gsm0808_speech_codec_type(sc->type, sc->cfg);
		if (!m)
			continue;
		sdp_audio_codec_add_copy(ac, &m->sdp);
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
