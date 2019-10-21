#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/msc/cc_sdp.h>
#include <osmocom/msc/codec_sdp_cc_t9n.h>
#include <osmocom/msc/debug.h>

/* Add all known payload types encountered in GSM networks */
static void sdp_add_all_mobile_codecs(struct sdp_audio_codecs *ac)
{
	/* In order of preference. TODO: make configurable */
	static const enum gsm48_bcap_speech_ver mobile_codecs[] = {
		GSM48_BCAP_SV_AMR_F	/*!< 4   GSM FR V3 (FR AMR) */,
		GSM48_BCAP_SV_AMR_H	/*!< 5   GSM HR V3 (HR_AMR) */,
		GSM48_BCAP_SV_EFR	/*!< 2   GSM FR V2 (GSM EFR) */,
		GSM48_BCAP_SV_FR	/*!< 0   GSM FR V1 (GSM FR) */,
		GSM48_BCAP_SV_HR	/*!< 1   GSM HR V1 (GSM HR) */,
	};
	int i;
	for (i = 0; i < ARRAY_SIZE(mobile_codecs); i++)
		sdp_audio_codecs_add_speech_ver(ac, mobile_codecs[i]);
}

/* Add all known AMR payload types encountered in UTRAN networks */
static void sdp_add_all_utran_codecs(struct sdp_audio_codecs *ac)
{
	/* In order of preference. TODO: make configurable */
	static const enum gsm48_bcap_speech_ver utran_codecs[] = {
		GSM48_BCAP_SV_AMR_F	/*!< 4   GSM FR V3 (FR AMR) */,
		GSM48_BCAP_SV_AMR_H	/*!< 5   GSM HR V3 (HR_AMR) */,
		GSM48_BCAP_SV_AMR_OH	/*!< 11  GSM HR V6 (OHR AMR) */,
		GSM48_BCAP_SV_AMR_FW	/*!< 8   GSM FR V5 (FR AMR-WB) */,
		GSM48_BCAP_SV_AMR_OFW	/*!< 6   GSM FR V4 (OFR AMR-WB) */,
		GSM48_BCAP_SV_AMR_OHW	/*!< 7   GSM HR V4 (OHR AMR-WB) */,
	};
	int i;
	for (i = 0; i < ARRAY_SIZE(utran_codecs); i++)
		sdp_audio_codecs_add_speech_ver(ac, utran_codecs[i]);
}

static void cc_sdp_set_ran(struct cc_sdp *cc_sdp, enum osmo_rat_type ran_type)
{
	cc_sdp->ran = (struct sdp_audio_codecs){};

	switch (ran_type) {
	default:
	case OSMO_RAT_GERAN_A:
		sdp_add_all_mobile_codecs(&cc_sdp->ran);
		break;

	case OSMO_RAT_UTRAN_IU:
		sdp_add_all_utran_codecs(&cc_sdp->ran);
		break;
	}
}

void cc_sdp_init(struct cc_sdp *cc_sdp,
		 enum osmo_rat_type ran_type,
		 const struct gsm_mncc_bearer_cap *ms_bearer_cap,
		 const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	*cc_sdp = (struct cc_sdp){};
	cc_sdp_set_ran(cc_sdp, ran_type);

	if (ms_bearer_cap)
		sdp_audio_codecs_from_bearer_cap(&cc_sdp->ms, ms_bearer_cap);

	if (codec_list_bss_supported)
		cc_sdp_set_cell(cc_sdp, codec_list_bss_supported);
}

void cc_sdp_set_cell(struct cc_sdp *cc_sdp,
		     const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	cc_sdp->cell = (struct sdp_audio_codecs){};
	if (codec_list_bss_supported)
		sdp_audio_codecs_from_speech_codec_list(&cc_sdp->cell, codec_list_bss_supported);
}

/* Render intersections of all known audio codec constraints to reach a resulting choice of favorite audio codec, plus
 * possible set of alternative audio codecs, in cc_sdp->result. (The result.rtp address remains unchanged.) */
int cc_sdp_filter(struct cc_sdp *cc_sdp)
{
	struct sdp_audio_codecs *r = &cc_sdp->result.audio_codecs;
	struct sdp_audio_codec *a = &cc_sdp->assignment;
	*r = cc_sdp->ran;
	if (cc_sdp->ms.count)
		sdp_audio_codecs_intersection(r, &cc_sdp->ms, false);
	if (cc_sdp->cell.count)
		sdp_audio_codecs_intersection(r, &cc_sdp->cell, false);
	if (cc_sdp->remote.audio_codecs.count)
		sdp_audio_codecs_intersection(r, &cc_sdp->remote.audio_codecs, true);

#if ALLOW_REASSIGNMENT
	/* If osmo-msc were able to trigger a re-assignment after the remote side has picked a codec mismatching the
	 * initial Assignment, then this code here would make sense: keep the other codecs as available to choose from,
	 * but put the currently assigned codec in the first position. */
	if (a->subtype_name[0]) {
		/* Assignment has completed, the chosen codec should be the first of the resulting SDP.
		 * Make sure this is actually listed in the result SDP and move to first place. */
		struct sdp_audio_codec *select = sdp_audio_codec_by_descr(r, a);

		if (!select) {
			/* Not present. Add. */
			if (sdp_audio_codec_by_payload_type(r, a->payload_type, false)) {
				/* Oh crunch, that payload type number is already in use.
				 * Find an unused one. */
				for (a->payload_type = 96; a->payload_type <= 127; a->payload_type++) {
					if (!sdp_audio_codec_by_payload_type(r, a->payload_type, false))
						break;
				}

				if (a->payload_type > 127)
					return -ENOSPC;
			}
			select = sdp_audio_codec_add_copy(r, a);
		}

		sdp_audio_codecs_select(r, select);
	}
#else
	/* Currently, osmo-msc does not trigger re-assignment if the remote side has picked a codec that the local side
	 * would also support, but the local side has already assigned a mismatching codec before. Mismatching codecs
	 * means call failure. So, currently, if locally, Assignment has already happened, it makes sense to send only
	 * the assigned codec as available choice to the remote side. */
	if (a->subtype_name[0]) {
		/* Assignment has completed, the chosen codec should be the the only possible one. */
		struct sdp_audio_codecs assigned_codec = {};
		sdp_audio_codec_add_copy(&assigned_codec, a);
		sdp_audio_codecs_intersection(r, &assigned_codec, false);
	}
#endif
	return 0;
}

int cc_sdp_name_buf(char *buf, size_t buflen, const struct cc_sdp *cc_sdp)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "RAN={");
	OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_name_buf, &cc_sdp->ran);
	OSMO_STRBUF_PRINTF(sb, "}");

	if (cc_sdp->cell.count) {
		OSMO_STRBUF_PRINTF(sb, " cell={");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_name_buf, &cc_sdp->cell);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	if (cc_sdp->ms.count) {
		OSMO_STRBUF_PRINTF(sb, " MS={");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_name_buf, &cc_sdp->ms);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	if (cc_sdp->remote.audio_codecs.count
	    || osmo_sockaddr_str_is_nonzero(&cc_sdp->remote.rtp)) {
		OSMO_STRBUF_PRINTF(sb, " remote=");
		OSMO_STRBUF_APPEND(sb, sdp_msg_name_buf, &cc_sdp->remote);
	}

	if (cc_sdp->assignment.subtype_name[0]) {
		OSMO_STRBUF_PRINTF(sb, " assigned=");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codec_name_buf, &cc_sdp->assignment);
	}

	OSMO_STRBUF_PRINTF(sb, " result=");
	OSMO_STRBUF_APPEND(sb, sdp_msg_name_buf, &cc_sdp->result);

	return sb.chars_needed;
}

char *cc_sdp_name_c(void *ctx, const struct cc_sdp *cc_sdp)
{
	OSMO_NAME_C_IMPL(ctx, 128, "cc_sdp_name_c-ERROR", cc_sdp_name_buf, cc_sdp)
}

const char *cc_sdp_name(const struct cc_sdp *cc_sdp)
{
	return cc_sdp_name_c(OTC_SELECT, cc_sdp);
}
