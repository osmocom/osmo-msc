/* BSSAP/BSSMAP encoding and decoding for MSC */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <osmocom/core/byteswap.h>

#include <osmocom/crypt/auth.h>
#include <osmocom/crypt/kdf.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/ran_msg_a.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/gsm_data.h>

#define LOG_RAN_A_DEC(RAN_DEC, level, fmt, args...) \
	LOG_RAN_DEC(RAN_DEC, DBSSAP, level, "BSSMAP: " fmt, ## args)

/* Assumes presence of struct ran_dec *ran_dec and ran_dec_msg.msg_name (set) in the local scope. */
#define LOG_RAN_A_DEC_MSG(level, fmt, args...) \
	LOG_RAN_DEC(ran_dec, DBSSAP, level, "%s: " fmt, ran_dec_msg.msg_name, ## args)

#define LOG_RAN_A_ENC(FI, level, fmt, args...) \
	LOG_RAN_ENC(FI, DBSSAP, level, "BSSMAP: " fmt, ## args)

static int ran_a_decode_l3_compl(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gsm0808_cell_id_list2 cil;
	struct gsm0808_cell_id cell_id;
	struct tlv_p_entry *ie_cell_id = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER);
	struct tlv_p_entry *ie_l3_info = TLVP_GET(tp, GSM0808_IE_LAYER_3_INFORMATION);
	struct tlv_p_entry *ie_codec_list_bss_supported = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST);
	struct gsm0808_speech_codec_list codec_list_bss_supported;
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_COMPL_L3,
		.msg_name = "BSSMAP Complete Layer 3 Information",
		.compl_l3 = {
			.cell_id = &cell_id,
			.msg = msg,
		},
	};
	int rc;

	if (!ie_cell_id) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory CELL IDENTIFIER not present, discarding message\n");
		return -EINVAL;
	}
	if (!ie_l3_info) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory LAYER 3 INFORMATION not present, discarding message\n");
		return -EINVAL;
	}

	/* Parse Cell ID element -- this should yield a cell identifier "list" with 1 element. */

	rc = gsm0808_dec_cell_id_list2(&cil, ie_cell_id->val, ie_cell_id->len);
	if (rc < 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding CELL IDENTIFIER gave rc=%d\n", rc);
		return -EINVAL;
	}
	if (cil.id_list_len != 1) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Unable to parse element CELL IDENTIFIER, discarding message\n");
		return -EINVAL;
	}

	/* Sanity check the Cell Identity */
	switch (cil.id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL:
	case CELL_IDENT_LAI_AND_LAC:
	case CELL_IDENT_LAC_AND_CI:
	case CELL_IDENT_LAC:
		break;

	case CELL_IDENT_CI:
	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
	default:
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "CELL IDENTIFIER does not specify a LAC, discarding message: %s\n",
				 gsm0808_cell_id_list_name(&cil));
		return -EINVAL;
	}

	cell_id = (struct gsm0808_cell_id){
		.id_discr = cil.id_discr,
		.id = cil.id_list[0],
	};

	/* Parse Layer 3 Information element; point ran_dec_msg->compl_l3.msg to the L3 Info data */
	msg->l3h = (uint8_t*)ie_l3_info->val;
	msgb_l3trim(msg, ie_l3_info->len);

	if (msgb_l3len(msg) < sizeof(struct gsm48_hdr)) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "too short L3 info (%d), discarding message\n", msgb_l3len(msg));
		return -ENODATA;
	}

	/* Decode Codec List (BSS Supported) */
	if (ie_codec_list_bss_supported) {
		rc = gsm0808_dec_speech_codec_list(&codec_list_bss_supported,
						   ie_codec_list_bss_supported->val, ie_codec_list_bss_supported->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR,
					  "Complete Layer 3 Information: unable to decode IE Codec List (BSS Supported)"
					  " (rc=%d), continuing anyway\n", rc);
			/* This IE is not critical, do not abort with error. */
		} else
			ran_dec_msg.compl_l3.codec_list_bss_supported = &codec_list_bss_supported;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_clear_request(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_CLEAR_REQUEST,
		.msg_name = "BSSMAP Clear Request",
	};

	if (!ie_cause) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Cause code is missing, using GSM0808_CAUSE_EQUIPMENT_FAILURE\n");
		ran_dec_msg.clear_request.bssap_cause = GSM0808_CAUSE_EQUIPMENT_FAILURE;
	} else {
		ran_dec_msg.clear_request.bssap_cause = ie_cause->val[0];
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_clear_complete(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_CLEAR_COMPLETE,
		.msg_name = "BSSMAP Clear Complete",
	};
	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_classmark_update(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_cm2 = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);
	struct tlv_p_entry *ie_cm3 = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
	struct osmo_gsm48_classmark cm = {};
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_CLASSMARK_UPDATE,
		.msg_name = "BSSMAP Classmark Update",
		.classmark_update = {
			.classmark = &cm,
		},
	};

	if (!ie_cm2) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "mandatory Classmark Information Type 2 not present, discarding message\n");
		return -EINVAL;
	}

	cm.classmark2_len = OSMO_MIN(sizeof(cm.classmark2), ie_cm2->len);
	memcpy(&cm.classmark2, ie_cm2->val, cm.classmark2_len);

	if (ie_cm3) {
		cm.classmark3_len = OSMO_MIN(sizeof(cm.classmark3), ie_cm3->len);
		memcpy(&cm.classmark3, ie_cm3->val, cm.classmark3_len);
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_cipher_mode_complete(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_chosen_encr_alg = TLVP_GET(tp, GSM0808_IE_CHOSEN_ENCR_ALG);
	struct tlv_p_entry *ie_l3_msg = TLVP_GET(tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
	int rc;
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_CIPHER_MODE_COMPLETE,
		.msg_name = "BSSMAP Ciphering Mode Complete",
	};

	if (ie_chosen_encr_alg) {
		uint8_t ie_val = ie_chosen_encr_alg->val[0];
		/* 3GPP TS 48.008 3.2.2.44 Chosen Encryption Algorithm encodes as 1 = no encryption, 2 = A5/1, 4 = A5/3.
		 * Internally we handle without this weird off-by-one. */
		if (ie_val < 1 || ie_val > 8)
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Unsupported value for 3.2.2.44 Chosen Encryption Algorithm: %u\n",
					 ie_val);
		else
			ran_dec_msg.cipher_mode_complete.alg_id = ie_chosen_encr_alg->val[0];
	}

	if (ie_l3_msg)
		ran_dec_msg.cipher_mode_complete.l3_msg = ie_l3_msg;

	rc = ran_decoded(ran_dec, &ran_dec_msg);

	return rc;
}

static int ran_a_decode_cipher_mode_reject(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	int rc;
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_CIPHER_MODE_REJECT,
		.msg_name = "BSSMAP Ciphering Mode Reject",
	};

	rc = gsm0808_get_cause(tp);
	if (rc < 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "failed to extract Cause\n");
		ran_dec_msg.cipher_mode_reject.bssap_cause = GSM0808_CAUSE_EQUIPMENT_FAILURE;
	} else {
		ran_dec_msg.cipher_mode_reject.bssap_cause = (enum gsm0808_cause)rc;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

enum mgcp_codecs ran_a_mgcp_codec_from_sc(const struct gsm0808_speech_codec *sc)
{
	switch (sc->type) {
	case GSM0808_SCT_FR1:
		return CODEC_GSM_8000_1;
	case GSM0808_SCT_FR2:
		return CODEC_GSMEFR_8000_1;
	case GSM0808_SCT_FR3:
		return CODEC_AMR_8000_1;
	case GSM0808_SCT_FR4:
		return CODEC_AMRWB_16000_1;
	case GSM0808_SCT_FR5:
		return CODEC_AMRWB_16000_1;
	case GSM0808_SCT_HR1:
		return CODEC_GSMHR_8000_1;
	case GSM0808_SCT_HR3:
		return CODEC_AMR_8000_1;
	case GSM0808_SCT_HR4:
		return CODEC_AMRWB_16000_1;
	case GSM0808_SCT_HR6:
		return CODEC_AMRWB_16000_1;
	case GSM0808_SCT_CSD:
		return CODEC_CLEARMODE;
	default:
		return CODEC_PCMU_8000_1;
	}
}

static int ran_a_decode_assignment_complete(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_aoip_transp_addr = TLVP_GET(tp, GSM0808_IE_AOIP_TRASP_ADDR);
	struct tlv_p_entry *ie_speech_codec = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC);
	struct tlv_p_entry *ie_codec_list_bss_supported = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST);
	struct tlv_p_entry *ie_osmux_cid = TLVP_GET(tp, GSM0808_IE_OSMO_OSMUX_CID);
	struct sockaddr_storage rtp_addr;
	struct gsm0808_speech_codec_list codec_list_bss_supported;
	int rc;
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_ASSIGNMENT_COMPLETE,
		.msg_name = "BSSMAP Assignment Complete",
	};

	if (ie_aoip_transp_addr) {
		/* Decode AoIP transport address element */
		rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr, ie_aoip_transp_addr->val, ie_aoip_transp_addr->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Unable to decode AoIP Transport Layer Address\n");
			return -EINVAL;
		}

		if (osmo_sockaddr_str_from_sockaddr(&ran_dec_msg.assignment_complete.remote_rtp, &rtp_addr)) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Assignment Complete: unable to decode remote RTP IP address\n");
			return -EINVAL;
		}
	}

	if (ie_osmux_cid) {
		rc = gsm0808_dec_osmux_cid(&ran_dec_msg.assignment_complete.osmux_cid, ie_osmux_cid->val, ie_osmux_cid->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Unable to decode Osmux CID\n");
			return -EINVAL;
		}
		ran_dec_msg.assignment_complete.osmux_present = true;
	}

	if (ie_speech_codec) {
		/* Decode Speech Codec (Chosen) element */
		rc = gsm0808_dec_speech_codec(&ran_dec_msg.assignment_complete.codec,
					      ie_speech_codec->val, ie_speech_codec->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Assignment Complete: unable to decode IE Speech Codec (Chosen)"
					  " (rc=%d).\n", rc);
			return -EINVAL;
		}
		ran_dec_msg.assignment_complete.codec_present = true;
	}

	if (ie_codec_list_bss_supported) {
		/* Decode Codec List (BSS Supported) */
		rc = gsm0808_dec_speech_codec_list(&codec_list_bss_supported,
						   ie_codec_list_bss_supported->val, ie_codec_list_bss_supported->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR,
					  "Assignment Complete: unable to decode IE Codec List (BSS Supported)"
					  " (rc=%d), continuing anyway\n", rc);
			/* This IE is not critical, do not abort with error. */
		} else
			ran_dec_msg.assignment_complete.codec_list_bss_supported = &codec_list_bss_supported;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_assignment_failure(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	struct tlv_p_entry *ie_rr_cause = TLVP_GET(tp, GSM0808_IE_RR_CAUSE);
	struct tlv_p_entry *ie_speech_codec_list = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST);
	struct gsm0808_speech_codec_list scl;
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_ASSIGNMENT_FAILURE,
		.msg_name = "BSSMAP Assignment Failure",
		.assignment_failure = {
			.bssap_cause = GSM0808_CAUSE_EQUIPMENT_FAILURE,
			.rr_cause = GSM48_RR_CAUSE_ABNORMAL_UNSPEC,
		},
	};

	if (ie_cause)
		ran_dec_msg.assignment_failure.bssap_cause = ie_cause->val[0];
	if (ie_rr_cause)
		ran_dec_msg.assignment_failure.rr_cause = ie_rr_cause->val[0];

	if (ie_speech_codec_list
	    && gsm0808_dec_speech_codec_list(&scl, ie_speech_codec_list->val, ie_speech_codec_list->len) == 0)
		ran_dec_msg.assignment_failure.scl_bss_supported = &scl;

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_sapi_n_reject(struct ran_dec *ran_dec, struct msgb *msg, struct tlv_parsed *tp)
{
	struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	struct tlv_p_entry *ie_dlci = TLVP_GET(tp, GSM0808_IE_DLCI);
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_SAPI_N_REJECT,
		.msg_name = "BSSMAP SAPI-N Reject",
	};

	/* Note: The MSC code seems not to care about the cause code, but by
	 * the specification it is mandatory, so we check its presence. See
	 * also 3GPP TS 48.008 3.2.1.34 SAPI "n" REJECT */
	if (!ie_cause) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "SAPI-N Reject: cause code IE is missing, discarding message\n");
		return -EINVAL;
	}
	ran_dec_msg.sapi_n_reject.bssap_cause = ie_cause->val[0];

	if (!ie_dlci) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "SAPI-N Reject: DLCI IE is missing, discarding message\n");
		return -EINVAL;
	}
	ran_dec_msg.sapi_n_reject.dlci = ie_dlci->val[0];

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_lcls_notification(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *ie_lcls_bss_status = TLVP_GET(tp, GSM0808_IE_LCLS_BSS_STATUS);
	const struct tlv_p_entry *ie_lcls_break_req = TLVP_GET(tp, GSM0808_IE_LCLS_BREAK_REQ);
	struct ran_msg ran_dec_msg;

	/* Either §3.2.2.119 LCLS-BSS-Status or §3.2.2.120 LCLS-Break-Request shall be present */
	if (ie_lcls_bss_status && !ie_lcls_break_req) {
		ran_dec_msg = (struct ran_msg){
			.msg_type = RAN_MSG_LCLS_STATUS,
			.msg_name = "BSSMAP LCLS Notification (LCLS Status)",
			.lcls_status = {
				.status = ie_lcls_bss_status->len ?
					ie_lcls_bss_status->val[0] : GSM0808_LCLS_STS_NA,
			},
		};
		return ran_decoded(ran_dec, &ran_dec_msg);
	} else if (ie_lcls_break_req && !ie_lcls_bss_status) {
		ran_dec_msg = (struct ran_msg){
			.msg_type = RAN_MSG_LCLS_BREAK_REQ,
			.msg_name = "BSSMAP LCLS Notification (LCLS Break Req)",
			.lcls_break_req = {
				.todo = 23,
			},
		};
		return ran_decoded(ran_dec, &ran_dec_msg);
	}

	LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "Ignoring broken LCLS Notification message\n");
	return -EINVAL;
}

static int ran_a_decode_handover_required(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	const struct tlv_p_entry *ie_cil = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_REQUIRED,
		.msg_name = "BSSMAP Handover Required",
	};
	/* On decoding failures, dispatch an invalid RAN_MSG_HANDOVER_REQUIRED so msc_a can pass down a
	 * BSS_MAP_MSG_HANDOVER_REQUIRED_REJECT	message. */

	if (ie_cause)
		ran_dec_msg.handover_required.cause = ie_cause->val[0];
	else
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Cause IE missing\n");

	if (!ie_cil
	    || gsm0808_dec_cell_id_list2(&ran_dec_msg.handover_required.cil, ie_cil->val, ie_cil->len) <= 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "No or invalid Cell Identifier List IE\n");
		ran_dec_msg.handover_required.cil = (struct gsm0808_cell_id_list2){};
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static uint8_t a5_encryption_mask_from_gsm0808_chosen_enc_alg(enum gsm0808_chosen_enc_alg val)
{
	return 1 << val;
}

static int ran_a_decode_handover_request(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct osmo_gsm48_classmark classmark = {};
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_REQUEST,
		.msg_name = "BSSMAP Handover Request",
		.handover_request = {
			.classmark = &classmark,
		},
	};
	struct ran_handover_request *r = &ran_dec_msg.handover_request;

	const struct tlv_p_entry *ie_channel_type = TLVP_GET(tp, GSM0808_IE_CHANNEL_TYPE);
	const struct tlv_p_entry *ie_encryption_information = TLVP_GET(tp, GSM0808_IE_ENCRYPTION_INFORMATION);
	const struct tlv_p_entry *ie_classmark1 = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_TYPE_1);
	const struct tlv_p_entry *ie_classmark2 = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);
	const struct tlv_p_entry *ie_cell_id_serving = TLVP_GET(&tp[0], GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_cell_id_target = TLVP_GET(&tp[1], GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	const struct tlv_p_entry *ie_classmark3 = TLVP_GET(tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
	const struct tlv_p_entry *ie_current_channel_type_1 = TLVP_GET(tp, GSM0808_IE_CURRENT_CHANNEL_TYPE_1);
	const struct tlv_p_entry *ie_speech_version_used = TLVP_GET(tp, GSM0808_IE_SPEECH_VERSION);
	const struct tlv_p_entry *ie_chosen_encr_alg_serving = TLVP_GET(tp, GSM0808_IE_CHOSEN_ENCR_ALG);
	const struct tlv_p_entry *ie_old_bss_to_new_bss_info = TLVP_GET(tp, GSM0808_IE_OLD_BSS_TO_NEW_BSS_INFORMATION);
	const struct tlv_p_entry *ie_imsi = TLVP_GET(tp, GSM0808_IE_IMSI);
	const struct tlv_p_entry *ie_aoip_transp_addr = TLVP_GET(tp, GSM0808_IE_AOIP_TRASP_ADDR);
	const struct tlv_p_entry *ie_codec_list_msc_preferred = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST);
	const struct tlv_p_entry *ie_call_id = TLVP_GET(tp, GSM0808_IE_CALL_ID);
	const struct tlv_p_entry *ie_kc128 = TLVP_GET(tp, GSM0808_IE_KC_128);
	const struct tlv_p_entry *ie_global_call_ref = TLVP_GET(tp, GSM0808_IE_GLOBAL_CALL_REF);

	struct gsm0808_channel_type channel_type;
	struct gsm0808_encrypt_info encr_info;
	struct gsm0808_speech_codec_list scl;
	struct geran_encr geran_encr = {};
	struct osmo_sockaddr_str rtp_ran_local;

	if (!ie_channel_type) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Channel Type\n");
		return -EINVAL;
	}
	if (gsm0808_dec_channel_type(&channel_type, ie_channel_type->val, ie_channel_type->len) <= 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Channel Type IE\n");
		return -EINVAL;
	}
	r->geran.channel_type = &channel_type;

	if (ie_encryption_information) {
		int i;
		if (gsm0808_dec_encrypt_info(&encr_info, ie_encryption_information->val, ie_encryption_information->len)
		    <= 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Encryption Information IE\n");
			return -EINVAL;
		}

		for (i = 0; i < encr_info.perm_algo_len; i++) {
			r->geran.a5_encryption_mask |=
				a5_encryption_mask_from_gsm0808_chosen_enc_alg(encr_info.perm_algo[i]);
		}

		if (encr_info.key_len > sizeof(geran_encr.key)) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Encryption Information IE:"
					  " encryption key is too long: %u\n", geran_encr.key_len);
			return -EINVAL;
		}

		if (encr_info.key_len) {
			memcpy(geran_encr.key, encr_info.key, encr_info.key_len);
			geran_encr.key_len = encr_info.key_len;
		}

		if (ie_kc128) {
			memcpy(geran_encr.kc128, ie_kc128->val, 16);
			geran_encr.kc128_present = true;
		}

		r->geran.chosen_encryption = &geran_encr;
	}

	if (!ie_classmark1 && !ie_classmark2) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: either Classmark Information 1"
				  " or Classmark Information 2 must be included\n");
		return -EINVAL;
	}

	if (ie_classmark1) {
		if (ie_classmark1->len != sizeof(classmark.classmark1)) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Invalid size for Classmark 1: %u, expected %zu\n",
					  ie_classmark1->len, sizeof(classmark.classmark1));
			return -EINVAL;
		}
		memcpy((uint8_t*)&classmark.classmark1, ie_classmark1->val, ie_classmark1->len);
		classmark.classmark1_set = true;
	}

	if (ie_classmark2) {
		uint8_t len = OSMO_MIN(ie_classmark2->len, sizeof(classmark.classmark2));
		memcpy((uint8_t*)&classmark.classmark2, ie_classmark2->val, len);
		classmark.classmark2_len = len;
	}

	if (!ie_cell_id_serving) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cell Identifier (Serving)\n");
		return -EINVAL;
	}
	if (gsm0808_dec_cell_id(&r->cell_id_serving, ie_cell_id_serving->val,
				ie_cell_id_serving->len) <= 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Cell Identifier (Serving) IE\n");
		return -EINVAL;
	}

	if (!ie_cell_id_target) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cell Identifier (Target)\n");
		return -EINVAL;
	}
	if (gsm0808_dec_cell_id(&r->cell_id_target, ie_cell_id_target->val,
				ie_cell_id_target->len) <= 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Cell Identifier (Target) IE\n");
		return -EINVAL;
	}

	if (ie_cause)
		r->bssap_cause = ie_cause->val[0];

	if (ie_classmark3) {
		uint8_t len = OSMO_MIN(ie_classmark3->len, sizeof(classmark.classmark3));
		memcpy(classmark.classmark3, ie_classmark3->val, len);
		classmark.classmark3_len = len;
	}

	if (ie_current_channel_type_1) {
		r->current_channel_type_1 = ie_current_channel_type_1->val[0];
		r->current_channel_type_1_present = true;
	}

	if (ie_speech_version_used) {
		r->speech_version_used = ie_speech_version_used->val[0];
	}

	if (ie_chosen_encr_alg_serving && ie_chosen_encr_alg_serving->len) {
		geran_encr.alg_id = ie_chosen_encr_alg_serving->val[0];
		r->geran.chosen_encryption = &geran_encr;
	}

	if (ie_old_bss_to_new_bss_info) {
		r->old_bss_to_new_bss_info_raw = ie_old_bss_to_new_bss_info->val;
		r->old_bss_to_new_bss_info_raw_len = ie_old_bss_to_new_bss_info->len;
	}

	if (ie_imsi) {
		struct osmo_mobile_identity mi;
		if (osmo_mobile_identity_decode(&mi, ie_imsi->val, ie_imsi->len, false)
		    || mi.type != GSM_MI_TYPE_IMSI)
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "IE IMSI: cannot decode IMSI identity\n");
		else
			r->imsi = mi.imsi;
	}

	if (ie_aoip_transp_addr) {
		struct sockaddr_storage rtp_addr;
		if (gsm0808_dec_aoip_trasp_addr(&rtp_addr, ie_aoip_transp_addr->val, ie_aoip_transp_addr->len) < 0)
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode AoIP transport address\n");
		else if (osmo_sockaddr_str_from_sockaddr(&rtp_ran_local, &rtp_addr) < 0)
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode remote RTP IP address\n");
		else
			r->rtp_ran_local = &rtp_ran_local;
	}

	if (ie_codec_list_msc_preferred
	    && gsm0808_dec_speech_codec_list(&scl, ie_codec_list_msc_preferred->val,
					     ie_codec_list_msc_preferred->len) == 0)
		r->codec_list_msc_preferred = &scl;

	if (ie_call_id && ie_call_id->len == 4) {
		r->call_id = osmo_load32le(ie_call_id->val);
		r->call_id_present = true;
	}

	if (ie_global_call_ref) {
		r->global_call_reference = ie_global_call_ref->val;
		r->global_call_reference_len = ie_global_call_ref->len;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_handover_request_ack(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_REQUEST_ACK,
		.msg_name = "BSSMAP Handover Request Acknowledge",
	};
	const struct tlv_p_entry *ie_l3_info = TLVP_GET(tp, GSM0808_IE_LAYER_3_INFORMATION);
	const struct tlv_p_entry *ie_aoip_transp_addr = TLVP_GET(tp, GSM0808_IE_AOIP_TRASP_ADDR);
	const struct tlv_p_entry *ie_speech_codec = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC);
	const struct tlv_p_entry *ie_chosen_channel = TLVP_GET(tp, GSM0808_IE_CHOSEN_CHANNEL);
	const struct tlv_p_entry *ie_chosen_encr_alg = TLVP_GET(tp, GSM0808_IE_CHOSEN_ENCR_ALG);
	const struct tlv_p_entry *ie_chosen_speech_version = TLVP_GET(tp, GSM0808_IE_SPEECH_VERSION);

	/* On missing mandatory IEs, dispatch an invalid RAN_MSG_HANDOVER_REQUEST_ACK so msc_a can act on the failure. */

	if (ie_l3_info) {
		ran_dec_msg.handover_request_ack.rr_ho_command = ie_l3_info->val;
		ran_dec_msg.handover_request_ack.rr_ho_command_len = ie_l3_info->len;
	}

	if (ie_chosen_channel) {
		ran_dec_msg.handover_request_ack.chosen_channel_present = true;
		ran_dec_msg.handover_request_ack.chosen_channel = *ie_chosen_channel->val;
	}

	if (ie_chosen_encr_alg) {
		ran_dec_msg.handover_request_ack.chosen_encr_alg = *ie_chosen_encr_alg->val;
		if (ran_dec_msg.handover_request_ack.chosen_encr_alg < 1
		    || ran_dec_msg.handover_request_ack.chosen_encr_alg > 8) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "invalid Chosen Encryption Algorithm: %u\n",
					 ran_dec_msg.handover_request_ack.chosen_encr_alg);
		}
	}

	if (ie_chosen_speech_version) {
		ran_dec_msg.handover_request_ack.chosen_speech_version = ie_chosen_speech_version->val[0];

		/* the codec may be extrapolated from this Speech Version or below from Speech Codec */
		if (gsm0808_speech_codec_from_chan_type(&ran_dec_msg.handover_request_ack.codec,
							ran_dec_msg.handover_request_ack.chosen_speech_version) == 0)
			ran_dec_msg.handover_request_ack.codec_present = true;
	}

	if (ie_aoip_transp_addr) {
		struct sockaddr_storage rtp_addr;
		if (gsm0808_dec_aoip_trasp_addr(&rtp_addr, ie_aoip_transp_addr->val, ie_aoip_transp_addr->len) < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode AoIP transport address\n");
		} else if (osmo_sockaddr_str_from_sockaddr(&ran_dec_msg.handover_request_ack.remote_rtp,
							   &rtp_addr)) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode remote RTP IP address\n");
			ran_dec_msg.handover_request_ack.remote_rtp = (struct osmo_sockaddr_str){};
		}
	}

	if (ie_speech_codec) {
		/* the codec may be extrapolated from above Speech Version or from this Speech Codec */
		if (gsm0808_dec_speech_codec(&ran_dec_msg.handover_request_ack.codec,
					     ie_speech_codec->val, ie_speech_codec->len) < 0)
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode IE Speech Codec (Chosen)\n");
		else
			ran_dec_msg.handover_request_ack.codec_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_handover_detect(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_DETECT,
		.msg_name = "BSSMAP Handover Detect",
	};

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_handover_succeeded(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_SUCCEEDED,
		.msg_name = "BSSMAP Handover Succeeded",
	};

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_handover_complete(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_COMPLETE,
		.msg_name = "BSSMAP Handover Complete",
	};

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_handover_failure(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_HANDOVER_FAILURE,
		.msg_name = "BSSMAP Handover Failure",
	};

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_setup_ack(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_SETUP_ACK,
		.msg_name = "BSSMAP VGCS/VBS SETUP ACKNOWLEDGE",
	};
	struct gsm0808_vgcs_vbs_setup_ack *r = &ran_dec_msg.vgcs_vbs_setup_ack;
	int rc;

	const struct tlv_p_entry *ie_flags = TLVP_GET(tp, GSM0808_IE_VGCS_FEATURE_FLAGS);

	/* VGCS Feature Flags, 3.2.2.88 */
	if (ie_flags) {
		rc = gsm0808_dec_vgcs_feature_flags(&r->flags, ie_flags->val, ie_flags->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Unable to decode VGCS/VBS Feature Flags\n");
			return -EINVAL;
		}
		r->vgcs_feature_flags_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_setup_refuse(struct ran_dec *ran_dec, const struct msgb *msg,
					      const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_SETUP_REFUSE,
		.msg_name = "BSSMAP VGCS/VBS SETUP REFUSE",
	};

	const struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);

	/* Cause, 3.2.2.5 */
	if (!ie_cause || ie_cause->len < 1) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cause\n");
		return -EINVAL;
	}
	ran_dec_msg.vgcs_vbs_setup_refuse.cause = ie_cause->val[0];

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_assign_res(struct ran_dec *ran_dec, const struct msgb *msg,
					    const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_ASSIGN_RES,
		.msg_name = "BSSMAP VGCS/VBS ASSIGNMENT RESULT",
	};
	struct gsm0808_vgcs_vbs_assign_res *r = &ran_dec_msg.vgcs_vbs_assign_res;
	int rc;

	const struct tlv_p_entry *ie_channel_type = TLVP_GET(tp, GSM0808_IE_CHANNEL_TYPE);
	const struct tlv_p_entry *ie_cell_id = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_chosen_channel = TLVP_GET(tp, GSM0808_IE_CHOSEN_CHANNEL);
	const struct tlv_p_entry *ie_cic = TLVP_GET(tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE);
	const struct tlv_p_entry *ie_circuit_pool = TLVP_GET(tp, GSM0808_IE_CIRCUIT_POOL);
	const struct tlv_p_entry *ie_aoip = TLVP_GET(tp, GSM0808_IE_AOIP_TRASP_ADDR);
	const struct tlv_p_entry *ie_call_id = TLVP_GET(tp, GSM0808_IE_CALL_ID);

	/* Channel Type, 3.2.2.11 */
	if (!ie_channel_type) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Channel Type\n");
		return -EINVAL;
	}
	if (gsm0808_dec_channel_type(&r->channel_type, ie_channel_type->val, ie_channel_type->len) <= 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Failed to decode Channel Type IE\n");
		return -EINVAL;
	}

	/* Cell Identifier, 3.2.2.17 */
	if (!ie_cell_id) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cell Identifier\n");
		return -EINVAL;
	}
	rc = gsm0808_dec_cell_id(&r->cell_identifier, ie_cell_id->val, ie_cell_id->len);
	if (rc < 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
		return -EINVAL;
	}

	/* Chosen Channel, 3.2.2.33 */
	if (ie_chosen_channel) {
		r->chosen_channel = ie_chosen_channel->val[0];
		r->chosen_channel_present = true;
	}

	/* Circuit Identity Code, 3.2.2.2 */
	if (ie_cic) {
		if (ie_cic->len != 2) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Circuit Identity Code has invalid length.\n");
			return -EINVAL;
		}
		r->cic = *(uint16_t *)ie_cic->val;
		r->cic_present = true;
	}

	/* Circuit Pool, 3.2.2.45 */
	if (ie_circuit_pool) {
		r->circuit_pool = ie_circuit_pool->val[0];
		r->circuit_pool_present = true;
	}

	/* AoIP Transport Layer Address (BSS), 3.2.2.102 */
	if (ie_aoip) {
		if (gsm0808_dec_aoip_trasp_addr(&r->aoip_transport_layer, ie_aoip->val, ie_aoip->len) < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "unable to decode AoIP transport address\n");
			return -EINVAL;
		}
		r->aoip_transport_layer_present = true;
	}

	if (ie_call_id) {
		if (ie_call_id->len != 4) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Call Identifier has invalid length.\n");
			return -EINVAL;
		}
		r->call_id = osmo_load32le(ie_call_id->val);
		r->call_id_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_assign_fail(struct ran_dec *ran_dec, const struct msgb *msg,
					     const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_ASSIGN_FAIL,
		.msg_name = "BSSMAP VGCS/VBS ASSIGNMENT FAILURE",
	};
	struct gsm0808_vgcs_vbs_assign_fail *r = &ran_dec_msg.vgcs_vbs_assign_fail;
	int rc;

	const struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	const struct tlv_p_entry *ie_circuit_pool = TLVP_GET(tp, GSM0808_IE_CIRCUIT_POOL);
	const struct tlv_p_entry *ie_circuit_pool_list = TLVP_GET(tp, GSM0808_IE_CIRCUIT_POOL_LIST);
	const struct tlv_p_entry *ie_codec_list_bss_supported = TLVP_GET(tp, GSM0808_IE_SPEECH_CODEC_LIST);

	/* Cause, 3.2.2.5 */
	if (!ie_cause || ie_cause->len < 1) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cause\n");
		return -EINVAL;
	}
	r->cause = ie_cause->val[0];

	/* Circuit Pool, 3.2.2.45 */
	if (ie_circuit_pool) {
		r->circuit_pool = ie_circuit_pool->val[0];
		r->circuit_pool_present = true;
	}

	/* Circuit Pool List, 3.2.2.46 */
	if (ie_circuit_pool_list && ie_circuit_pool_list->len) {
		if (ie_circuit_pool_list->len > CIRCUIT_POOL_LIST_MAXLEN) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Circuit Pool List has invalid length.\n");
			return -EINVAL;
		}
		memcpy(r->cpl.pool, ie_circuit_pool_list->val, ie_circuit_pool_list->len);
		r->cpl.list_len = ie_circuit_pool_list->len;
		r->cpl_present = true;
	}

	/* Codec List (BSS Supported) 3.2.2.103 */
	if (ie_codec_list_bss_supported) {
		rc = gsm0808_dec_speech_codec_list(&r->codec_list_bss_supported,
						   ie_codec_list_bss_supported->val, ie_codec_list_bss_supported->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR,
					  "Complete Layer 3 Information: unable to decode IE Codec List (BSS Supported)"
					  " (rc=%d), continuing anyway\n", rc);
			/* This IE is not critical, do not abort with error. */
		} else
			r->codec_list_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_queuing_ind(struct ran_dec *ran_dec, const struct msgb *msg,
					     const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_QUEUING_IND,
		.msg_name = "BSSMAP VGCS/VBS QUEUING INDICATION",
	};

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_uplink_request(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_UPLINK_REQUEST,
		.msg_name = "BSSMAP UPLINK REQUEST",
	};
	struct gsm0808_uplink_request *r = &ran_dec_msg.uplink_request;
	int rc;

	const struct tlv_p_entry *ie_talker_priority = TLVP_GET(tp, GSM0808_IE_TALKER_PRIORITY);
	const struct tlv_p_entry *ie_cell_id = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_l3_info = TLVP_GET(tp, GSM0808_IE_LAYER_3_INFORMATION);
	const struct tlv_p_entry *ie_mi = TLVP_GET(tp, GSM0808_IE_MOBILE_IDENTITY);

	/* Talker Priority, 3.2.2.89 */
	if (ie_talker_priority) {
		r->talker_priority = ie_talker_priority->val[0] & 0x03;
		r->talker_priority_present = true;
	}

	/* Cell Identifier, 3.2.2.17 */
	if (ie_cell_id) {
		rc = gsm0808_dec_cell_id(&r->cell_identifier, ie_cell_id->val, ie_cell_id->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
			return -EINVAL;
		}
	}

	/* Layer 3 Information, 3.2.2.24 */
	if (ie_l3_info && ie_l3_info->len) {
		if (ie_l3_info->len > LAYER_3_INFORMATION_MAXLEN) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Call Identifier has invalid length.\n");
			return -EINVAL;
		}
		memcpy(r->l3.l3, ie_l3_info->val, ie_l3_info->len);
		r->l3.l3_len = ie_l3_info->len;
		r->l3_present = true;
	}

	/* Mobile Identity,  3.2.2.41 */
	if (ie_mi) {
		rc = osmo_mobile_identity_decode(&r->mi, ie_mi->val, ie_mi->len, false);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Mobile Identity gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->mi_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_uplink_request_cnf(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_UPLINK_REQUEST_CNF,
		.msg_name = "BSSMAP UPLINK REQUEST CONFIRM",
	};
	struct gsm0808_uplink_request_cnf *r = &ran_dec_msg.uplink_request_cnf;
	int rc;

	const struct tlv_p_entry *ie_cell_id = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_talker_identity = TLVP_GET(tp, GSM0808_IE_TALKER_IDENTITY);
	const struct tlv_p_entry *ie_l3_info = TLVP_GET(tp, GSM0808_IE_LAYER_3_INFORMATION);

	/* Cell Identifier, 3.2.2.17 */
	if (!ie_cell_id) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cell Identifier\n");
		return -EINVAL;
	}
	rc = gsm0808_dec_cell_id(&r->cell_identifier, ie_cell_id->val, ie_cell_id->len);
	if (rc < 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
		return -EINVAL;
	}

	/* Talker Identity, 3.2.2.91 */
	if (ie_talker_identity) {
		rc = gsm0808_dec_talker_identity(&r->talker_identity, ie_talker_identity->val, ie_talker_identity->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Talker Identity gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->talker_identity_present = true;
	}

	/* Layer 3 Information, 3.2.2.24 */
	if (!ie_l3_info) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Layer 3 Information\n");
		return -EINVAL;
	}
	if (ie_l3_info->len > LAYER_3_INFORMATION_MAXLEN) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Call Identifier has invalid length.\n");
		return -EINVAL;
	}
	memcpy(r->l3.l3, ie_l3_info->val, ie_l3_info->len);
	r->l3.l3_len = ie_l3_info->len;

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_uplink_application_data(struct ran_dec *ran_dec, const struct msgb *msg,
						const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_UPLINK_APPLICATION_DATA,
		.msg_name = "BSSMAP UPLINK APPLICATION DATA",
	};
	struct gsm0808_uplink_app_data *r = &ran_dec_msg.uplink_app_data;
	int rc;

	const struct tlv_p_entry *ie_cell_id = TLVP_GET(tp, GSM0808_IE_CELL_IDENTIFIER);
	const struct tlv_p_entry *ie_l3_info = TLVP_GET(tp, GSM0808_IE_LAYER_3_INFORMATION);
	const struct tlv_p_entry *ie_app_data = TLVP_GET(tp, GSM0808_IE_APP_DATA);

	/* Cell Identifier, 3.2.2.17 */
	if (!ie_cell_id) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cell Identifier\n");
		return -EINVAL;
	}
	rc = gsm0808_dec_cell_id(&r->cell_identifier, ie_cell_id->val, ie_cell_id->len);
	if (rc < 0) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
		return -EINVAL;
	}

	/* Layer 3 Information, 3.2.2.24 */
	if (!ie_l3_info) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Layer 3 Information\n");
		return -EINVAL;
	}
	if (ie_l3_info->len > LAYER_3_INFORMATION_MAXLEN) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Call Identifier has invalid length.\n");
		return -EINVAL;
	}
	memcpy(r->l3.l3, ie_l3_info->val, ie_l3_info->len);
	r->l3.l3_len = ie_l3_info->len;

	/* Application Data Information, 3.2.2.100 */
	if (!ie_app_data || ie_app_data->len < 1) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Application Data Information\n");
		return -EINVAL;
	}
	r->bt_ind = ie_app_data->val[0] & 0x01;

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_uplink_release_ind(struct ran_dec *ran_dec, const struct msgb *msg, const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_UPLINK_RELEASE_IND,
		.msg_name = "BSSMAP UPLINK RELEASE INDICATION",
	};
	struct gsm0808_uplink_release_ind *r = &ran_dec_msg.uplink_release_ind;

	const struct tlv_p_entry *ie_cause = TLVP_GET(tp, GSM0808_IE_CAUSE);
	const struct tlv_p_entry *ie_talker_priority = TLVP_GET(tp, GSM0808_IE_TALKER_PRIORITY);

	/* Cause, 3.2.2.5 */
	if (!ie_cause || ie_cause->len < 1) {
		LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Mandatory IE missing: Cause\n");
		return -EINVAL;
	}
	r->cause = ie_cause->val[0];

	/* Talker Priority, 3.2.2.89 */
	if (ie_talker_priority) {
		r->talker_priority = ie_talker_priority->val[0] & 0x03;
		r->talker_priority_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_vgcs_vbs_assign_status(struct ran_dec *ran_dec, const struct msgb *msg,
					       const struct tlv_parsed *tp)
{
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_VGCS_VBS_ASSIGN_STATUS,
		.msg_name = "BSSMAP VGCS/VBS ASSIGNMENT STATUS",
	};
	struct gsm0808_vgcs_vbs_assign_stat *r = &ran_dec_msg.vgcs_vbs_assign_stat;
	int rc;

	const struct tlv_p_entry *ie_cils_est = TLVP_GET(tp, GSM0808_IE_CELL_ID_LIST_SEG_EST_CELLS);
	const struct tlv_p_entry *ie_cils_tbe = TLVP_GET(tp, GSM0808_IE_CELL_ID_LIST_SEG_CELLS_TBE);
	const struct tlv_p_entry *ie_cils_rel = TLVP_GET(tp, GSM0808_IE_CELL_ID_LIST_SEG_REL_CELLS);
	const struct tlv_p_entry *ie_cils_ne = TLVP_GET(tp, GSM0808_IE_CELL_ID_LIST_SEG_NE_CELLS);
	const struct tlv_p_entry *ie_cell_status = TLVP_GET(tp, GSM0808_IE_VGCS_VBS_CELL_STATUS);

	/* Cell Identifier List Segment, 3.2.2.27b */
	if (ie_cils_est) {
		rc = gsm0808_dec_cell_id_list_segment(&r->cils_est, ie_cils_est->val, ie_cils_est->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->cils_est_present = true;
	}

	/* Cell Identifier List Segment, 3.2.2.27c */
	if (ie_cils_tbe) {
		rc = gsm0808_dec_cell_id_list_segment(&r->cils_tbe, ie_cils_tbe->val, ie_cils_tbe->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->cils_tbe_present = true;
	}

	/* Cell Identifier List Segment, 3.2.2.27e */
	if (ie_cils_rel) {
		rc = gsm0808_dec_cell_id_list_segment(&r->cils_rel, ie_cils_rel->val, ie_cils_rel->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->cils_rel_present = true;
	}

	/* Cell Identifier List Segment, 3.2.2.27f */
	if (ie_cils_ne) {
		rc = gsm0808_dec_cell_id_list_segment(&r->cils_ne, ie_cils_ne->val, ie_cils_ne->len);
		if (rc < 0) {
			LOG_RAN_A_DEC_MSG(LOGL_ERROR, "Decoding Cell Identifier gave rc=%d\n", rc);
			return -EINVAL;
		}
		r->cils_ne_present = true;
	}

	/* VGCS/VBS Cell Status, 3.2.2.94 */
	if (ie_cell_status && ie_cell_status->len) {
		r->cell_status = ie_cell_status->val[0] & 0x73;
		r->cell_status_present = true;
	}

	return ran_decoded(ran_dec, &ran_dec_msg);
}

static int ran_a_decode_bssmap(struct ran_dec *ran_dec, struct msgb *bssmap)
{
	struct tlv_parsed tp[2];
	int rc;
	struct bssmap_header *h = msgb_l2(bssmap);
	uint8_t msg_type;
	bssmap->l3h = bssmap->l2h + sizeof(*h);

	if (msgb_l3len(bssmap) < 1) {
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "No data received, discarding message\n");
		return -1;
	}

	if (msgb_l3len(bssmap) < h->length) {
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "BSSMAP data truncated, discarding message:"
			      " msgb_l3len(bssmap) == %u < bssmap_header->length == %u\n",
			      msgb_l3len(bssmap), h->length);
		return -1;
	}

	if (msgb_l3len(bssmap) > h->length) {
		LOG_RAN_A_DEC(ran_dec, LOGL_NOTICE, "There are %u extra bytes after the BSSMAP data, truncating:"
			      " msgb_l3len(bssmap) == %u > bssmap_header->length == %u\n",
			      msgb_l3len(bssmap) - h->length,
			      msgb_l3len(bssmap), h->length);
		msgb_l3trim(bssmap, h->length);
	}

	/* h->type == BSSAP_MSG_BSS_MANAGEMENT; h->length is the data length,
	 * which starts with the MAP msg_type, followed by IEs. */
	msg_type = bssmap->l3h[0];
	rc = osmo_bssap_tlv_parse2(tp, ARRAY_SIZE(tp), bssmap->l3h + 1, h->length - 1);
	if (rc < 0) {
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "Failed parsing TLV, discarding message\n");
		return -EINVAL;
	}

	LOG_RAN_A_DEC(ran_dec, LOGL_DEBUG, "%s\n", gsm0808_bssmap_name(msg_type));

	switch (msg_type) {
	case BSS_MAP_MSG_COMPLETE_LAYER_3:
		return ran_a_decode_l3_compl(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_CLEAR_RQST:
		return ran_a_decode_clear_request(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return ran_a_decode_clear_complete(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_CLASSMARK_UPDATE:
		return ran_a_decode_classmark_update(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_CIPHER_MODE_COMPLETE:
		return ran_a_decode_cipher_mode_complete(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_CIPHER_MODE_REJECT:
		return ran_a_decode_cipher_mode_reject(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		rc = ran_a_decode_assignment_complete(ran_dec, bssmap, tp);
		if (rc < 0) {
			struct ran_msg ran_dec_msg = {
				.msg_type = RAN_MSG_ASSIGNMENT_FAILURE,
				.msg_name = "BSSMAP Assignment Complete but failed to decode",
				.clear_request = {
					.bssap_cause = GSM0808_CAUSE_EQUIPMENT_FAILURE,
				},
			};
			ran_decoded(ran_dec, &ran_dec_msg);
		}
		return rc;
	case BSS_MAP_MSG_ASSIGMENT_FAILURE:
		return ran_a_decode_assignment_failure(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_SAPI_N_REJECT:
		return ran_a_decode_sapi_n_reject(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_LCLS_NOTIFICATION:
		return ran_a_decode_lcls_notification(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_SETUP_ACK:
		return ran_a_decode_vgcs_vbs_setup_ack(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_SETUP_REFUSE:
		return ran_a_decode_vgcs_vbs_setup_refuse(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_RESULT:
		return ran_a_decode_vgcs_vbs_assign_res(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_FAILURE:
		return ran_a_decode_vgcs_vbs_assign_fail(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_QUEUING_INDICATION:
		return ran_a_decode_vgcs_vbs_queuing_ind(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_UPLINK_RQST:
		return ran_a_decode_uplink_request(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_UPLINK_RQST_CONFIRMATION:
		return ran_a_decode_uplink_request_cnf(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_UPLINK_APP_DATA:
		return ran_a_decode_uplink_application_data(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_UPLINK_RELEASE_INDICATION:
		return ran_a_decode_uplink_release_ind(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_VGCS_VBS_ASSIGNMENT_STATUS:
		return ran_a_decode_vgcs_vbs_assign_status(ran_dec, bssmap, tp);

	/* From current RAN peer, the Handover origin: */
	case BSS_MAP_MSG_HANDOVER_REQUIRED:
		return ran_a_decode_handover_required(ran_dec, bssmap, tp);

	/* From current MSC to remote handover target MSC */
	case BSS_MAP_MSG_HANDOVER_RQST:
		return ran_a_decode_handover_request(ran_dec, bssmap, tp);

	/* From potential new RAN peer, the Handover target: */
	case BSS_MAP_MSG_HANDOVER_RQST_ACKNOWLEDGE:
		return ran_a_decode_handover_request_ack(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_HANDOVER_DETECT:
		return ran_a_decode_handover_detect(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_HANDOVER_SUCCEEDED:
		return ran_a_decode_handover_succeeded(ran_dec, bssmap, tp);
	case BSS_MAP_MSG_HANDOVER_COMPLETE:
		return ran_a_decode_handover_complete(ran_dec, bssmap, tp);

	/* From any Handover peer: */
	case BSS_MAP_MSG_HANDOVER_FAILURE:
		return ran_a_decode_handover_failure(ran_dec, bssmap, tp);

	default:
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "Unimplemented msg type: %s\n", gsm0808_bssmap_name(msg_type));
		return -EINVAL;
	}

	return -EINVAL;
}

static int ran_a_decode_l3(struct ran_dec *ran_dec, struct msgb *l3)
{
	struct dtap_header *dtap = msgb_l2(l3);
	struct ran_msg ran_dec_msg = {
		.msg_type = RAN_MSG_DTAP,
		.msg_name = "BSSAP DTAP",
		.dtap = l3,
	};
	l3->l3h = l3->l2h + sizeof(struct dtap_header);
	OMSC_LINKID_CB(l3) = dtap->link_id;
	return ran_decoded(ran_dec, &ran_dec_msg);
}

int ran_a_decode_l2(struct ran_dec *ran_dec, struct msgb *bssap)
{
	uint8_t bssap_type;
	OSMO_ASSERT(bssap);

	if (!msgb_l2(bssap) || !msgb_l2len(bssap)) {
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "Cannot decode L2, msg->l2h is unset / empty: %s\n",
			      msgb_hexdump(bssap));
		return -EINVAL;
	}

	if (msgb_l2len(bssap) < sizeof(struct bssmap_header)) {
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "The header is too short -- discarding message\n");
		return -EINVAL;
	}

	bssap_type = bssap->l2h[0];
	switch (bssap_type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		return ran_a_decode_bssmap(ran_dec, bssap);
	case BSSAP_MSG_DTAP:
		return ran_a_decode_l3(ran_dec, bssap);
	default:
		LOG_RAN_A_DEC(ran_dec, LOGL_ERROR, "Unimplemented BSSAP msg type: %s\n", gsm0808_bssap_name(bssap_type));
		return -EINVAL;
	}
}

static struct msgb *ran_a_wrap_dtap(struct msgb *dtap)
{
	struct msgb *an_apdu;
	dtap->l3h = dtap->data;
	an_apdu = gsm0808_create_dtap(dtap, OMSC_LINKID_CB(dtap));
	an_apdu->l2h = an_apdu->data;
	msgb_free(dtap);
	return an_apdu;
}

static int ran_a_channel_type_to_speech_codec_list(struct gsm0808_speech_codec_list *scl, const struct gsm0808_channel_type *ct)
{
	unsigned int i;
	int rc;

	memset(scl, 0, sizeof(*scl));

	switch (ct->ch_indctr) {
	case GSM0808_CHAN_DATA:
		scl->codec[0] = (struct gsm0808_speech_codec) {
			.pi = true, /* PI indicates CSDoIP is supported */
			.pt = false, /* PT indicates CSDoTDM is not supported */
			.type = GSM0808_SCT_CSD,
			.cfg = 0, /* R2/R3 not set (redundancy not supported) */
		};
		scl->len = 1;
		break;
	case GSM0808_CHAN_SPEECH:
		for (i = 0; i < ct->perm_spch_len; i++) {
			rc = gsm0808_speech_codec_from_chan_type(&scl->codec[i], ct->perm_spch[i]);
			if (rc != 0)
				return -EINVAL;
		}
		scl->len = i;
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}

	return 0;
}

/* Compose a BSSAP Assignment Command.
 * Passing an RTP address is optional.
 * The msub is passed merely for error logging. */
static struct msgb *ran_a_make_assignment_command(struct osmo_fsm_inst *log_fi,
						  const struct ran_assignment_command *ac)
{
	struct gsm0808_speech_codec_list scl;
	struct gsm0808_speech_codec_list *use_scl = NULL;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_storage *use_rtp_addr = NULL;
	struct msgb *msg;
	const uint32_t *call_id = NULL;
	int rc;

	if (!ac->channel_type) {
		LOG_RAN_A_ENC(log_fi, LOGL_ERROR, "Assignment Command: missing Channel Type\n");
		return NULL;
	}

	if (ac->channel_type->ch_indctr == GSM0808_CHAN_SPEECH || ac->channel_type->ch_indctr == GSM0808_CHAN_DATA) {
		rc = ran_a_channel_type_to_speech_codec_list(&scl, ac->channel_type);
		if (rc < 0) {
			LOG_RAN_A_ENC(log_fi, LOGL_ERROR, "Assignment Command: Cannot translate Channel Type to Speech Codec List\n");
			return NULL;
		}
		use_scl = &scl;

		/* Package RTP-Address data */
		if (osmo_sockaddr_str_is_nonzero(ac->cn_rtp)) {
			struct sockaddr_in *sin;
			struct sockaddr_in6 *sin6;
			int family = osmo_ip_str_type(ac->cn_rtp->ip);
			switch (family) {
			case AF_INET:
				sin = (struct sockaddr_in *)&rtp_addr;
				sin->sin_family = AF_INET;
				sin->sin_port = osmo_htons(ac->cn_rtp->port);
				if (inet_pton(AF_INET, ac->cn_rtp->ip, &sin->sin_addr) != 1) {
					LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
						      "Assignment Command: Invalid RTP-Address %s\n",
						      ac->cn_rtp->ip);
					return NULL;
				}
				if (sin->sin_port == 0) {
					LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
							"Assignment Command: Invalid RTP-Port\n");
					return NULL;
				}
				break;
			case AF_INET6:
				sin6 = (struct sockaddr_in6 *)&rtp_addr;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = osmo_htons(ac->cn_rtp->port);
				if (inet_pton(AF_INET6, ac->cn_rtp->ip, &sin6->sin6_addr) != 1) {
					LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
						      "Assignment Command: Invalid RTP-Address %s\n",
						      ac->cn_rtp->ip);
					return NULL;
				}
				if (sin6->sin6_port == 0) {
					LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
							"Assignment Command: Invalid RTP-Port\n");
					return NULL;
				}
				break;
			default:
				LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
					      "Assignment Command: Invalid RTP-Address type for %s\n",
					       ac->cn_rtp->ip);
				return NULL;
			}
			use_rtp_addr = &rtp_addr;
		}
	}

	if(ac->call_id_present == true)
		call_id = &ac->call_id;

	msg = gsm0808_create_ass2(ac->channel_type, NULL, use_rtp_addr, use_scl, call_id,
				  NULL, ac->lcls);
	if (msg == NULL) {
		LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
			      "Failed to encode BSSMAP Assignment Request message\n");
		return NULL;
	}

	/* Append optional IEs: Group Call Reference and Osmux CID */
	OSMO_ASSERT(msg->l3h[1] == msgb_l3len(msg) - 2); /* TL not in len */
	if (ac->callref_present)
		gsm0808_enc_group_callref(msg, &ac->callref);
	if (ac->osmux_present)
		msgb_tv_put(msg, GSM0808_IE_OSMO_OSMUX_CID, ac->osmux_cid);
	msg->l3h[1] = msgb_l3len(msg) - 2;
	return msg;
}

/* For an A5/N number a5_n set dst to the matching GSM0808_ALG_ID_A5_<n>. */
static int a5_n_to_gsm0808_chosen_enc_alg(uint8_t *dst, int a5_n)
{
	switch (a5_n) {
	case 0:
		*dst = GSM0808_ALG_ID_A5_0;
		return 0;
	case 1:
		*dst = GSM0808_ALG_ID_A5_1;
		return 0;
	case 2:
		*dst = GSM0808_ALG_ID_A5_2;
		return 0;
	case 3:
		*dst = GSM0808_ALG_ID_A5_3;
		return 0;
	case 4:
		*dst = GSM0808_ALG_ID_A5_4;
		return 0;
	default:
		return -ENOTSUP;
	}
}

static int make_encrypt_info_perm_algo(struct osmo_fsm_inst *fi, struct gsm0808_encrypt_info *ei,
				       uint8_t a5_encryption_mask, const struct osmo_gsm48_classmark *cm)
{
	int i;
	int j = 0;
	for (i = 0; i < 8; i++) {
		int supported;

		/* A5/n permitted by osmo-msc.cfg? */
		if (!(a5_encryption_mask & (1 << i)))
			continue;

		/* A5/n supported by MS? */
		supported = osmo_gsm48_classmark_supports_a5(cm, i);
		if (supported != 1)
			continue;

		if (a5_n_to_gsm0808_chosen_enc_alg(&ei->perm_algo[j], i)) {
			LOG_RAN_A_ENC(fi, LOGL_ERROR, "Not supported: A5/%d algorithm\n", i);
			return -1;
		}
		j++;
		ei->perm_algo_len = j;
	}
	return 0;
}

/* For ran_a_make_cipher_mode_command(), for
 * memcpy(ei.key, cm->vec->kc, sizeof(cm->vec->kc));
 */
osmo_static_assert(sizeof(((struct gsm0808_encrypt_info*)0)->key) >= sizeof(((struct osmo_auth_vector*)0)->kc),
		   gsm0808_encrypt_info_key_fits_osmo_auth_vec_kc);
static struct msgb *ran_a_make_cipher_mode_command(struct osmo_fsm_inst *fi, const struct ran_cipher_mode_command *cm)
{
	struct gsm0808_cipher_mode_command cmc = {
		.cipher_response_mode_present = true,
		.cipher_response_mode = 1, /* 1: include IMEISV (3GPP TS 48.008 3.2.2.34) */
	};
	struct gsm0808_encrypt_info *ei = &cmc.ei;
	char buf[16 * 2 + 1];

	if (make_encrypt_info_perm_algo(fi, ei, cm->geran.a5_encryption_mask, cm->classmark))
		return NULL;

	if (ei->perm_algo_len == 0) {
		LOG_RAN_A_ENC(fi, LOGL_ERROR, "cannot start ciphering, no intersection between MSC-configured"
			       " and MS-supported A5 algorithms. MSC: 0x%02x  MS: %s\n",
			       cm->geran.a5_encryption_mask, osmo_gsm48_classmark_a5_name(cm->classmark));
		return NULL;
	}

	/* In case of UMTS AKA, the Kc for ciphering must be derived from the 3G auth
	 * tokens.  vec->kc was calculated from the GSM algorithm and is not
	 * necessarily a match for the UMTS AKA tokens. */
	if (cm->geran.umts_aka) {
		int i;
		osmo_auth_c3(ei->key, cm->vec->ck, cm->vec->ik);

		for (i = 0; i < ei->perm_algo_len; i++) {
			if (ei->perm_algo[i] != GSM0808_ALG_ID_A5_4)
				continue;
			/* A5/4 is included, so need to generate Kc128 */
			osmo_kdf_kc128(cm->vec->ck, cm->vec->ik, cmc.kc128);
			cmc.kc128_present = true;
			break;
		}
	} else {
		memcpy(ei->key, cm->vec->kc, sizeof(cm->vec->kc));
	}
	ei->key_len = sizeof(cm->vec->kc);

	/* Store chosen GERAN key where the caller asked it to be stored.
	 * alg_id remains unknown until we receive a Cipher Mode Complete from the BSC */
	if (cm->geran.chosen_key) {
		*cm->geran.chosen_key = (struct geran_encr){0};

		if (ei->key_len > sizeof(cm->geran.chosen_key->key)) {
			LOG_RAN_A_ENC(fi, LOGL_ERROR, "Chosen key is larger than I can store\n");
			return NULL;
		}
		memcpy(cm->geran.chosen_key->key, ei->key, ei->key_len);
		cm->geran.chosen_key->key_len = ei->key_len;

		if (cmc.kc128_present) {
			memcpy(cm->geran.chosen_key->kc128, cmc.kc128, 16);
			cm->geran.chosen_key->kc128_present = true;
		}
	}

	LOG_RAN_A_ENC(fi, LOGL_DEBUG, "Tx BSSMAP CIPHER MODE COMMAND to BSC, %u ciphers (%s) key %s\n",
		       ei->perm_algo_len, osmo_hexdump_nospc(ei->perm_algo, ei->perm_algo_len),
		       osmo_hexdump_buf(buf, sizeof(buf), ei->key, ei->key_len, NULL, false));
	return gsm0808_create_cipher2(&cmc);
}

struct msgb *ran_a_make_handover_request(struct osmo_fsm_inst *log_fi, const struct ran_handover_request *n)
{
	struct sockaddr_storage ss;
	struct gsm0808_handover_request r = {
		.cell_identifier_serving = n->cell_id_serving,
		.cell_identifier_target = n->cell_id_target,
		.cause = n->bssap_cause,
		.current_channel_type_1_present = n->current_channel_type_1_present,
		.current_channel_type_1 = n->current_channel_type_1,

		.speech_version_used = n->speech_version_used,

		.old_bss_to_new_bss_info_raw = n->old_bss_to_new_bss_info_raw,
		.old_bss_to_new_bss_info_raw_len = n->old_bss_to_new_bss_info_raw_len,

		.imsi = n->imsi,
		.codec_list_msc_preferred = n->codec_list_msc_preferred,
		.call_id_present = n->call_id_present,
		.call_id = n->call_id,
		.global_call_reference = n->global_call_reference,
		.global_call_reference_len = n->global_call_reference_len,
	};

	if (!n->geran.channel_type) {
		LOG_RAN_A_ENC(log_fi, LOGL_ERROR, "Channel Type required for encoding Handover Request in BSSAP\n");
		return NULL;
	}
	r.channel_type = *n->geran.channel_type;

	/* Encryption Information */
	make_encrypt_info_perm_algo(log_fi, &r.encryption_information, n->geran.a5_encryption_mask, n->classmark);
	if (n->geran.chosen_encryption && n->geran.chosen_encryption->key_len) {
		/* Prevent both source / destination buffer overrun / overflow */
		if (n->geran.chosen_encryption->key_len > sizeof(r.encryption_information.key)
		    || n->geran.chosen_encryption->key_len > sizeof(n->geran.chosen_encryption->key)) {
			LOG_RAN_A_ENC(log_fi, LOGL_ERROR, "Handover Request: invalid chosen encryption key size %u\n",
				       n->geran.chosen_encryption->key_len);
			return NULL;
		}
		memcpy(r.encryption_information.key,
		       n->geran.chosen_encryption->key, n->geran.chosen_encryption->key_len);
		r.encryption_information.key_len = n->geran.chosen_encryption->key_len;
		r.chosen_encryption_algorithm_serving = n->geran.chosen_encryption->alg_id;

		if (n->geran.chosen_encryption->kc128_present) {
			r.more_items = true;
			memcpy(r.kc128, n->geran.chosen_encryption->kc128, sizeof(r.kc128));
			r.kc128_present = true;
		}
	}

	if (n->classmark)
		r.classmark_information = *n->classmark;

	if (osmo_sockaddr_str_is_nonzero(n->rtp_ran_local)) {
		if (osmo_sockaddr_str_to_sockaddr(n->rtp_ran_local, &ss)) {
			LOG_RAN_A_ENC(log_fi, LOGL_ERROR,
				       "Handover Request: invalid AoIP Transport Layer address/port: "
				       OSMO_SOCKADDR_STR_FMT "\n", OSMO_SOCKADDR_STR_FMT_ARGS(n->rtp_ran_local));
			return NULL;
		}
		r.aoip_transport_layer = &ss;
	}

	return gsm0808_create_handover_request(&r);
}

static struct msgb *ran_a_make_handover_request_ack(struct osmo_fsm_inst *caller_fi, const struct ran_handover_request_ack *r)
{
	struct sockaddr_storage ss;
	struct gsm0808_handover_request_ack params = {
		.l3_info = r->rr_ho_command,
		.l3_info_len = r->rr_ho_command_len,
		.chosen_channel_present = r->chosen_channel_present,
		.chosen_channel = r->chosen_channel,
		.chosen_encr_alg = r->chosen_encr_alg,
		.chosen_speech_version = r->chosen_speech_version,
	};

	if (osmo_sockaddr_str_is_nonzero(&r->remote_rtp)) {
		osmo_sockaddr_str_to_sockaddr(&r->remote_rtp, &ss);
		params.aoip_transport_layer = &ss;
	}

	return gsm0808_create_handover_request_ack2(&params);
}

struct msgb *ran_a_make_handover_command(struct osmo_fsm_inst *log_fi, const struct ran_handover_command *n)
{
	struct gsm0808_handover_command c = {
		.l3_info = n->rr_ho_command,
		.l3_info_len = n->rr_ho_command_len,
	};

	return gsm0808_create_handover_command(&c);
}

struct msgb *ran_a_make_handover_failure(struct osmo_fsm_inst *log_fi, const struct ran_msg *msg)
{
	struct gsm0808_handover_failure params = {
		.cause = msg->handover_failure.cause,
	};
	return gsm0808_create_handover_failure(&params);
}

static struct msgb *_ran_a_encode(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg)
{

	LOG_RAN_A_ENC(caller_fi, LOGL_DEBUG, "%s\n", ran_msg_type_name(ran_enc_msg->msg_type));

	switch (ran_enc_msg->msg_type) {

	case RAN_MSG_DTAP:
		return ran_a_wrap_dtap(ran_enc_msg->dtap);

	case RAN_MSG_CLASSMARK_REQUEST:
		return gsm0808_create_classmark_request();

	case RAN_MSG_CLEAR_COMMAND:
		return gsm0808_create_clear_command2(ran_enc_msg->clear_command.gsm0808_cause,
						     ran_enc_msg->clear_command.csfb_ind);

	case RAN_MSG_ASSIGNMENT_COMMAND:
		return ran_a_make_assignment_command(caller_fi, &ran_enc_msg->assignment_command);

	case RAN_MSG_COMMON_ID:
		return gsm0808_create_common_id(ran_enc_msg->common_id.imsi, NULL,
						ran_enc_msg->common_id.last_eutran_plmn_present ?
							&ran_enc_msg->common_id.last_eutran_plmn :
							NULL
						);

	case RAN_MSG_CIPHER_MODE_COMMAND:
		return ran_a_make_cipher_mode_command(caller_fi, &ran_enc_msg->cipher_mode_command);

	case RAN_MSG_HANDOVER_REQUIRED_REJECT:
		return gsm0808_create_handover_required_reject(&ran_enc_msg->handover_required_reject);

	case RAN_MSG_HANDOVER_REQUEST:
		return ran_a_make_handover_request(caller_fi, &ran_enc_msg->handover_request);

	case RAN_MSG_HANDOVER_REQUEST_ACK:
		return ran_a_make_handover_request_ack(caller_fi, &ran_enc_msg->handover_request_ack);

	case RAN_MSG_HANDOVER_COMMAND:
		return ran_a_make_handover_command(caller_fi, &ran_enc_msg->handover_command);

	case RAN_MSG_HANDOVER_SUCCEEDED:
		return gsm0808_create_handover_succeeded();

	case RAN_MSG_HANDOVER_FAILURE:
		return ran_a_make_handover_failure(caller_fi, ran_enc_msg);

	case RAN_MSG_VGCS_VBS_SETUP:
		return gsm0808_create_vgcs_vbs_setup(&ran_enc_msg->vgcs_vbs_setup);

	case RAN_MSG_VGCS_VBS_ASSIGN_REQ:
		return gsm0808_create_vgcs_vbs_assign_req(&ran_enc_msg->vgcs_vbs_assign_req);

	case RAN_MSG_UPLINK_REQUEST_ACK:
		return gsm0808_create_uplink_request_ack(&ran_enc_msg->uplink_request_ack);

	case RAN_MSG_UPLINK_REJECT_CMD:
		return gsm0808_create_uplink_reject_cmd(&ran_enc_msg->uplink_reject_cmd);

	case RAN_MSG_UPLINK_RELEASE_CMD:
		return gsm0808_create_uplink_release_cmd(ran_enc_msg->uplink_release_cmd.cause);

	case RAN_MSG_UPLINK_SEIZED_CMD:
		return gsm0808_create_uplink_seized_cmd(&ran_enc_msg->uplink_seized_cmd);

	case RAN_MSG_VGCS_ADDITIONAL_INFO:
		return gsm0808_create_vgcs_additional_info(&ran_enc_msg->vgcs_additional_info.talker_identity);

	case RAN_MSG_VGCS_VBS_AREA_CELL_INFO:
		return gsm0808_create_vgcs_vbs_area_cell_info(&ran_enc_msg->vgcs_vbs_area_cell_info);

	case RAN_MSG_VGCS_SMS:
		return gsm0808_create_vgcs_sms(&ran_enc_msg->vgcs_sms.sms_to_vgcs);

	case RAN_MSG_NOTIFICATION_DATA:
		return gsm0808_create_notification_data(&ran_enc_msg->notification_data);

	default:
		LOG_RAN_A_ENC(caller_fi, LOGL_ERROR, "Unimplemented RAN-encode message type: %s\n",
			       ran_msg_type_name(ran_enc_msg->msg_type));
		return NULL;
	}
}

struct msgb *ran_a_encode(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg)
{
	struct msgb *msg = _ran_a_encode(caller_fi, ran_enc_msg);

	if (!msg)
		return NULL;

	msg->l2h = msg->data;

	/* some consistency checks to ensure we don't send invalid length */
	switch (msg->l2h[0]) {
	case BSSAP_MSG_DTAP:
		OSMO_ASSERT(msgb_l2len(msg) == msg->l2h[2] + 3);
		break;
	case BSSAP_MSG_BSS_MANAGEMENT:
		OSMO_ASSERT(msgb_l2len(msg) == msg->l2h[1] + 2);
		break;
	default:
		break;
	}

	return msg;
}

static void cl_parse_osmux(struct osmo_fsm_inst *log_fi, struct msgb *msg, int *supports_osmux)
{
	struct tlv_parsed tp;
	int rc;

	if (supports_osmux == NULL)
		return;

	rc = tlv_parse(&tp, gsm0808_att_tlvdef(), msgb_l3(msg) + 1, msgb_l3len(msg) - 1, 0, 0);
	if (rc < 0) {
		LOGPFSMSL(log_fi, DBSSAP, LOGL_ERROR, "BSSMAP: Failed parsing TLV looking for Osmux support\n");
		return;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_OSMO_OSMUX_SUPPORT)) {
		*supports_osmux = true;
	} else {
		*supports_osmux = false;
	}
}

/* Return 1 for a RESET, 2 for a RESET ACK message, 0 otherwise.
 * In supports_osmux, return 0 for no information, 1 for support detected, -1 for non-support detected. */
enum reset_msg_type bssmap_is_reset_msg(const struct sccp_ran_inst *sri, struct osmo_fsm_inst *log_fi,
					struct msgb *l2, int *supports_osmux)
{
	struct bssmap_header *bs = (struct bssmap_header *)msgb_l2(l2);

	if (supports_osmux != NULL)
		*supports_osmux = 0;

	if (!bs
	    || msgb_l2len(l2) < (sizeof(*bs) + 1)
	    || bs->type != BSSAP_MSG_BSS_MANAGEMENT)
		return SCCP_RAN_MSG_NON_RESET;

	l2->l3h = l2->l2h + sizeof(struct bssmap_header);

	switch (l2->l3h[0]) {
	case BSS_MAP_MSG_RESET:
		cl_parse_osmux(log_fi, l2, supports_osmux);
		return SCCP_RAN_MSG_RESET;
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		cl_parse_osmux(log_fi, l2, supports_osmux);
		return SCCP_RAN_MSG_RESET_ACK;
	default:
		return SCCP_RAN_MSG_NON_RESET;
	}
}

/* Patch regular BSSMAP RESET to add extra T to announce Osmux support (osmocom extension) */
static void _gsm0808_extend_announce_osmux(struct msgb *msg)
{
	OSMO_ASSERT(msg->l3h[1] == msgb_l3len(msg) - 2); /*TL not in len */
	msgb_put_u8(msg, GSM0808_IE_OSMO_OSMUX_SUPPORT);
	msg->l3h[1] = msgb_l3len(msg) - 2;
}

struct msgb *bssmap_make_reset_msg(const struct sccp_ran_inst *sri, enum reset_msg_type type)
{
	struct gsm_network *net = sri->user_data;
	struct msgb *msg;

	switch (type) {
	case SCCP_RAN_MSG_RESET:
		msg = gsm0808_create_reset();
		break;
	case SCCP_RAN_MSG_RESET_ACK:
		msg = gsm0808_create_reset_ack();
		break;
	default:
		return NULL;
	}

	if (!msg)
		return NULL;

	if (net->use_osmux != OSMUX_USAGE_OFF)
		_gsm0808_extend_announce_osmux(msg);

	return msg;
}

struct msgb *bssmap_make_paging_msg(const struct sccp_ran_inst *sri, const struct gsm0808_cell_id *page_cell_id,
				    const char *imsi, uint32_t tmsi, enum paging_cause cause)
{
	struct gsm0808_cell_id_list2 cil;
	gsm0808_cell_id_to_list(&cil, page_cell_id);
	return gsm0808_create_paging2(imsi, tmsi == GSM_RESERVED_TMSI ? NULL : &tmsi, &cil, NULL);
}

const char *bssmap_msg_name(const struct sccp_ran_inst *sri, const struct msgb *l2)
{
	struct bssmap_header *bs;

	if (!l2->l2h)
		return "?";

	bs = (struct bssmap_header *)msgb_l2(l2);
	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		return gsm0808_bssmap_name(l2->l2h[0]);
	case BSSAP_MSG_DTAP:
		return "DTAP";
	default:
		return "?";
	}
}
