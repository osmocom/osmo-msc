/* API to forward upcoming NAS events, e.g. from BSSAP and RANAP, to be handled by MSC-A or MSC-I. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * All Rights Reserved
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
#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/msc_common.h>

struct msgb;
struct osmo_fsm_inst;

#define LOG_RAN_DEC(NAS_DEC, subsys, level, fmt, args...) \
	LOGPFSMSL((NAS_DEC)? (NAS_DEC)->caller_fi : NULL, subsys, level, "RAN decode: " fmt, ## args)

#define LOG_RAN_ENC(FI, subsys, level, fmt, args...) \
	LOGPFSMSL(FI, subsys, level, "RAN encode: " fmt, ## args)

/* These message types are named after the BSSAP procedures in nas_a.h; most are also used for RANAP procedures of
 * similar meaning in nas_iu.h. */
enum ran_msg_type {
	RAN_MSG_NONE = 0,
	RAN_MSG_COMPL_L3,
	RAN_MSG_DTAP,
	RAN_MSG_CLEAR_COMMAND,
	RAN_MSG_CLEAR_REQUEST,
	RAN_MSG_CLEAR_COMPLETE,
	RAN_MSG_CLASSMARK_REQUEST,
	RAN_MSG_CLASSMARK_UPDATE,
	RAN_MSG_CIPHER_MODE_COMMAND,
	RAN_MSG_CIPHER_MODE_COMPLETE,
	RAN_MSG_CIPHER_MODE_REJECT,
	RAN_MSG_COMMON_ID,
	RAN_MSG_ASSIGNMENT_COMMAND,
	RAN_MSG_ASSIGNMENT_COMPLETE,
	RAN_MSG_ASSIGNMENT_FAILURE,
	RAN_MSG_SAPI_N_REJECT,
	RAN_MSG_LCLS_STATUS,
	RAN_MSG_LCLS_BREAK_REQ,
	RAN_MSG_HANDOVER_COMMAND,
	RAN_MSG_HANDOVER_PERFORMED,
	RAN_MSG_HANDOVER_REQUIRED,
	RAN_MSG_HANDOVER_REQUIRED_REJECT,
	RAN_MSG_HANDOVER_REQUEST,
	RAN_MSG_HANDOVER_REQUEST_ACK,
	RAN_MSG_HANDOVER_DETECT,
	RAN_MSG_HANDOVER_SUCCEEDED,
	RAN_MSG_HANDOVER_COMPLETE,
	RAN_MSG_HANDOVER_FAILURE,
	RAN_MSG_VGCS_VBS_SETUP,
	RAN_MSG_VGCS_VBS_SETUP_ACK,
	RAN_MSG_VGCS_VBS_SETUP_REFUSE,
	RAN_MSG_VGCS_VBS_ASSIGN_REQ,
	RAN_MSG_VGCS_VBS_ASSIGN_RES,
	RAN_MSG_VGCS_VBS_ASSIGN_FAIL,
	RAN_MSG_VGCS_VBS_QUEUING_IND,
	RAN_MSG_UPLINK_REQUEST,
	RAN_MSG_UPLINK_REQUEST_ACK,
	RAN_MSG_UPLINK_REQUEST_CNF,
	RAN_MSG_UPLINK_APPLICATION_DATA,
	RAN_MSG_UPLINK_RELEASE_IND,
	RAN_MSG_UPLINK_REJECT_CMD,
	RAN_MSG_UPLINK_RELEASE_CMD,
	RAN_MSG_UPLINK_SEIZED_CMD,
	RAN_MSG_VGCS_ADDITIONAL_INFO,
	RAN_MSG_VGCS_VBS_AREA_CELL_INFO,
	RAN_MSG_VGCS_VBS_ASSIGN_STATUS,
	RAN_MSG_VGCS_SMS,
	RAN_MSG_NOTIFICATION_DATA,
};

extern const struct value_string ran_msg_type_names[];
static inline const char *ran_msg_type_name(enum ran_msg_type val)
{ return get_value_string(ran_msg_type_names, val); }

struct ran_clear_command {
	enum gsm0808_cause gsm0808_cause;
	bool csfb_ind;
};

struct ran_assignment_command {
	const struct osmo_sockaddr_str *cn_rtp;
	const struct gsm0808_channel_type *channel_type;
	enum nsap_addr_enc rab_assign_addr_enc;
	bool osmux_present;
	uint8_t osmux_cid;
	bool call_id_present;
	uint32_t call_id;
	struct osmo_lcls *lcls;
	bool callref_present;
	struct gsm0808_group_callref callref;
};

struct ran_cipher_mode_command {
	const struct osmo_auth_vector *vec;
	const struct osmo_gsm48_classmark *classmark;
	struct {
		bool umts_aka;
		bool retrieve_imeisv;
		uint8_t a5_encryption_mask;

		/* out-argument to return the key to the caller, pass NULL if not needed. */
		struct geran_encr *chosen_key;
	} geran;
	struct {
		uint8_t uea_encryption_mask;
	} utran;
};

struct ran_handover_request {
	const char *imsi;
	const struct osmo_gsm48_classmark *classmark;
	/* A Handover Request on GERAN-A sends separate IEs for
	 * - permitted algorithms, here composed from the a5_encryption_mask,
	 * - the key, here taken from chosen_encryption->key iff chosen_encryption is present,
	 * - the actually chosen algorithm ("Serving"), here taken from chosen_encryption->alg_id.
	 */
	struct {
		struct gsm0808_channel_type *channel_type;
		uint8_t a5_encryption_mask;
		/*! chosen_encryption->alg_id is in encoded format:
		 * alg_id == 1 means A5/0 i.e. no encryption, alg_id == 4 means A5/3.
		 * alg_id == 0 means no such IE was present. */
		struct geran_encr *chosen_encryption;
	} geran;
	struct gsm0808_cell_id cell_id_serving;
	struct gsm0808_cell_id cell_id_target;

	enum gsm0808_cause bssap_cause;

	bool current_channel_type_1_present;
	uint8_t current_channel_type_1;

	enum gsm0808_permitted_speech speech_version_used;

	const uint8_t *old_bss_to_new_bss_info_raw;
	uint8_t old_bss_to_new_bss_info_raw_len;

	struct osmo_sockaddr_str *rtp_ran_local;

	struct gsm0808_speech_codec_list *codec_list_msc_preferred;

	bool call_id_present;
	uint32_t call_id;

	const uint8_t *global_call_reference;
	uint8_t global_call_reference_len;
};

struct ran_handover_request_ack {
	const uint8_t *rr_ho_command;
	uint8_t rr_ho_command_len;
	bool chosen_channel_present;
	uint8_t chosen_channel;
	/*! chosen_encr_alg is in encoded format:
	 * chosen_encr_alg == 1 means A5/0 i.e. no encryption, chosen_encr_alg == 4 means A5/3.
	 * chosen_encr_alg == 0 means no such IE was present. */
	uint8_t chosen_encr_alg;

	/* chosen_speech_version == 0 means "not present" */
	enum gsm0808_permitted_speech chosen_speech_version;

	struct osmo_sockaddr_str remote_rtp;
	bool codec_present;
	struct gsm0808_speech_codec codec;
	bool codec_with_iuup;
};

struct ran_handover_command {
	const uint8_t *rr_ho_command;
	uint8_t rr_ho_command_len;

	const uint8_t *new_bss_to_old_bss_info_raw;
	uint8_t new_bss_to_old_bss_info_raw_len;
};

struct ran_handover_required {
	uint16_t cause;
	struct gsm0808_cell_id_list2 cil;

	bool current_channel_type_1_present;
	/*! See gsm0808_chosen_channel() */
	uint8_t current_channel_type_1;

	enum gsm0808_permitted_speech speech_version_used;

	uint8_t *old_bss_to_new_bss_info_raw;
	size_t old_bss_to_new_bss_info_raw_len;
};

struct ran_msg {
	enum ran_msg_type msg_type;

	/* Since different RAN implementations feed these messages, they should place here an implementation specific
	 * string constant to name the actual message (e.g. "BSSMAP Assignment Complete" vs. "RANAP RAB Assignment
	 * Response") */
	const char *msg_name;

	union {
		struct {
			const struct gsm0808_cell_id *cell_id;
			const struct gsm0808_speech_codec_list *codec_list_bss_supported;
			struct msgb *msg;
		} compl_l3;
		struct msgb *dtap;
		struct {
			enum gsm0808_cause bssap_cause;
#define RAN_MSG_BSSAP_CAUSE_UNSET 0xffff
		} clear_request;
		struct ran_clear_command clear_command;
		struct {
			const struct osmo_gsm48_classmark *classmark;
		} classmark_update;
		struct ran_cipher_mode_command cipher_mode_command;
		struct {
			/*! alg_id is in encoded format:
			 * alg_id == 1 means A5/0 i.e. no encryption, alg_id == 4 means A5/3.
			 * alg_id == 0 means no such IE was present. */
			uint8_t alg_id;
			/*! utran integrity protection. 0..15 */
			int16_t utran_integrity;
			/*! utran_integrity is in encoded format:
			 *  utran_integrity == -1 means no such IE was present
			 *  utran_integrity == 0 means no encryption. */
			int16_t utran_encryption;
			const char *imeisv;
			const struct tlv_p_entry *l3_msg;
		} cipher_mode_complete;
		struct {
			enum gsm0808_cause bssap_cause;
		} cipher_mode_reject;
		struct {
			const char *imsi;
			bool last_eutran_plmn_present;
			struct osmo_plmn_id last_eutran_plmn;
		} common_id;
		struct {
			enum gsm48_reject_value cause;
		} cm_service_reject;
		struct ran_assignment_command assignment_command;
		struct {
			struct osmo_sockaddr_str remote_rtp;
			bool codec_present;
			struct gsm0808_speech_codec codec;
			bool codec_with_iuup;
			const struct gsm0808_speech_codec_list *codec_list_bss_supported;
			bool osmux_present;
			uint8_t osmux_cid;
		} assignment_complete;
		struct {
			enum gsm0808_cause bssap_cause;
			uint8_t rr_cause;
			const struct gsm0808_speech_codec_list *scl_bss_supported;
		} assignment_failure;
		struct {
			enum gsm0808_cause bssap_cause;
			uint8_t dlci;
		} sapi_n_reject;
		struct {
			enum gsm0808_lcls_status status;
		} lcls_status;
		struct {
			int todo;
		} lcls_break_req;
		struct ran_handover_required handover_required;
		struct gsm0808_handover_required_reject handover_required_reject;
		struct ran_handover_command handover_command;
		struct {
			enum gsm0808_cause cause;
		} handover_failure;
		struct ran_handover_request handover_request;
		struct ran_handover_request_ack handover_request_ack;
		struct gsm0808_vgcs_vbs_setup vgcs_vbs_setup;
		struct gsm0808_vgcs_vbs_setup_ack vgcs_vbs_setup_ack;
		struct {
			enum gsm0808_cause cause;
		} vgcs_vbs_setup_refuse;
		struct gsm0808_vgcs_vbs_assign_req vgcs_vbs_assign_req;
		struct gsm0808_vgcs_vbs_assign_res vgcs_vbs_assign_res;
		struct gsm0808_vgcs_vbs_assign_fail vgcs_vbs_assign_fail;
		struct gsm0808_uplink_request uplink_request;
		struct gsm0808_uplink_request_ack uplink_request_ack;
		struct gsm0808_uplink_request_cnf uplink_request_cnf;
		struct gsm0808_uplink_app_data uplink_app_data;
		struct gsm0808_uplink_release_ind uplink_release_ind;
		struct gsm0808_uplink_seized_cmd uplink_seized_cmd;
		struct gsm0808_uplink_reject_cmd uplink_reject_cmd;
		struct {
			enum gsm0808_cause cause;
		} uplink_release_cmd;
		struct {
			struct gsm0808_talker_identity talker_identity;
		} vgcs_additional_info;
		struct gsm0808_vgcs_vbs_area_cell_info vgcs_vbs_area_cell_info;
		struct gsm0808_vgcs_vbs_assign_stat vgcs_vbs_assign_stat;
		struct {
			struct gsm0808_sms_to_vgcs sms_to_vgcs;
		} vgcs_sms;
		struct gsm0808_notification_data notification_data;
	};
};

/* MSC-A/I/T roles implement this to receive decoded NAS messages, upon feeding an L2 msgb to a ran_dec_l2_t matching the
 * RAN type implementation. */
typedef int (* ran_decode_cb_t )(struct osmo_fsm_inst *caller_fi, void *caller_data, const struct ran_msg *msg);

struct ran_dec {
	/* caller provided osmo_fsm_inst, used both for logging from within decoding of NAS events, as well as caller's
	 * context in decode_cb(). */
	struct osmo_fsm_inst *caller_fi;
	void *caller_data;

	/* Callback receives the decoded NAS messages */
	ran_decode_cb_t decode_cb;
};

/* NAS decoders (BSSAP/RANAP) implement this to turn a msgb into a struct ran_msg.
 * An implementation typically calls ran_decoded() when done decoding.
 * NAS decoding is modeled with a callback instead of a plain decoding, because some L2 messages by design contain more
 * than one NAS event, e.g. Ciphering Mode Complete may include another L3 message for Identity Response, and LCLS
 * Information messages can contain Status and Break Req events. */
typedef int (* ran_dec_l2_t )(struct ran_dec *ran_dec, struct msgb *l2);

int ran_decoded(struct ran_dec *ran_dec, struct ran_msg *msg);

/* An MSC-A/I/T role that receives NAS events containing DTAP buffers may use this to detect DTAP duplicates as in TS
 * 24.007 11.2.3.2 Message Type Octet / Duplicate Detection */
bool ran_dec_dtap_undup_is_duplicate(struct osmo_fsm_inst *log_fi, uint8_t *n_sd_next, bool is_r99, struct msgb *l3);

/* Implemented by individual RAN implementations, see ran_a_encode() and ran_iu_encode(). */
typedef struct msgb *(* ran_encode_t )(struct osmo_fsm_inst *caller_fi, const struct ran_msg *ran_enc_msg);
