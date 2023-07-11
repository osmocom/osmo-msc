/* MSC-A role: main subscriber management */
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
#pragma once

#include <osmocom/core/use_count.h>
#include <osmocom/core/tdef.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/msc_common.h>
#include <osmocom/msc/msc_ho.h>
#include <osmocom/msc/neighbor_ident.h>

struct ran_infra;
struct vgcs_bss;
struct vgcs_bss_cell;

#define MSC_A_USE_LOCATION_UPDATING	"lu"
#define MSC_A_USE_CM_SERVICE_CC	"cm_service_cc"
#define MSC_A_USE_CM_SERVICE_GCC	"cm_service_gcc"
#define MSC_A_USE_CM_SERVICE_BCC	"cm_service_bcc"
#define MSC_A_USE_CM_SERVICE_SMS	"cm_service_sms"
#define MSC_A_USE_CM_SERVICE_SS	"cm_service_ss"
#define MSC_A_USE_PAGING_RESPONSE	"paging-response"
#define MSC_A_USE_GCC		"gcc"
#define MSC_A_USE_BCC		"bcc"
#define MSC_A_USE_CC		"cc"
#define MSC_A_USE_SMS		"sms"
#define MSC_A_USE_SMS_MMTS	"sms_mmts"
#define MSC_A_USE_NC_SS		"nc_ss"
#define MSC_A_USE_SILENT_CALL	"silent_call"

/* These are macros to use the source file:line information from the caller in a trivial way */
#define msc_a_get(msc_a, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&msc_a->use_count, use, 1) == 0)
#define msc_a_put(msc_a, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&msc_a->use_count, use, -1) == 0)
#define msc_a_put_all(msc_a, use) do { \
		int32_t has_count = osmo_use_count_by(&msc_a->use_count, use); \
		if (has_count) \
			OSMO_ASSERT(osmo_use_count_get_put(&msc_a->use_count, use, -has_count) == 0); \
	} while(0)


enum msc_a_action_on_classmark_update_type {
	MSC_A_CLASSMARK_UPDATE_NOT_EXPECTED = 0,
	MSC_A_CLASSMARK_UPDATE_THEN_CIPHERING,
};

/* A Classmark Update might be required for various tasks. At the time of writing, the only use case is to determine A5
 * capabilities for choosing a ciphering algorithm. This structure anticipates other Classmark Update use cases to be
 * added in the future. */
struct msc_a_action_on_classmark_update {
	enum msc_a_action_on_classmark_update_type type;
	union {
		/* State required to resume Ciphering after the Classmark Request / Classmark Update is complete. */
		struct {
			bool umts_aka;
			bool retrieve_imeisv;
		} ciphering;

		/* Add more use cases here... */
	};
};

struct msc_a {
	/* struct msc_role_common must remain at start */
	struct msc_role_common c;
	enum complete_layer3_type complete_layer3_type;
	struct osmo_cell_global_id via_cell;

	/* Temporary storage for Classmark Information for times when a connection has no VLR subscriber
	 * associated yet. It will get copied to the VLR subscriber upon msc_vlr_subscr_assoc(). */
	struct osmo_gsm48_classmark temporary_classmark;

	/* See handling of E_MSC_A_CLASSMARK_UPDATE */
	struct msc_a_action_on_classmark_update action_on_classmark_update;
	uint32_t state_before_classmark_update;

	/* After Ciphering Mode Complete on GERAN, this reflects the chosen ciphering algorithm and key */
	struct geran_encr geran_encr;

	/* Type of MI requested in MM Identity Request */
	uint8_t mm_id_req_type;

	/* N(SD) expected in the received frame, per flow (TS 24.007 11.2.3.2.3.2.2) */
	uint8_t n_sd_next[4];

	/* Call control and MSC-A side of RTP switching. Without inter-MSC handover involved, this manages all of the
	 * MGW and RTP switching; after an inter-MSC handover, the RAN-side of this is redirected via another MNCC
	 * connection to the Handover MSISDN, and a remote MSC-I role takes over RTP switching to the remote BSS.
	 *
	 * Without / before inter-MSC HO:
	 *
	 *     BSS     [MSC-I  MSC-A]    MNCC to PBX
	 *       <--RTP---------> <--RTP-->
	 *
	 * After inter-MSC HO:
	 *
	 *     BSS     [MSC-I  MSC-A]    MNCC to PBX      MSC-I     BSS-B
	 *                   /--> <--RTP-->
	 *                   \-------RTP--> (ISUP) <--RTP--> <--RTP-->
	 */
	struct {
		/* Codec List (BSS Supported) as received during Complete Layer 3 Information */
		struct gsm0808_speech_codec_list compl_l3_codec_list_bss_supported;

		/* All of the RTP stream handling */
		struct call_leg *call_leg;
		struct mncc_call *mncc_forwarding_to_remote_ran;

		/* There may be up to 7 incoming calls for this subscriber. This is the currently serviced voice call,
		 * as in, the other person the subscriber is currently talking to. */
		struct gsm_trans *active_trans;
	} cc;

	struct msc_ho_state ho;

	struct osmo_use_count use_count;
	struct osmo_use_count_entry use_count_buf[8];
	int32_t max_total_use_count;
};

osmo_static_assert(offsetof(struct msc_a, c) == 0, msc_role_common_first_member_of_msc_a);

struct msc_a_ran_dec_data {
	enum msc_role from_role;
	const struct an_apdu *an_apdu;
	const struct ran_msg *ran_dec;
};

#define LOG_MSC_A(MSC_A, LEVEL, FMT, ARGS ...) \
		LOG_MSC_A_CAT(MSC_A, (MSC_A) ? (MSC_A)->c.ran->log_subsys : DMSC, LEVEL, FMT, ## ARGS)
#define LOG_MSC_A_CAT(MSC_A, SUBSYS, LEVEL, FMT, ARGS ...) \
		LOGPFSMSL((MSC_A) ? (MSC_A)->c.fi : NULL, SUBSYS, LEVEL, FMT, ## ARGS)
#define LOG_MSC_A_CAT_SRC(MSC_A, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ARGS ...) \
		LOGPFSMSLSRC((MSC_A) ? (MSC_A)->c.fi : NULL, SUBSYS, LEVEL, SRCFILE, LINE, FMT, ## ARGS)

enum msc_a_states {
	MSC_A_ST_VALIDATE_L3,
	MSC_A_ST_AUTH_CIPH,
	MSC_A_ST_WAIT_CLASSMARK_UPDATE,
	MSC_A_ST_AUTHENTICATED,
	MSC_A_ST_COMMUNICATING,
	MSC_A_ST_RELEASING,
	MSC_A_ST_RELEASED,
};

struct msc_a *msc_a_alloc(struct msub *msub, struct ran_infra *ran);

int msc_a_classmark_request_then_cipher_mode_cmd(struct msc_a *msc_a, bool umts_aka, bool retrieve_imeisv);

bool msc_a_is_establishing_auth_ciph(const struct msc_a *msc_a);
bool msc_a_is_accepted(const struct msc_a *msc_a);
bool msc_a_in_release(struct msc_a *msc_a);

struct gsm_network *msc_a_net(const struct msc_a *msc_a);
struct vlr_subscr *msc_a_vsub(const struct msc_a *msc_a);
struct msc_i *msc_a_msc_i(const struct msc_a *msc_a);
struct msc_t *msc_a_msc_t(const struct msc_a *msc_a);

struct msc_a *msc_a_for_vsub(const struct vlr_subscr *vsub, bool valid_conn_only);

void msc_a_pending_cm_service_req_add(struct msc_a *msc_a, enum osmo_cm_service_type type);
unsigned int msc_a_pending_cm_service_req_count(struct msc_a *msc_a, enum osmo_cm_service_type type);
void msc_a_pending_cm_service_req_del(struct msc_a *msc_a, enum osmo_cm_service_type type);
bool msc_a_is_ciphering_to_be_attempted(const struct msc_a *msc_a);
bool msc_a_is_ciphering_required(const struct msc_a *msc_a);

#define msc_a_ran_down(A,B,C) \
	_msc_a_ran_down(A,B,C, __FILE__, __LINE__)
int _msc_a_ran_down(struct msc_a *msc_a, enum msc_role to_role, const struct ran_msg *ran_enc_msg,
		    const char *file, int line);
#define msc_a_msg_down(A,B,C,D) \
	_msc_a_msg_down(A,B,C,D, __FILE__, __LINE__)
int _msc_a_msg_down(struct msc_a *msc_a, enum msc_role to_role, uint32_t to_role_event,
		    const struct ran_msg *ran_enc_msg,
		    const char *file, int line);

int msc_a_tx_dtap_to_i(struct msc_a *msc_a, struct msgb *dtap);
int msc_a_tx_common_id(struct msc_a *msc_a);
int msc_a_tx_mm_serv_ack(struct msc_a *msc_a);
int msc_a_tx_mm_serv_rej(struct msc_a *msc_a, enum gsm48_reject_value value);

int msc_a_up_l3(struct msc_a *msc_a, struct msgb *msg);

void msc_a_up_ciph_res(struct msc_a *msc_a, bool success, const char *imeisv);

bool msc_a_is_accepted(const struct msc_a *msc_a);
bool msc_a_is_establishing_auth_ciph(const struct msc_a *msc_a);

int msc_a_ensure_cn_local_rtp(struct msc_a *msc_a, struct gsm_trans *cc_trans);
int msc_a_try_call_assignment(struct gsm_trans *cc_trans);

const char *msc_a_cm_service_type_to_use(struct msc_a *msc_a, enum osmo_cm_service_type cm_service_type);

void msc_a_release_cn(struct msc_a *msc_a);
void msc_a_release_mo(struct msc_a *msc_a, enum gsm48_gsm_cause gsm_cause);

int msc_a_rx_vgcs_bss(struct vgcs_bss *bss, struct ran_conn *from_conn, struct msgb *msg);
int msc_a_rx_vgcs_cell(struct vgcs_bss_cell *cell, struct ran_conn *from_conn, struct msgb *msg);

int msc_a_ran_decode_cb(struct osmo_fsm_inst *msc_a_fi, void *data, const struct ran_msg *msg);

int msc_a_vlr_set_cipher_mode(void *_msc_a, bool umts_aka, bool retrieve_imeisv);

struct msgb *msc_a_ran_encode(struct msc_a *msc_a, const struct ran_msg *ran_enc_msg);

void msc_a_update_id(struct msc_a *msc_a);
