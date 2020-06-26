/* The RAN (Radio Access Network) side of an A- or Iu-connection, which is closely tied to an SCCP connection.
 * (as opposed to the NAS side.)
 *
 * The SCCP connection is located with the MSC-I role, while the MSC-A responsible for subscriber management may be at a
 * remote MSC behind an E-interface connection. In that case we need to forward the L2 messages over the E-interface and
 * the BSSAP or RANAP messages get decoded and interpreted at MSC-A.
 *
 * The life cycle of a DTAP message from RAN to MSC-A -- starting from the bottom left:
 *
 *       ------------------>[ 3GPP TS 24.008 ]------------------->|
 *       ^      (Request)                        (Response)       |
 *       |                                                        v
 *      msc_a_up_l3()                                            msc_a_tx_dtap_to_i(dtap_msgb)
 *       ^                                                        |
 *       |                                                        v
 *      msc_a_ran_decode_cb(struct ran_dec_msg)                  msc_a_ran_enc(struct ran_enc_msg)
 *       ^                ^                    .                  |
 *       |  -Decode NAS-  |                       .  NAS          v
 *       |                |                          .           ran_infra[type]->ran_encode(struct ran_enc_msg)
 *      ran_a_decode_l2()    ran_iu_decode_l2()         .         |                      |
 *       ^                ^                                .      v                      v
 *       |                |                                   .  ran_a_encode()    ran_iu_encode()
 *      ran_infra[type]->ran_dec_l2()                             |                      |
 *       ^                                                        | -Encode BSSAP/RANAP- |
 *       |                                                        v                      v
 *      msc_a_ran_dec()                                           msub_tx_an_apdu(from MSC_ROLE_A to MSC_ROLE_I)
 *       ^                                                        |
 *       |                             MSC-A                      v
 *    . msc_a FSM .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  . msc_a FSM .  .  .  .  .  .  .  .  .  .
 *       ^                                                        |
 *       | MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST      v
 *       | data = an_apdu                                       [possibly
 *       |                                                       via GSUP
 *     [possibly                                                 from remote MSC-A]
 *      via GSUP                                                  |
 *      to remote MSC-A]                                          | MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST
 *       ^                                                        | data = an_apdu
 *       |                                                        v
 *    . msc_i FSM .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  . msc_i FSM .  .  .  .  .  .  .  .  .  .
 *       ^                             MSC-I                      |
 *       | MSC_EV_FROM_RAN_UP_L2                                  V
 *       | data = an_apdu                                        msc_i_down_l2(an_apdu->msg)
 *       |                                                        |
 *      ran_peer FSM                                              V
 *       ^                                                       ran_conn_down_l2_co();
 *       | RAN_PEER_EV_MSG_UP_CO                                  |
 *       | data = struct ran_peer_ev_ctx                          | RAN_PEER_EV_MSG_DOWN_CO
 *       |                                                        | data = struct ran_peer_ev_ctx
 *      ran_peer_up_l2()                                          V
 *      (ran_infa->sccp_ran_ops.up_l2)                           ran_peer FSM
 *       ^    ^                                                   |
 *       |    |                                                   v
 *      sccp_ran_sap_up()                                        sccp_ran_down_l2_co(conn_id, msg)
 *       ^    ^                                                   |    |
 *       |    |                                                   |SCCP|
 *       |SCCP|                                                   v    v
 *       |    |  <------------------------------------------------------
 *      BSC  RNC
 *       |    |
 *      BTS  NodeB
 *       |    |
 *       MS   UE
 *
 * sccp_ran:
 * - handles receiving of SCCP primitives from the SCCP layer.
 * - extracts L2 msg
 * - passes on L2 msg and conn_id by calling sccp_ran_ops.up_l2 == ran_peer_up_l2().
 *
 * On Connection-Oriented *Initial* message
 * ========================================
 *
 * ran_peer_up_l2()
 * - notices an unknown, new osmo_rat_type:conn_id and
 * - first creates an "empty" msub with new local MSC-I and MSC-A roles;
 *   in this case always a *local* MSC-A (never remote on Initial messages).
 * - Passes the L2 msgb containing the BSSAP or RANAP as AN-APDU
 *   in MSC_A_EV_FROM_I_COMPLETE_LAYER_3 to the MSC-A role FSM instance.
 *
 * MSC-A:
 * - Receives MSC_A_EV_FROM_I_COMPLETE_LAYER_3 AN-APDU, notices an_proto indicating BSSAP or RANAP.
 * - Passes L2 message to ran_infra[]->ran_dec_l2(), which decodes the BSSAP or RANAP.
 * - contained information is passed to msc_a_ran_decode_cb().
 * - which msc_a starts Complete-L3 and VLR procedures,
 * - associates msub with a vlr_subscr,
 * - sends DTAP requests back down by calling msc_a_tx_dtap_to_i() (possibly other more specialized tx functions)
 * - according to ran_infra[]->ran_encode(), the ran_enc_msg gets encoded as BSSAP or RANAP.
 * - passes as AN-APDU to MSC-I in MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST signal.
 *
 * MSC-I, receiving AN-APDU from local MSC-A:
 * - feeds L2 msgb to the ran_peer FSM as RAN_PEER_EV_MSG_DOWN_CO, passing the SCCP conn_id.
 *
 * sccp_ran_down_l2_co()
 * - wraps in SCCP prim,
 * - sends down.
 *
 *
 * On (non-Initial) Connection-Oriented DTAP
 * =========================================
 *
 * ran_peer_up_l2()
 * - notices an already known conn_id by looking up a matching osmo_rat_type:ran_conn.
 * - ran_conn already associated with an MSC-I role.
 * - Now forwards AN-APDU like above, only using MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST.
 *
 *
 * MSC-A and MSC-I roles on separate MSC instances
 * ===============================================
 *
 * After inter-MSC handover, the MSC-I and MSC-A roles can be on separate MSC instances, typically physically distant /
 * possibly belonging to a different operator. This will never see Complete-L3.
 * Assuming that both instances are osmo-msc, then:
 *
 * At MSC-B:
 *   initially, via GSUP:
 *   - receives Handover Request from remote MSC-A,
 *   - creates msub with local MSC-T role,
 *   - sets up the ran_conn with a new SCCP conn_id, and waits for the MS/UE to show up.
 *   - (fast-forward to successful Handover)
 *   - MSC-T role becomes MSC-I for the remote MSC-A.
 *
 *   Then for DTAP from the MS:
 *
 *   sccp_ran:
 *   - receives SCCP,
 *   - extracts L2 and passes on to ran_peer_up_l2().
 *
 *   ran_peer_up_l2()
 *   - notices an already known conn_id by looking up a matching ran_conn.
 *   - ran_conn already associated with an MSC-I role and an msub.
 *   - forwards AN-APDU in MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST to the MSC-A role.
 *
 *   At MSC-B, the "MSC-A role" is a *remote* implementation,
 *   meaning there is an msc_a_remote FSM instance in MSC-B's msub:
 *
 *   MSC-A-Remote:
 *   - msc_a_remote receives MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST,
 *   - wraps AN-APDU in GSUP message,
 *   - sends to remote MSC-A.
 *
 * At MSC-A:
 *   Here, msub has a *remote* MSC-I role,
 *   meaning it is an msc_i_remote FSM instance:
 *
 *   MSC-I-Remote:
 *   - msc_i_remote receives and decodes GSUP message,
 *   - passes AN-APDU to MSC-A FSM instance via MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST.
 *
 *   MSC-A role:
 *   - Receives MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST, notices an_proto indicating BSSAP or RANAP.
 *   - Passes L2 message to ran_infra[]->ran_dec_l2(), which decodes the BSSAP or RANAP.
 *   - contained information is passed to msc_a_ran_decode_cb().
 *   - sends DTAP requests back down by calling msc_a_tx_dtap_to_i() (possibly other more specialized tx functions)
 *   - according to ran_infra[]->ran_encode(), the ran_enc_msg gets encoded as BSSAP or RANAP.
 *   - passes as AN-APDU to MSC-I in MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST signal.
 *
 *   MSC-I-Remote:
 *   - msc_i_remote wraps AN-APDU in GSUP message,
 *   - sends to MSC-B
 *
 * At MSC-B:
 *   MSC-A-Remote:
 *   - msc_a_remote receives GSUP message,
 *   - passes AN-APDU to msc_i in MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST.
 *
 *   MSC-I:
 *   - BSSAP or RANAP is indicated both by the AN-APDU an_proto, as well as the ran_conn state for that subscriber.
 *   - feeds L2 msgb to the ran_peer FSM as RAN_PEER_EV_MSG_DOWN_CO, passing the SCCP conn_id.
 *
 *   sccp_ran_down_l2_co()
 *   - wraps in SCCP prim,
 *   - sends down.
 *
 */

#pragma once

#include <stdint.h>

#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/msc/paging.h>

struct msgb;
struct ran_infra;
struct sccp_ran_inst;

#define LOG_SCCP_RAN_CO(sri, peer_addr, conn_id, level, fmt, args...) \
	LOGP((sri) && (sri)->ran? (sri)->ran->log_subsys : DMSC, level, "(%s-%u%s%s) " fmt, \
	     osmo_rat_type_name((sri) && (sri)->ran ? (sri)->ran->type : OSMO_RAT_UNKNOWN), conn_id, \
	     peer_addr ? " from " : "", \
	     peer_addr ? osmo_sccp_inst_addr_name((sri)->sccp, peer_addr) : "", \
	     ## args)

#define LOG_SCCP_RAN_CL_CAT(sri, peer_addr, subsys, level, fmt, args...) \
	LOGP(subsys, level, "(%s%s%s) " fmt, \
	     osmo_rat_type_name((sri) && (sri)->ran ? (sri)->ran->type : OSMO_RAT_UNKNOWN), \
	     peer_addr ? " from " : "", \
	     peer_addr ? osmo_sccp_inst_addr_name((sri)->sccp, peer_addr) : "", \
	     ## args)

#define LOG_SCCP_RAN_CL(sri, peer_addr, level, fmt, args...) \
	LOG_SCCP_RAN_CL_CAT(sri, peer_addr, (sri) && (sri)->ran? (sri)->ran->log_subsys : DMSC, level, fmt, ##args)

#define LOG_SCCP_RAN_CAT(sri, subsys, level, fmt, args...) \
	LOG_SCCP_RAN_CL_CAT(sri, NULL, subsys, level, fmt, ##args)

#define LOG_SCCP_RAN(sri, level, fmt, args...) \
	LOG_SCCP_RAN_CL(sri, NULL, level, fmt, ##args)

extern struct osmo_tdef g_sccp_tdefs[];

enum reset_msg_type {
	SCCP_RAN_MSG_NON_RESET = 0,
	SCCP_RAN_MSG_RESET,
	SCCP_RAN_MSG_RESET_ACK,
};

struct sccp_ran_ops {
	/* Implemented to receive L2 messages (e.g. BSSAP or RANAP passed to ran_peer).
	 * - ConnectionLess messages: co = false, calling_addr != NULL, conn_id == 0;
	 * - ConnectionOriented Initial messages: co = true, calling_addr != NULL;
	 * - ConnectionOriented non-Initial messages: co = true, calling_addr == NULL;
	 */
	int (* up_l2 )(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *calling_addr, bool co, uint32_t conn_id,
		       struct msgb *l2);

	/* Implemented to finally remove a connection state. Last event in a connection-oriented exchange. If the
	 * N-DISCONNECT contained l2 data, it was dispatched via up_l2() before this is called. */
	void (* disconnect )(struct sccp_ran_inst *sri, uint32_t conn_id);

	/* Return whether the given l2_cl message is a RESET, RESET ACKNOWLEDGE, or RESET-unrelated message.
	 * This callback is stored in struct sccp_ran_inst to provide RESET handling to the caller (ran_peer),
	 * it is not used in sccp_ran.c.
	 * In supports_osmux, return 0 for no information, 1 for support detected, -1 for non-support detected.
	 */
	enum reset_msg_type (* is_reset_msg )(const struct sccp_ran_inst *sri, struct osmo_fsm_inst *log_fi,
					      struct msgb *l2_cl, int *supports_osmux);

	/* Return a RESET or RESET ACK message for this RAN type.
	 * This callback is stored in struct sccp_ran_inst to provide RESET handling to the caller (ran_peer),
	 * it is not used in sccp_ran.c. */
	struct msgb* (* make_reset_msg )(const struct sccp_ran_inst *sri, enum reset_msg_type);

	/* Return a PAGING message towards the given Cell Identifier, to page for the given TMSI or IMSI.
	 * Page for TMSI if TMSI != GSM_RESERVED_TMSI, otherwise page for IMSI. */
	struct msgb* (* make_paging_msg )(const struct sccp_ran_inst *sri, const struct gsm0808_cell_id *page_cell_id,
					  const char *imsi, uint32_t tmsi, enum paging_cause cause);

	/* Return a human printable name for the msgb */
	const char* (* msg_name )(const struct sccp_ran_inst *sri, const struct msgb *l2);
};

struct sccp_ran_inst {
	struct ran_infra *ran;

	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *scu;
	struct osmo_sccp_addr local_sccp_addr;

	struct llist_head ran_peers;
	struct llist_head ran_conns;

	void *user_data;

	/* Compatibility with legacy osmo-hnbgw that was unable to properly handle RESET messages.  Set to 'false' to
	 * require proper RESET procedures, set to 'true' to implicitly put a ran_peer in RAN_PEER_ST_READY upon the
	 * first CO message. Default is false = be strict. */
	bool ignore_missing_reset;
};

struct sccp_ran_inst *sccp_ran_init(void *talloc_ctx, struct osmo_sccp_instance *sccp, enum osmo_sccp_ssn ssn,
				    const char *sccp_user_name, struct ran_infra *ran, void *user_data);

int sccp_ran_down_l2_co_initial(struct sccp_ran_inst *sri,
				const struct osmo_sccp_addr *called_addr,
				uint32_t conn_id, struct msgb *l2);
int sccp_ran_down_l2_co(struct sccp_ran_inst *sri, uint32_t conn_id, struct msgb *l2);
int sccp_ran_down_l2_cl(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *called_addr, struct msgb *l2);

int sccp_ran_disconnect(struct sccp_ran_inst *ran, uint32_t conn_id, uint32_t cause);
