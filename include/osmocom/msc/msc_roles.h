#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/msc/msc_common.h>
#include <osmocom/msc/ran_infra.h>

/* Each subscriber connection is managed by different roles, as described in 3GPP TS 49.008 '4.3 Roles of MSC-A, MSC-I
 * and MSC-T':
 *
 * MSC-A: subscriber management and control of all transactions (CC, SMS, USSD,...)
 * MSC-I: "internal": the actual BSSMAP link to the BSS, or RANAP link to the RNC.
 * MSC-T: "transitory": a new pending RAN link to a BSS or RNC, while handover is in progress.
 *        MSC-T becomes the new MSC-I once handover ends successfully.
 *
 * Without inter-MSC handover involved, all of the roles are managed by a single MSC instance.  During inter-MSC
 * handover negotiation, an MSC-T is set up at a remote MSC while MSC-A remains in the original MSC, and when handover
 * concludes successfully, the remote MSC-T becomes the new remote MSC-I, replacing the local MSC-I role.
 *
 * Furthermore, the 3GPP specs use the following terms for naming MSC locations: MSC-A, MSC-B and MSC-B', as well as BSS
 * or BSS-A, BSS-B and BSS-B':
 *
 * MSC-A: the first MSC the subscriber connected to.
 * MSC-B: a remote MSC (if any).
 * MSC-B': another remote MSC (if any, during Subsequent Handover).
 *
 * The full role assignments are spelled out in 3GPP TS 29.002.
 *
 * In Osmocom, the MAP protocol spoken between the MSCs is modeled using GSUP instead.
 *
 * Here are some diagrams of the lifecycle of a single subscriber's MSC-A,-I,-T roles at the locations MSC-A, MSC-B and
 * MSC-B'.
 *
 * Initially:
 *
 *             [MSC-A]
 *      BSS <-> MSC-I
 *
 * Then during inter-MSC handover negotiation:
 *
 *             [MSC-A] <-MAP-> MSC-B
 *      BSS <-> MSC-I          MSC-T <-> new BSS
 *
 * and when successful:
 *
 *             [MSC-A] <-MAP-> MSC-B
 *                             MSC-I <-> BSS
 *
 * Additional subsequent handover:
 *
 *             [MSC-A] <-MAP-> MSC-B
 *               ^             MSC-I <-> BSS
 *               |
 *               +-------MAP-> MSC-B'
 *                             MSC-T <-> new BSS
 *
 * (Here, quote, MSC-A "shall act as the target BSS towards the MSC-I and as the MSC towards the MSC-T.")
 * and when successful:
 *
 *             [MSC-A]
 *               ^
 *               |
 *               +-------MAP-> MSC-B 
 *                             MSC-I <-> BSS
 *
 * Subsequent handover back to the original MSC:
 *
 *             [MSC-A] <-MAP-> MSC-B
 *  new BSS <-> MSC-T          MSC-I <-> BSS
 *
 * and then
 *             [MSC-A]
 *      BSS <-> MSC-I
 *
 *
 * Inter-BSC Handover is just a special case of inter-MSC Handover, where the same MSC-A takes on both MSC-I and MSC-T
 * roles:
 *
 *             [MSC-A]
 *      BSS <-> MSC-I
 *  new BSS <-> MSC-T
 *
 * The mechanism to take on different roles is implemented by different FSM instances. Each FSM kind has one
 * implementation that acts locally, and another implementation to forward to a remote MSC. For example, in this
 * scenario:
 *
 *             [MSC-A] <-MAP-> MSC-B
 *                             MSC-I <-> BSS
 *
 * the implementation is
 *
 *     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a <-> msc_i_REMOTE <---GSUP---> msc_a_REMOTE <-> msc_i <--BSSMAP--> [BSS]
 *
 * MSC-A has a locally acting msc_a FSM implementation. The msc_i FSM implementation at MSC-A receives signals from the
 * msc_a FSM and "merely" sends the MAP instructions to MSC-B.
 *
 * At MSC-B, in turn, the msc_a FSM's "remote" implementation receives the MAP messages and dispatches according events
 * to the MSC-B's local msc_i FSM instance, which is implemented to directly act towards the BSS.
 *
 * To implement single-MSC operation, we have the separate MSC roles' local implementations on the same MSC instance
 * instead of forwarding.
 *
 *
 * Use of MAP procedures on GSUP towards HLR:
 *
 * The MSC <-> VLR communication does still happen locally in the MSC-A only. In other words, there may be MAP message
 * handling between the MSCs (in the form of GSUP), but no MAP to talk to our internal VLR.
 *
 * From the VLR to the HLR, though, we again use GSUP for subscriber related HLR operations such as LU requesting and
 * retrieving auth tokens.
 *
 * To complete the picture, the MSC-A <--GSUP--> MSC-B forwarding happens over the same GSUP connection
 * as the VLR <--GSUP--> HLR link:
 *
 *    OsmoMSC
 *      MSC-A <----------E-interface--->+--GSUP--> [IPA routing] ----E--> MSC-B
 *       ^                              ^          (in osmo-hlr) \
 *       | (internal API)              /                          \--D--> HLR
 *       v                            /
 *      VLR <------------D-interface-/
 */

struct inter_msc_link;
struct ran_conn;

enum msc_role {
	MSC_ROLE_A,
	MSC_ROLE_I,
	MSC_ROLE_T,

	MSC_ROLES_COUNT
};

extern const struct value_string msc_role_names[];
static inline const char *msc_role_name(enum msc_role role)
{ return get_value_string(msc_role_names, role); }


enum msc_common_events {
	/* Explicitly start with 0 (first real event will be -1 + 1 = 0). */
	OFFSET_MSC_COMMON_EV = -1,

	MSC_REMOTE_EV_RX_GSUP,

	MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE,
	MSC_EV_CALL_LEG_RTP_COMPLETE,
	MSC_EV_CALL_LEG_RTP_RELEASED,
	MSC_EV_CALL_LEG_TERM,

	/* MNCC has told us to RTP_CREATE, but local RTP port has not yet been set up.
	 * The MSC role should respond by calling mncc_set_rtp_stream() */
	MSC_MNCC_EV_NEED_LOCAL_RTP,
	MSC_MNCC_EV_CALL_PROCEEDING,
	MSC_MNCC_EV_CALL_COMPLETE,
	MSC_MNCC_EV_CALL_ENDED,

	LAST_MSC_COMMON_EV,
};


/* The events that the msc_a_local and msc_a_remote FSM implementations can receive,
 * according to specifications. Not all of these are necessarily implemented. */
enum msc_a_events {
	OFFSET_MSC_A_EV = LAST_MSC_COMMON_EV - 1,

	/* Establishing Layer 3 happens only at MSC-A (all-local MSC). To distinguish from the inter-MSC DTAP
	 * forwarding, keep this as a separate event. */
	MSC_A_EV_FROM_I_COMPLETE_LAYER_3,

	/* In inter-MSC situations, DTAP is forwarded transparently in AN-APDU IEs (formerly named
	 * BSS-APDU); see
	 * - 3GPP TS 49.008 4.2 'Transfer of DTAP and BSSMAP layer 3 messages on the * E-interface',
	 * - 3GPP TS 29.010 4.5.4 'BSSAP Messages transfer on E-Interface',
	 * - 3GPP TS 29.002 8.4.3 MAP_PROCESS_ACCESS_SIGNALLING service, 8.4.4 MAP_FORWARD_ACCESS_SIGNALLING service.
	 *
	 *   MSC-B ---DTAP--> MSC-A  MAP PROCESS ACCESS SIGNALLING request
	 *   MSC-B <--DTAP--- MSC-A  MAP FORWARD ACCESS SIGNALLING request
	 *   (where neither will receive a "response")
	 *
	 * See 3GPP TS 49.008 6. 'BSSMAP messages transferred on the E-interface'.
	 * Depending on the RAN, the AN-APDU contains a BSSMAP or a RANAP encoded message.
	 * MSC-I to MSC-A:
	 * - Managing attach to one BSC+MSC:
	 *   - CLASSMARK_UPDATE,
	 *   - CIPHER_MODE_COMPLETE,
	 *   - CIPHER_MODE_REJECT,
	 *   - ASSIGNMENT_COMPLETE,
	 *   - ASSIGNMENT_FAILURE,
	 *   - CLEAR_REQUEST,
	 * - Handover related messages:
	 *   - HANDOVER_REQUEST,
	 *   - HANDOVER_PERFORMED,
	 *   - HANDOVER_FAILURE,
	 * - Messages we don't need/support yet:
	 *   - CHANNEL_MODIFY_REQUEST (MSC assisted codec changing handover),
	 *   - SAPI_N_REJECT,
	 *   - CONFUSION,
	 *   - BSS_INVOKE_TRACE,
	 *   - QUEUING_INDICATION,
	 *   - PERFORM_LOCATION_REQUEST (*not* related to a Location Updating, but about passing the MS's geological
	 *     position)
	 *   - PERFORM_LOCATION_ABORT,
	 *   - PERFORM_LOCATION_RESPONSE,
	 *   - CONNECTION_ORIENTED_INFORMATION is listed in 48.008 3.2.1.70 as "(void)",
	 */
	MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST,
	MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST,

	/* See 3GPP TS 29.002 8.4.2 MAP_SEND_END_SIGNAL service. */
	MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST,

	/* These BSSMAP messages are relevant for MSC-T -> MSC-A, i.e. from the transitory during inter-MSC handover:
	 *
	 * - Handover related messages:
	 *   - HANDOVER_REQUEST_ACKNOWLEDGE,
	 *   - HANDOVER_COMPLETE,
	 *   - HANDOVER_FAILURE,
	 *   - HANDOVER_DETECT,
	 *   - CLEAR_REQUEST,
	 * - Messages we don't need/support yet:
	 *   - CONFUSION,
	 *   - QUEUING_INDICATION,
	 */
	MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST,

	/* Essentially the HO Request Ack. 3GPP TS 29.002 8.4.1 MAP_PREPARE_HANDOVER service. */
	MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE,
	MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE,

	/* Done establishing the radio link to the MS, for Handover.
	 * See 3GPP TS 29.002 8.4.2 MAP_SEND_END_SIGNAL service.
	 * Not to be confused with the MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE that tells MSC-B to release. */
	MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST,

	/* gsm_04_08.c has successfully received a valid Complete Layer 3 message, i.e. Location Updating, CM Service
	 * Request, Paging Reponse or IMSI Detach. */
	MSC_A_EV_COMPLETE_LAYER_3_OK,

	/* Received a Classmark Update -- during GERAN ciphering, msc_a may have to wait for Classmark information to
	 * determine supported ciphers. */
	MSC_A_EV_CLASSMARK_UPDATE,

	/* LU or Process Access FSM have determined that the peer has verified its authenticity. */
	MSC_A_EV_AUTHENTICATED,

	/* A valid request is starting to be processed on the connection. Upon this event, msc_a moves from
	 * MSC_A_ST_AUTHENTICATED to MSC_A_ST_COMMUNICATING, and enters the only state without an expiry timeout. */
	MSC_A_EV_TRANSACTION_ACCEPTED,

	/* MSC originated close request, e.g. all done, failed authentication, ... */
	MSC_A_EV_CN_CLOSE,

	/* Subscriber originated close request */
	MSC_A_EV_MO_CLOSE,

	/* msc_a->use_count has reached a total of zero. */
	MSC_A_EV_UNUSED,

	MSC_A_EV_HANDOVER_REQUIRED,
	MSC_A_EV_HANDOVER_END,

	/* indicates nr of MSC_A events, keep this as last enum value */
	LAST_MSC_A_EV
};
osmo_static_assert(LAST_MSC_A_EV <= 32, not_too_many_msc_a_events);

extern const struct value_string msc_a_fsm_event_names[];

enum msc_from_ran_events {
	OFFSET_MSC_EV_FROM_RAN = LAST_MSC_COMMON_EV - 1,

	MSC_EV_FROM_RAN_COMPLETE_LAYER_3,

	/* A BSSMAP/RANAP message came in on the RAN conn. */
	MSC_EV_FROM_RAN_UP_L2,

	/* The RAN connection is gone, or busy going. */
	MSC_EV_FROM_RAN_CONN_RELEASED,

	LAST_MSC_EV_FROM_RAN
};

/* The events that the msc_i_local and msc_i_remote FSM implementations can receive.
 * The MSC-I can also receive all msc_common_events and msc_from_ran_events. */
enum msc_i_events {
	OFFSET_E_MSC_I = LAST_MSC_EV_FROM_RAN - 1,

	/* BSSMAP/RANAP comes in from MSC-A to be sent out on the RAN conn.
	 * Depending on the RAN, the AN-APDU contains a BSSMAP or a RANAP encoded message.
	 * Relevant BSSMAP procedures, see 3GPP TS 49.008 6. 'BSSMAP messages transferred on the E-interface':
	 * - Managing attach to one BSC+MSC:
	 *   - CLASSMARK_REQUEST,
	 *   - CIPHER_MODE_COMMAND,
	 *   - COMMON_ID,
	 *   - ASSIGNMENT_REQUEST,
	 * - Handover related messages:
	 *   - HANDOVER_REQUEST_ACKNOWLEDGE,
	 *   - HANDOVER_FAILURE,
	 * - Messages we don't need/support yet:
	 *   - CONFUSION,
	 *   - MSC_INVOKE_TRACE,
	 *   - QUEUING_INDICATION,
	 *   - LSA_INFORMATION,
	 *   - PERFORM_LOCATION_REQUEST, (*not* related to a Location Updating, but about passing the MS's geological position)
	 *   - PERFORM_LOCATION_ABORT,
	 *   - PERFORM_LOCATION_RESPONSE,
	 *   - CONNECTION_ORIENTED_INFORMATION is listed in 48.008 3.2.1.70 as "(void)"
	 */
	MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST,

	/* MSC-A tells us to release the RAN connection. */
        MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE,

	MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT,
	MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR,

	LAST_MSC_I_EV
};
osmo_static_assert(LAST_MSC_I_EV <= 32, not_too_many_msc_i_events);

extern const struct value_string msc_i_fsm_event_names[];

/* The events that the msc_t_local and msc_t_remote FSM implementations can receive.
 * The MSC-T can also receive all msc_common_events and msc_from_ran_events. */
enum msc_t_events {
	/* sufficient would be to use LAST_MSC_EV_FROM_RAN as offset. But while we have enough numbers
	 * available, it is a good idea to keep MSC-I and MSC-T events separate, to catch errors of
	 * sending wrong event kinds. */
        OFFSET_MSC_T_EV = LAST_MSC_I_EV - 1,

	/* BSSMAP/RANAP comes in from MSC-A to be sent out on the RAN conn.
	 * Relevant BSSMAP procedures, see 3GPP TS 49.008 6. 'BSSMAP messages transferred on the E-interface':
	 * - Handover related messages:
         *   - HANDOVER_REQUEST,
         *   - CLASSMARK_UPDATE, (?)
	 * - Messages we don't need/support yet:
	 *   - CONFUSION,
	 *   - MSC_INVOKE_TRACE,
	 *   - BSS_INVOKE_TRACE,
	 */
	MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST,
	MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST,

	/* MSC originated close request, e.g. all done, failed handover, ... */
	MSC_T_EV_CN_CLOSE,

	/* Subscriber originated close request */
	MSC_T_EV_MO_CLOSE,

	MSC_T_EV_CLEAR_COMPLETE,

	LAST_MSC_T_EV
};
osmo_static_assert(LAST_MSC_T_EV <= 32, not_too_many_msc_t_events);

extern const struct value_string msc_t_fsm_event_names[];

/* All MSC role FSM implementations share this at the start of their fi->priv struct.
 * See struct msc_a, struct msc_i, struct msc_t in their individual headers. */
struct msc_role_common {
	enum msc_role role;

	struct osmo_fsm_inst *fi;

	/* For a local implementation, this is NULL. Otherwise, this identifies how to reach the remote
	 * MSC that this "remote" implementation forwards messages to. */
	struct e_link *remote_to;

	struct msub *msub;
	struct gsm_network *net;
	struct ran_infra *ran;
};

/* AccessNetworkSignalInfo as in 3GPP TS 29.002. */
struct an_apdu {
	/* accessNetworkProtocolId */
	enum osmo_gsup_access_network_protocol an_proto;
	/* signalInfo */
	struct msgb *msg;
	/* If this AN-APDU is sent between MSCs, additional information from the E-interface messaging, like the
	 * Handover Number, will placed/available here. Otherwise may be left NULL. */
	const struct osmo_gsup_message *e_info;
};
