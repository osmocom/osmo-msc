#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/tdef.h>

struct osmo_fsm_inst;
struct osmo_sockaddr_str;
struct osmo_mgcpc_ep;
struct gsm_network;
struct gsm_trans;
struct rtp_stream;
enum rtp_direction;

extern struct osmo_tdef g_mgw_tdefs[];

/* All sides of an MGW endpoint, connecting remote RTP peers via the MGW.
 *
 *     BSC                 MGW                PBX
 *                   CI          CI
 *                   [MGW-endpoint]
 *     [--rtp_stream--]          [--rtp_stream--]
 *     [----------------call_leg----------------]
 *
 */
struct call_leg {
	struct osmo_fsm_inst *fi;

	struct osmo_mgcpc_ep *mgw_endpoint;

	/* Array indexed by enum rtp_direction. */
	struct rtp_stream *rtp[2];
	/* Array indexed by enum rtp_direction. */
	enum mgcp_connection_mode crcx_conn_mode[2];

	uint32_t parent_event_rtp_addr_available;
	uint32_t parent_event_rtp_complete;
	uint32_t parent_event_rtp_released;

	/* For internal MNCC, if RTP addresses for endpoints become assigned by the MGW, implicitly notify the other
	 * call leg's RTP_TO_CN side rtp_stream with rtp_stream_remote_addr_available(). */
	struct call_leg *local_bridge;

	/* Prevent events from deallocating for certain release code paths, to prevent use-after-free problems. */
	bool deallocating;
};

enum call_leg_event {
	CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE,
	CALL_LEG_EV_RTP_STREAM_ESTABLISHED,
	CALL_LEG_EV_RTP_STREAM_GONE,
	CALL_LEG_EV_MGW_ENDPOINT_GONE,
};

void call_leg_init(struct gsm_network *net);

struct call_leg *call_leg_alloc(struct osmo_fsm_inst *parent_fi,
				uint32_t parent_event_term,
				uint32_t parent_event_rtp_addr_available,
				uint32_t parent_event_rtp_complete,
				uint32_t parent_event_rtp_released);

void call_leg_reparent(struct call_leg *cl,
		       struct osmo_fsm_inst *parent_fi,
		       uint32_t parent_event_term,
		       uint32_t parent_event_rtp_addr_available,
		       uint32_t parent_event_rtp_complete,
		       uint32_t parent_event_rtp_released);

int call_leg_local_bridge(struct call_leg *cl1, uint32_t call_id1, struct gsm_trans *trans1,
			  struct call_leg *cl2, uint32_t call_id2, struct gsm_trans *trans2);

int call_leg_ensure_rtp_alloc(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id,
			      struct gsm_trans *for_trans);
int call_leg_ensure_ci(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id, struct gsm_trans *for_trans,
		       const enum mgcp_codecs *codec_if_known, const struct osmo_sockaddr_str *remote_port_if_known);
struct osmo_sockaddr_str *call_leg_local_ip(struct call_leg *cl, enum rtp_direction dir);

void call_leg_rtp_stream_gone(struct call_leg *cl, struct rtp_stream *rtps);
void call_leg_release(struct call_leg *cl);
