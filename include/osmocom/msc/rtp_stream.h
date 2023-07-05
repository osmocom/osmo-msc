#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/sdp_msg.h>

struct gsm_trans;

struct osmo_fsm_inst;
struct call_leg;
struct osmo_mgcpc_ep;
struct osmo_mgcpc_ep_ci;

enum rtp_direction {
	RTP_TO_RAN,
	RTP_TO_CN,
};

extern const struct value_string rtp_direction_names[];
static inline const char *rtp_direction_name(enum rtp_direction val)
{ return get_value_string(rtp_direction_names, val); }

/* A single bidirectional RTP hop between remote and MGW's local RTP port. */
struct rtp_stream {
	struct osmo_fsm_inst *fi;
	uint32_t event_avail;
	uint32_t event_estab;
	enum rtp_direction dir;

	uint32_t call_id;

	/* Backpointer for callers (optional) */
	struct gsm_trans *for_trans;

	struct osmo_sockaddr_str local;
	struct osmo_sockaddr_str remote;
	bool remote_sent_to_mgw;

	bool codecs_known;
	struct sdp_audio_codecs codecs;
	bool codecs_sent_to_mgw;

	struct osmo_mgcpc_ep_ci *ci;

	enum mgcp_connection_mode crcx_conn_mode;
	bool mode_sent_to_mgw;

	/* configured to use Osmux */
	bool use_osmux;
	/* Allocated by our MGW, negative means invalid, not yet known */
	int local_osmux_cid;
	/* Allocated by BSC MGW, negative means invalid, not yet known */
	int remote_osmux_cid;
	 /* Whether remote_osmux_cid has been communicated to MGW */
	bool remote_osmux_cid_sent_to_mgw;
};

#define RTP_STREAM_FMT "local=" RTP_IP_PORT_FMT ",remote=" RTP_IP_PORT_FMT
#define RTP_STREAM_ARGS(RS) RTP_IP_PORT_ARGS(&(RS)->local), RTP_IP_PORT_ARGS(&(RS)->remote),

struct rtp_stream *rtp_stream_alloc(struct osmo_fsm_inst *parent_fi, uint32_t event_gone, uint32_t event_avail,
				    uint32_t event_estab, enum rtp_direction dir, uint32_t call_id,
				    struct gsm_trans *for_trans);

int rtp_stream_ensure_ci(struct rtp_stream *rtps, struct osmo_mgcpc_ep *at_endpoint);
int rtp_stream_do_mdcx(struct rtp_stream *rtps);

bool rtp_stream_set_codecs_from_mgcp_codec(struct rtp_stream *rtps, enum mgcp_codecs codec);
void rtp_stream_set_one_codec(struct rtp_stream *rtps, const struct sdp_audio_codec *codec);
void rtp_stream_set_codecs(struct rtp_stream *rtps, const struct sdp_audio_codecs *codecs);
void rtp_stream_set_mode(struct rtp_stream *rtps, enum mgcp_connection_mode mode);
void rtp_stream_set_remote_addr(struct rtp_stream *rtps, const struct osmo_sockaddr_str *r);
void rtp_stream_set_remote_addr_and_codecs(struct rtp_stream *rtps, const struct sdp_msg *sdp);
void rtp_stream_set_remote_osmux_cid(struct rtp_stream *rtps, uint8_t osmux_cid);
int rtp_stream_commit(struct rtp_stream *rtps);

void rtp_stream_release(struct rtp_stream *rtps);

bool rtp_stream_is_established(struct rtp_stream *rtps);
