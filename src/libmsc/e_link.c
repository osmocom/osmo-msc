/* E-interface messaging over a GSUP connection */
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

#include <osmocom/core/fsm.h>
#include <osmocom/gsupclient/gsup_client.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsup_client_mux.h>
#include <osmocom/msc/e_link.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_a_remote.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/msc_i_remote.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/msc_t_remote.h>

#define LOG_E_LINK(e_link, level, fmt, args...) \
	LOGPFSML(e_link->msc_role, level, fmt, ##args)

#define LOG_E_LINK_CAT(e_link, ss, level, fmt, args...) \
	LOGPFSMSL(e_link->msc_role, ss, level, fmt, ##args)

void e_link_assign(struct e_link *e, struct osmo_fsm_inst *msc_role)
{
	struct msc_role_common *c;
	if (e->msc_role) {
		c = e->msc_role->priv;
		if (c->remote_to == e) {
			c->remote_to = NULL;
			msub_update_id(c->msub);
		}
	}

	c = msc_role->priv;
	e->msc_role = msc_role;
	c->remote_to = e;

	msub_update_id(c->msub);
	LOG_E_LINK(e, LOGL_DEBUG, "Assigned E-link to %s\n", e_link_name(e));
}

struct e_link *e_link_alloc(struct gsup_client_mux *gcm, struct osmo_fsm_inst *msc_role,
			    const uint8_t *remote_name, size_t remote_name_len)
{
	struct e_link *e;
	struct msc_role_common *c = msc_role->priv;
	size_t use_len;

	/* use msub as talloc parent, so we can move an e_link from msc_t to msc_i when it is established. */
	e = talloc_zero(c->msub, struct e_link);
	if (!e)
		return NULL;

	e->gcm = gcm;

	/* FIXME: this is a braindamaged duality of char* and blob, which we can't seem to get rid of easily.
	 * See also osmo-hlr change I01a45900e14d41bcd338f50ad85d9fabf2c61405 which resolved this on the
	 * osmo-hlr side, but was abandoned. Not sure which way is the right solution. */
	/* To be able to include a terminating NUL character when sending the IPA name, append one if there is none yet.
	 * Current osmo-hlr needs the terminating NUL to be included. */
	use_len = remote_name_len;
	if (remote_name[use_len-1] != '\0')
		use_len++;
	e->remote_name = talloc_size(e, use_len);
	OSMO_ASSERT(e->remote_name);
	memcpy(e->remote_name, remote_name, remote_name_len);
	e->remote_name[use_len-1] = '\0';
	e->remote_name_len = use_len;

	e_link_assign(e, msc_role);
	return e;
}

void e_link_free(struct e_link *e)
{
	if (!e)
		return;
	if (e->msc_role) {
		struct msc_role_common *c = e->msc_role->priv;
		if (c->remote_to == e)
			c->remote_to = NULL;
	}
	talloc_free(e);
}

/* Set up IMSI, source and destination names in given gsup_msg struct. */
int e_prep_gsup_msg(struct e_link *e, struct osmo_gsup_message *gsup_msg)
{
	struct msc_role_common *c;
	struct vlr_subscr *vsub;
	const char *local_msc_name = NULL;

	if (e->gcm && e->gcm->gsup_client && e->gcm->gsup_client->ipa_dev) {
		local_msc_name = e->gcm->gsup_client->ipa_dev->serno;
		if (!local_msc_name)
			local_msc_name = e->gcm->gsup_client->ipa_dev->unit_name;
	}

	if (!local_msc_name) {
		LOG_E_LINK(e, LOGL_ERROR, "Cannot prep E-interface GSUP message: no local MSC name defined\n");
		return -ENODEV;
	}

	c = e->msc_role->priv;
	vsub = c->msub->vsub;
	*gsup_msg = (struct osmo_gsup_message){
		.message_class = OSMO_GSUP_MESSAGE_CLASS_INTER_MSC,
		.source_name = (const uint8_t*)local_msc_name,
		.source_name_len = strlen(local_msc_name)+1, /* include terminating nul */
		.destination_name = (const uint8_t*)e->remote_name,
		.destination_name_len = e->remote_name_len, /* the nul here is also included, from e_link_alloc() */
	};

	if (vsub)
		OSMO_STRLCPY_ARRAY(gsup_msg->imsi, vsub->imsi);
	return 0;
}

int e_tx(struct e_link *e, const struct osmo_gsup_message *gsup_msg)
{
	LOG_E_LINK_CAT(e, DLGSUP, LOGL_DEBUG, "Tx GSUP %s to %s\n",
		       osmo_gsup_message_type_name(gsup_msg->message_type),
		       e_link_name(e));
	return gsup_client_mux_tx(e->gcm, gsup_msg);
}

const char *e_link_name(struct e_link *e)
{
       return osmo_escape_str((const char*)e->remote_name, e->remote_name_len);
}

static struct msub *msc_new_msc_t_for_handover_request(struct gsm_network *net,
						       const struct osmo_gsup_message *gsup_msg)
{
	struct ran_infra *ran;
	struct msub *msub;
	struct msc_a *msc_a;
	struct vlr_subscr *vsub;

	switch (gsup_msg->an_apdu.access_network_proto) {
	case OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_48006:
		ran = &msc_ran_infra[OSMO_RAT_GERAN_A];
		break;
	case OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_25413:
		ran = &msc_ran_infra[OSMO_RAT_UTRAN_IU];
		break;
	default:
		ran = NULL;
		break;
	}

	if (!ran || !ran->ran_dec_l2) {
		LOGP(DLGSUP, LOGL_ERROR, "Cannot handle AN-proto %s\n",
		     an_proto_name(gsup_msg->an_apdu.access_network_proto));
		return NULL;
	}

	msub = msub_alloc(net);

	/* To properly compose GSUP messages going back to the remote peer, make sure the incoming IMSI is set in a
	 * vlr_subscr associated with the msub. */
	vsub = vlr_subscr_find_or_create_by_imsi(net->vlr, gsup_msg->imsi, __func__, NULL);
	msub_set_vsub(msub, vsub);
	vlr_subscr_put(vsub, __func__);

	LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "New subscriber for incoming inter-MSC Handover Request\n");

	msc_a = msc_a_remote_alloc(msub, ran, gsup_msg->source_name, gsup_msg->source_name_len);
	if (!msc_a) {
		osmo_fsm_inst_term(msub->fi, OSMO_FSM_TERM_REQUEST, NULL);
		return NULL;
	}

	LOG_MSC_A_REMOTE_CAT(msc_a, DLGSUP, LOGL_DEBUG, "New subscriber for incoming inter-MSC Handover Request\n");
	return msub;
}

static bool name_matches(const uint8_t *name, size_t len, const uint8_t *match_name, size_t match_len)
{
	if (!match_name)
		return !name || !len;
	if (len != match_len)
		return false;
	return memcmp(name, match_name, len) == 0;
}

static bool e_link_matches_gsup_msg_source_name(const struct e_link *e, const struct osmo_gsup_message *gsup_msg)
{
	return name_matches(gsup_msg->source_name, gsup_msg->source_name_len, e->remote_name, e->remote_name_len);
}

static int msc_a_i_t_gsup_rx(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *gsup_msg)
{
	struct gsm_network *net = data;
	struct vlr_instance *vlr = net->vlr;
	struct vlr_subscr *vsub;
	struct msub *msub;
	struct osmo_fsm_inst *msc_role = NULL;
	struct e_link *e;
	struct msc_role_common *c;
	int i;

	OSMO_ASSERT(net);

	vsub = vlr_subscr_find_by_imsi(vlr, gsup_msg->imsi, __func__);
	if (vsub)
		LOGP(DLGSUP, LOGL_DEBUG, "Found VLR entry for IMSI %s\n", gsup_msg->imsi);

	msub = msub_for_vsub(vsub);
	if (msub)
		LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "Found already attached subscriber for IMSI %s\n",
			     gsup_msg->imsi);

	if (vsub) {
		vlr_subscr_put(vsub, __func__);
		vsub = NULL;
	}

	/* Only for an incoming Handover Request: create a new remote-MSC-A as proxy for the MSC-A that is sending the
	 * Handover Request */
	if (!msub && gsup_msg->message_type == OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST) {
		msub = msc_new_msc_t_for_handover_request(net, gsup_msg);
	}

	if (!msub) {
		LOGP(DLGSUP, LOGL_ERROR, "%s: Cannot find subscriber for IMSI %s\n",
		     __func__, osmo_quote_str(gsup_msg->imsi, -1));
		return -EINVAL;
	}

	LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "Rx GSUP %s\n", osmo_gsup_message_type_name(gsup_msg->message_type));

	e = NULL;
	for (i = 0; i < ARRAY_SIZE(msub->role); i++) {
		msc_role = msub->role[i];
		if (!msc_role) {
			LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "No %s\n", msc_role_name(i));
			continue;
		}
		c = msc_role->priv;
		if (!c->remote_to) {
			LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "%s has no remote\n", msc_role_name(i));
			continue;
		}
		if (!e_link_matches_gsup_msg_source_name(c->remote_to, gsup_msg)) {
			LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG, "%s has remote to mismatching %s\n", msc_role_name(i),
				     c->remote_to->remote_name);
			continue;
		}
		/* Found a match. */
		e = c->remote_to;
		break;
	}

	if (!e) {
		LOG_MSUB_CAT(msub, DLGSUP, LOGL_ERROR,
			     "There is no E link that matches: Rx GSUP %s from %s\n",
			     osmo_gsup_message_type_name(gsup_msg->message_type),
			     osmo_quote_str((const char*)gsup_msg->source_name, gsup_msg->source_name_len));
		return -EINVAL;
	}

	LOG_MSUB_CAT(msub, DLGSUP, LOGL_DEBUG,
		     "Rx GSUP %s from %s %s\n",
		     osmo_gsup_message_type_name(gsup_msg->message_type),
		     msc_role_name(c->role),
		     e_link_name(e));

	return osmo_fsm_inst_dispatch(msc_role, MSC_REMOTE_EV_RX_GSUP, (void*)gsup_msg);
}

void msc_a_i_t_gsup_init(struct gsm_network *net)
{
	OSMO_ASSERT(net->gcm);
	OSMO_ASSERT(net->vlr);

	net->gcm->rx_cb[OSMO_GSUP_MESSAGE_CLASS_INTER_MSC] = (struct gsup_client_mux_rx_cb){
		.func = msc_a_i_t_gsup_rx,
		.data = net,
	};
}

int gsup_msg_assign_an_apdu(struct osmo_gsup_message *gsup_msg, struct an_apdu *an_apdu)
{
	if (!an_apdu) {
		LOGP(DLGSUP, LOGL_ERROR, "Cannot assign NULL AN-APDU\n");
		return -EINVAL;
	}

	gsup_msg->an_apdu = (struct osmo_gsup_an_apdu){
		.access_network_proto = an_apdu->an_proto,
	};

	if (an_apdu->msg) {
		gsup_msg->an_apdu.data = msgb_l2(an_apdu->msg);
		gsup_msg->an_apdu.data_len = msgb_l2len(an_apdu->msg);
		if (!gsup_msg->an_apdu.data || !gsup_msg->an_apdu.data_len) {
			LOGP(DLGSUP, LOGL_ERROR, "Cannot assign AN-APDU without msg->l2 to GSUP message: %s\n",
			     msgb_hexdump(an_apdu->msg));
			return -EINVAL;
		}
	}

	/* We are composing a struct osmo_gsup_msg from the osmo-msc internal struct an_apdu. The an_apdu may contain
	 * additional info in form of a partly filled an_apdu->e_info. Make sure that data ends up in the resulting full
	 * osmo_gsup_message. */
	if (an_apdu->e_info) {
		const struct osmo_gsup_message *s = an_apdu->e_info;

		gsup_msg->msisdn_enc = s->msisdn_enc;
		gsup_msg->msisdn_enc_len = s->msisdn_enc_len;

		if (s->cause_rr_set) {
			gsup_msg->cause_rr = s->cause_rr;
			gsup_msg->cause_rr_set = true;
		}
		if (s->cause_bssap_set) {
			gsup_msg->cause_bssap = s->cause_bssap;
			gsup_msg->cause_bssap_set = true;
		}
		if (s->cause_sm)
			gsup_msg->cause_sm = s->cause_sm;
	}
	return 0;
}

/* Allocate a new msgb to contain the gsup_msg->an_apdu's data as l2h.
 * The msgb will have sufficient headroom to be passed down a RAN peer's SCCP user SAP. */
struct msgb *gsup_msg_to_msgb(const struct osmo_gsup_message *gsup_msg)
{
	struct msgb *pdu;
	const uint8_t *pdu_data = gsup_msg->an_apdu.data;
	uint8_t pdu_len = gsup_msg->an_apdu.data_len;

	if (!pdu_data || !pdu_len)
		return NULL;

	/* Strictly speaking this is not limited to BSSMAP, but why not just use those sizes. */
	pdu = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, "AN-APDU from gsup_msg");

	pdu->l2h = msgb_put(pdu, pdu_len);
	memcpy(pdu->l2h, pdu_data, pdu_len);
	return pdu;
}

/* Compose a struct an_apdu from the data found in gsup_msg.  gsup_msg_to_msgb() is used to wrap the data in a static
 * msgb, so the returned an_apdu->msg must be freed if not NULL. */
void gsup_msg_to_an_apdu(struct an_apdu *an_apdu, const struct osmo_gsup_message *gsup_msg)
{
	*an_apdu = (struct an_apdu){
		.an_proto = gsup_msg->an_apdu.access_network_proto,
		.msg = gsup_msg_to_msgb(gsup_msg),
		.e_info = gsup_msg,
	};
}
