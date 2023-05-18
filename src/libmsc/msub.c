/* Manage all MSC roles of a connected subscriber (MSC-A, MSC-I, MSC-T) */
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

#include <osmocom/gsm/gsm48.h>

#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/e_link.h>

const struct value_string msc_role_names[] = {
	{ MSC_ROLE_A, "MSC-A" },
	{ MSC_ROLE_I, "MSC-I" },
	{ MSC_ROLE_T, "MSC-T" },
	{}
};

LLIST_HEAD(msub_list);

#define for_each_msub_role(msub, role_idx) \
	for ((role_idx) = 0; (role_idx) < ARRAY_SIZE((msub)->role); (role_idx)++) \
		if ((msub)->role[role_idx])

enum msub_fsm_state {
	MSUB_ST_ACTIVE,
	MSUB_ST_TERMINATING,
};

enum msub_fsm_event {
	MSUB_EV_ROLE_TERMINATED,
};

static void msub_check_for_release(struct osmo_fsm_inst *fi)
{
	struct msub *msub = fi->priv;
	struct msc_role_common *msc_role_a_c = NULL;
	enum msc_role role_idx;
	int role_present[MSC_ROLES_COUNT] = {};
	struct osmo_fsm_inst *child;

	/* See what child FSMs are still present. A caller might exchange roles by first allocating a new one as child
	 * of this FSM, and then exchanging the msub->role[] pointer. Even though the currently active role is removing
	 * itself from msub, we can still see whether another one is pending as a child of this msub. */
	llist_for_each_entry(child, &fi->proc.children, proc.child) {
		struct msc_role_common *c = child->priv;
		role_present[c->role]++;
		if (c->role == MSC_ROLE_A)
			msc_role_a_c = c;
	}

	/* Log. */
	for (role_idx = 0; role_idx < ARRAY_SIZE(role_present); role_idx++) {
		if (!role_present[role_idx])
			continue;
		LOG_MSUB(msub, LOGL_DEBUG, "%d %s still active\n", role_present[role_idx], msc_role_name(role_idx));
	}

	/* To remain valid, there must be both an MSC-A role and one of MSC-I or MSC-T;
	 * except, SGs connections need no MSC-I or MSC-T. */
	if (role_present[MSC_ROLE_A]
	    && (role_present[MSC_ROLE_I] || role_present[MSC_ROLE_T]
		|| (msc_role_a_c && msc_role_a_c->ran->type == OSMO_RAT_EUTRAN_SGS)))
		return;

	/* The subscriber has become invalid. Go to terminating state to clearly signal that this msub is definitely
	 * going now. */
	osmo_fsm_inst_state_chg(fi, MSUB_ST_TERMINATING, 0, 0);
}

void msub_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msub *msub = fi->priv;
	struct osmo_fsm_inst *role_fi;

	switch (event) {
	case MSUB_EV_ROLE_TERMINATED:
		role_fi = data;
		/* Role implementations are required to pass their own osmo_fsm_inst pointer to osmo_fsm_inst_term(). */
		msub_remove_role(msub, role_fi);
		msub_check_for_release(fi);
		return;
	default:
		return;
	}
}

void msub_fsm_terminating_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

void msub_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msub *msub = fi->priv;
	LOG_MSUB(msub, LOGL_DEBUG, "Free\n");
	msub_set_vsub(msub, NULL);
	llist_del(&msub->entry);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msub_fsm_states[] = {
	[MSUB_ST_ACTIVE] = {
		.name = "active",
		.in_event_mask = S(MSUB_EV_ROLE_TERMINATED),
		.out_state_mask = S(MSUB_ST_TERMINATING),
		.action = msub_fsm_active,
	},
	[MSUB_ST_TERMINATING] = {
		.name = "terminating",
		.onenter = msub_fsm_terminating_onenter,
	},
};

static const struct value_string msub_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSUB_EV_ROLE_TERMINATED),
	{}
};

struct osmo_fsm msub_fsm = {
	.name = "msub_fsm",
	.states = msub_fsm_states,
	.num_states = ARRAY_SIZE(msub_fsm_states),
	.log_subsys = DMSC,
	.event_names = msub_fsm_event_names,
	.cleanup = msub_fsm_cleanup,
};

static __attribute__((constructor)) void msub_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&msub_fsm) == 0);
}

struct msc_role_common *_msub_role_alloc(struct msub *msub, enum msc_role role, struct osmo_fsm *role_fsm,
					 size_t struct_size, const char *struct_name, struct ran_infra *ran)
{
	struct osmo_fsm_inst *fi;
	struct msc_role_common *c;

	fi = osmo_fsm_inst_alloc_child(role_fsm, msub->fi, MSUB_EV_ROLE_TERMINATED);
	OSMO_ASSERT(fi);

	c = (struct msc_role_common*)talloc_named_const(fi, struct_size, struct_name);
	OSMO_ASSERT(c);
	memset(c, 0, struct_size);
	fi->priv = c;

	*c = (struct msc_role_common){
		.role = role,
			.fi = fi,
			.ran = ran,
	};

	msub_set_role(msub, fi);
	return c;
}

struct msub *msub_alloc(struct gsm_network *net)
{
	struct msub *msub;
	struct osmo_fsm_inst *msub_fi = osmo_fsm_inst_alloc(&msub_fsm, net, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(msub_fi);

	msub = talloc(msub_fi, struct msub);
	OSMO_ASSERT(msub);
	msub_fi->priv = msub;
	*msub = (struct msub){
		.net = net,
		.fi = msub_fi,
	};

	llist_add_tail(&msub->entry, &msub_list);
	return msub;
}

/* Careful: the subscriber may not yet be authenticated, or may already be in release. Better use
 * msc_a_for_vsub(for_vsub, true) to make sure you don't use an invalid conn. */
struct msub *msub_for_vsub(const struct vlr_subscr *for_vsub)
{
	struct msub *msub;
	if (!for_vsub)
		return NULL;

	llist_for_each_entry(msub, &msub_list, entry) {
		if (msub->vsub == for_vsub)
			return msub;
	}

	return NULL;
}

const char *msub_name(const struct msub *msub)
{
	return vlr_subscr_name(msub? msub->vsub : NULL);
}

void msub_set_role(struct msub *msub, struct osmo_fsm_inst *msc_role)
{
	struct osmo_fsm_inst *prev_role;
	struct msc_role_common *c;

	OSMO_ASSERT(msc_role);
	c = msc_role->priv;

	prev_role = msub->role[c->role];
	if (prev_role)
		LOGPFSML(prev_role, LOGL_DEBUG, "Replaced by another %s\n", msc_role_name(c->role));

	c->msub = msub;
	msub->role[c->role] = msc_role;
	msub_update_id(msub);

	if (prev_role) {
		struct msc_role_common *prev_c = prev_role->priv;
		switch (prev_c->role) {
		case MSC_ROLE_I:
			msc_i_clear(prev_role->priv);
			break;
		case MSC_ROLE_T:
			msc_t_clear(prev_role->priv);
			break;
		default:
			osmo_fsm_inst_term(prev_role, OSMO_FSM_TERM_REQUEST, prev_role);
			break;
		}
	}
}

void msub_remove_role(struct msub *msub, struct osmo_fsm_inst *fi)
{
	enum msc_role idx;
	struct msc_role_common *c;
	if (!msub || !fi)
		return;

	c = fi->priv;
	LOG_MSUB(msub, LOGL_DEBUG, "%s terminated\n", msc_role_name(c->role));

	for_each_msub_role(msub, idx) {
		if (msub->role[idx] == fi)
			msub->role[idx] = NULL;
	}
}

struct msc_a *msub_msc_a(const struct msub *msub)
{
	struct osmo_fsm_inst *fi;
	if (!msub)
		return NULL;
	fi = msub->role[MSC_ROLE_A];
	if (!fi)
		return NULL;
	return (struct msc_a*)fi->priv;
}

struct msc_i *msub_msc_i(const struct msub *msub)
{
	struct osmo_fsm_inst *fi;
	if (!msub)
		return NULL;
	fi = msub->role[MSC_ROLE_I];
	if (!fi)
		return NULL;
	return (struct msc_i*)fi->priv;
}

struct msc_t *msub_msc_t(const struct msub *msub)
{
	struct osmo_fsm_inst *fi;
	if (!msub)
		return NULL;
	fi = msub->role[MSC_ROLE_T];
	if (!fi)
		return NULL;
	return (struct msc_t*)fi->priv;
}

/* Return the ran_conn of the MSC-I role, if available. If the MSC-I role is handled by a remote MSC, return NULL. */
struct ran_conn *msub_ran_conn(const struct msub *msub)
{
	struct msc_i *msc_i = msub_msc_i(msub);
	if (!msc_i)
		return NULL;
	return msc_i->ran_conn;
}

static struct ran_infra *msub_ran(const struct msub *msub)
{
	int i;
	struct msc_role_common *c;

	for (i = 0; i < MSC_ROLES_COUNT; i++) {
		if (!msub->role[i])
			continue;
		c = msub->role[i]->priv;
		if (!c->ran)
			continue;
		return c->ran;
	}

	return &msc_ran_infra[OSMO_RAT_UNKNOWN];
}

const char *msub_ran_conn_name(const struct msub *msub)
{
	struct msc_i *msc_i = msub_msc_i(msub);
	struct msc_t *msc_t = msub_msc_t(msub);
	if (msc_i && msc_i->c.remote_to)
		return e_link_name(msc_i->c.remote_to);
	if (msc_i && msc_i->ran_conn)
		return ran_conn_name(msc_i->ran_conn);
	if (msc_t && msc_t->c.remote_to)
		return e_link_name(msc_t->c.remote_to);
	if (msc_t && msc_t->ran_conn)
		return ran_conn_name(msc_t->ran_conn);
	return osmo_rat_type_name(msub_ran(msub)->type);
}

int msub_set_vsub(struct msub *msub, struct vlr_subscr *vsub)
{
	OSMO_ASSERT(msub);
	if (msub->vsub == vsub)
		return 0;
	if (msub->vsub && vsub) {
		LOG_MSUB(msub, LOGL_ERROR,
			 "Changing a connection's VLR Subscriber is not allowed: not changing to %s\n",
			 vlr_subscr_name(vsub));
		return -ENOTSUP;
	}
	if (vsub) {
		struct msub *other_msub = msub_for_vsub(vsub);
		if (other_msub) {
			struct msc_a *msc_a = msub_msc_a(msub);
			struct msc_a *other_msc_a = msub_msc_a(other_msub);
			LOG_MSC_A(msc_a, LOGL_ERROR,
				  "Cannot associate with VLR subscr, another connection is already active%s%s\n",
				  other_msc_a ? " at " : "", other_msc_a ? other_msc_a->c.fi->id : "");
			LOG_MSC_A(other_msc_a, LOGL_ERROR, "Attempt to associate a second subscriber connection%s%s\n",
				  msc_a ? " at " : "", msc_a ? msc_a->c.fi->id : "");
			if (other_msc_a && msc_a_in_release(other_msc_a)) {
				LOG_MSC_A(other_msc_a, LOGL_ERROR,
					  "Another connection for this subscriber is coming up, since this"
					  " is already in release, forcefully discarding it\n");
				osmo_fsm_inst_term(other_msc_a->c.fi, OSMO_FSM_TERM_ERROR, other_msc_a->c.fi);
				/* Count this as "recovered from duplicate connection" error and do associate. */
			} else
				return -EINVAL;
		}
	}
	if (msub->vsub) {
		vlr_subscr_put(msub->vsub, VSUB_USE_MSUB);
		msub->vsub = NULL;
	}
	if (vsub) {
		vlr_subscr_get(vsub, VSUB_USE_MSUB);
		msub->vsub = vsub;
		vsub->cs.attached_via_ran = msub_ran(msub)->type;
		msub_update_id(msub);
	}
	return 0;
}

struct vlr_subscr *msub_vsub(const struct msub *msub)
{
	return msub ? msub->vsub : NULL;
}

struct gsm_network *msub_net(const struct msub *msub)
{
	OSMO_ASSERT(msub->net);
	return msub->net;
}

int msub_role_to_role_event(struct msub *msub, enum msc_role from_role, enum msc_role to_role)
{
	switch (from_role) {
	case MSC_ROLE_A:
		switch (to_role) {
		case MSC_ROLE_I:
			return MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST;
		case MSC_ROLE_T:
			return MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST;
		default:
			break;
		}
		break;

	case MSC_ROLE_I:
		switch (to_role) {
		case MSC_ROLE_A:
			return MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST;
		default:
			break;
		}
		break;

	case MSC_ROLE_T:
		switch (to_role) {
		case MSC_ROLE_A:
			return MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST;
		default:
			break;
		}
		break;

	default:
		break;
	}

	LOG_MSUB(msub, LOGL_ERROR, "Cannot tx DTAP from %s to %s\n", msc_role_name(from_role), msc_role_name(to_role));
	return -1;
}

/* The caller retains ownership of the an_apdu_msg -- don't forget to msgb_free() it. */
int _msub_role_dispatch(struct msub *msub, enum msc_role to_role, uint32_t to_role_event, const struct an_apdu *an_apdu,
			const char *file, int line)
{
	struct osmo_fsm_inst *to_fi = msub->role[to_role];

	if (!to_fi) {
		LOG_MSUB_CAT_SRC(msub, DMSC, LOGL_ERROR, file, line,
				 "Cannot tx event to %s, no such role defined\n", msc_role_name(to_role));
		return -EINVAL;
	}

	return _osmo_fsm_inst_dispatch(to_fi, to_role_event, (void*)an_apdu, file, line);
}

/* The caller retains ownership of the an_apdu_msg -- don't forget to msgb_free() it. */
int msub_tx_an_apdu(struct msub *msub, enum msc_role from_role, enum msc_role to_role, struct an_apdu *an_apdu)
{
	int event = msub_role_to_role_event(msub, from_role, to_role);
	if (event < 0)
		return event;
	return msub_role_dispatch(msub, to_role, event, an_apdu);
}

static void _msub_update_id(struct msub *msub, const char *subscr_name)
{
	enum msc_role idx;
	struct msc_a *msc_a = msub_msc_a(msub);
	struct vlr_subscr *vsub = msub_vsub(msub);
	const char *compl_l3_name = NULL;
	char id[128];

	if (msc_a)
		compl_l3_name = get_value_string_or_null(complete_layer3_type_names, msc_a->complete_layer3_type);
	if (!compl_l3_name)
		compl_l3_name = "no-compl-l3";

	snprintf(id, sizeof(id), "%s:%s:%s", subscr_name, msub_ran_conn_name(msub), compl_l3_name);
	osmo_identifier_sanitize_buf(id, NULL, '-');

	for_each_msub_role(msub, idx) {
		osmo_fsm_inst_update_id(msub->role[idx], id);
	}
	if (vsub) {
		if (vsub->lu_fsm)
			osmo_fsm_inst_update_id(vsub->lu_fsm, id);
		if (vsub->auth_fsm)
			osmo_fsm_inst_update_id(vsub->auth_fsm, id);
		if (vsub->proc_arq_fsm)
			osmo_fsm_inst_update_id(vsub->proc_arq_fsm, id);
	}
}

/* Compose an ID almost like gsm48_mi_to_string(), but print the MI type along, and print a TMSI as hex. */
void msub_update_id_from_mi(struct msub *msub, const struct osmo_mobile_identity *mi)
{
	_msub_update_id(msub, osmo_mobile_identity_to_str_c(OTC_SELECT, mi));
}

/* Update msub->fi id string from current msub->vsub and msub->complete_layer3_type. */
void msub_update_id(struct msub *msub)
{
	if (!msub)
		return;
	_msub_update_id(msub, vlr_subscr_name(msub->vsub));
}

/* Iterate all msub instances that are relevant for this subscriber, and update FSM ID strings for all of the FSM
 * instances. */
void msub_update_id_for_vsub(struct vlr_subscr *for_vsub)
{
	struct msub *msub;
	if (!for_vsub)
		return;

	llist_for_each_entry(msub, &msub_list, entry) {
		if (msub->vsub == for_vsub)
			msub_update_id(msub);
	}
}

void msc_role_forget_conn(struct osmo_fsm_inst *role, struct ran_conn *conn)
{
	struct msc_i *old_i = role->priv;
	struct msc_t *old_t = role->priv;
	struct msc_role_common *c = role->priv;
	struct ran_conn **conn_p = NULL;

	switch (c->role) {
	case MSC_ROLE_I:
		conn_p = &old_i->ran_conn;
		break;

	case MSC_ROLE_T:
		conn_p = &old_t->ran_conn;
		break;
	default:
		break;
	}

	if (!conn_p)
		return;

	if (*conn_p != conn)
		return;

	(*conn_p)->msc_role = NULL;
	*conn_p = NULL;
}

/* NOTE: the resulting message buffer will be attached to OTC_SELECT, so its lifetime
 * is limited by the current select() loop iteration.  Use talloc_steal() to avoid this. */
struct msgb *msc_role_ran_encode(struct osmo_fsm_inst *fi, const struct ran_msg *ran_msg)
{
	struct msc_role_common *c = fi->priv;
	struct msgb *msg;
	if (!c->ran->ran_encode) {
		LOGPFSML(fi, LOGL_ERROR, "Cannot encode %s: no NAS encoding function defined for RAN type %s\n",
			 ran_msg_type_name(ran_msg->msg_type), osmo_rat_type_name(c->ran->type));
		return NULL;
	}
	msg = c->ran->ran_encode(fi, ran_msg);
	if (!msg)
		LOGPFSML(fi, LOGL_ERROR, "Failed to encode %s\n", ran_msg_type_name(ran_msg->msg_type));
	else
		talloc_steal(OTC_SELECT, msg);
	return msg;
}

int msc_role_ran_decode(struct osmo_fsm_inst *fi, const struct an_apdu *an_apdu,
			ran_decode_cb_t decode_cb, void *decode_cb_data)
{
	struct ran_dec ran_dec;
	struct msc_role_common *c = fi->priv;
	if (!an_apdu) {
		LOGPFSML(fi, LOGL_ERROR, "NULL AN-APDU\n");
		return -EINVAL;
	}
	if (an_apdu->an_proto != c->ran->an_proto) {
		LOGPFSML(fi, LOGL_ERROR, "Unexpected AN-APDU protocol: %s\n", an_proto_name(an_apdu->an_proto));
		return -EINVAL;
	}
	if (!an_apdu->msg) {
		LOGPFSML(fi, LOGL_DEBUG, "No PDU in this AN-APDU\n");
		return 0;
	}
	ran_dec = (struct ran_dec) {
		.caller_fi = fi,
		.caller_data = decode_cb_data,
		.decode_cb = decode_cb,
	};
	if (!c->ran->ran_dec_l2) {
		LOGPFSML(fi, LOGL_ERROR, "No ran_dec_l2() defined for RAN type %s\n",
			 osmo_rat_type_name(c->ran->type));
		return -ENOTSUP;
	}
	return c->ran->ran_dec_l2(&ran_dec, an_apdu->msg);
}
