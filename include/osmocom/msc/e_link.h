/* E-interface messaging over a GSUP connection */
#pragma once

#include <osmocom/gsm/gsup.h>
#include <osmocom/msc/msc_roles.h>

struct osmo_fsm_inst;
struct gsm_network;
struct vlr_instance;

/* E-interface: connection to a remote MSC via GSUP */
struct e_link {
	struct osmo_fsm_inst *msc_role;
	struct gsup_client_mux *gcm;
	uint8_t *remote_name;
	size_t remote_name_len;
};

struct e_link *e_link_alloc(struct gsup_client_mux *gcm, struct osmo_fsm_inst *msc_role,
			    const uint8_t *remote_name, size_t remote_name_len);
void e_link_assign(struct e_link *e, struct osmo_fsm_inst *msc_role);
void e_link_free(struct e_link *e);

int e_prep_gsup_msg(struct e_link *e, struct osmo_gsup_message *gsup_msg);
int e_tx(struct e_link *e, const struct osmo_gsup_message *gsup_msg);

const char *e_link_name(struct e_link *e);

void msc_a_i_t_gsup_init(struct gsm_network *net);

enum osmo_gsup_entity msc_role_to_gsup_entity(enum msc_role role);
enum msc_role gsup_entity_to_msc_role(enum osmo_gsup_entity entity);
int gsup_msg_assign_an_apdu(struct osmo_gsup_message *gsup_msg, struct an_apdu *an_apdu);

struct msgb *gsup_msg_to_msgb(const struct osmo_gsup_message *gsup_msg);
void gsup_msg_to_an_apdu(struct an_apdu *an_apdu, const struct osmo_gsup_message *gsup_msg);
