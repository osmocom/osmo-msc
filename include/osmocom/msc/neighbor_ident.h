/* Manage identity of neighboring BSS cells for inter-BSC handover */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/sccp_sap.h>

struct vty;
struct gsm_network;

enum msc_neighbor_type {
	MSC_NEIGHBOR_TYPE_NONE = 0,
	MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER,
	MSC_NEIGHBOR_TYPE_REMOTE_MSC,
};

struct msc_ipa_name {
	char buf[64];
	size_t len;
};

int msc_ipa_name_from_str(struct msc_ipa_name *min, const char *name);
int msc_ipa_name_cmp(const struct msc_ipa_name *a, const struct msc_ipa_name *b);

struct neighbor_ident_addr {
	enum osmo_rat_type ran_type;
	enum msc_neighbor_type type;
	union {
		char local_ran_peer_pc_str[23];
		struct msc_ipa_name remote_msc_ipa_name;
	};
};

struct neighbor_ident_entry {
	struct llist_head entry;

	struct neighbor_ident_addr addr;

	/* A list of struct cell_ids_entry. A gsm0808_cell_id_list2 would in principle suffice, but to support
	 * storing more than 127 cell ids and to allow storing IDs of differing types, have a list of any number of
	 * gsm0808_cell_id_list2. */
	struct llist_head cell_ids;
};

void neighbor_ident_init(struct gsm_network *net);
const char *neighbor_ident_addr_name(const struct neighbor_ident_addr *nia);

const struct neighbor_ident_entry *neighbor_ident_add(struct llist_head *ni_list,
						      const struct neighbor_ident_addr *nia,
						      const struct gsm0808_cell_id *cid);

const struct neighbor_ident_entry *neighbor_ident_find_by_cell(const struct llist_head *ni_list,
							       enum osmo_rat_type ran_type,
							       const struct gsm0808_cell_id *cell_id);

const struct neighbor_ident_entry *neighbor_ident_find_by_addr(const struct llist_head *ni_list,
							       const struct neighbor_ident_addr *nia);

void neighbor_ident_del(const struct neighbor_ident_entry *nie);

void neighbor_ident_clear(struct llist_head *ni_list);

void neighbor_ident_vty_init(struct gsm_network *net);
void neighbor_ident_vty_write(struct vty *vty);

