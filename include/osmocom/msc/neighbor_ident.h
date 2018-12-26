/* Manage identity of neighboring BSS cells for inter-BSC handover */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>

struct vty;
struct gsm_network;

enum msc_neighbor_type {
	/* Neighboring BSC reachable via SCCP. */
	MSC_NEIGHBOR_TYPE_BSC,

	/* Neighboring MSC reachable via GSUP. */
	MSC_NEIGHBOR_TYPE_MSC
};

struct neighbor_ident_addr {
	enum msc_neighbor_type type;
	union {
		int point_code; /* BSC */
		const char *ipa_name; /* MSC */
	} a;
};

struct neighbor_ident_list {
	struct llist_head list;
};

struct neighbor_ident {
	struct llist_head entry;

	/* Address of a neighboring BSC or MSC. */
	struct neighbor_ident_addr addr;

	/* IDs of cells in this neighbor's domain. */
	struct gsm0808_cell_id_list2 cell_ids;
};

struct gsm0808_cell_id;
struct gsm0808_cell_id_list2;

const char *neighbor_ident_addr_name(struct gsm_network *net, const struct neighbor_ident_addr *ni_addr);

struct neighbor_ident_list *neighbor_ident_init(void *talloc_ctx);
void neighbor_ident_free(struct neighbor_ident_list *nil);

bool neighbor_ident_addr_match(const struct neighbor_ident_addr *entry,
			       const struct neighbor_ident_addr *search_for,
			       bool exact_match);

int neighbor_ident_add(struct neighbor_ident_list *nil, const struct neighbor_ident_addr *addr,
		       const struct gsm0808_cell_id_list2 *cell_ids);
const struct gsm0808_cell_id_list2 *neighbor_ident_get(const struct neighbor_ident_list *nil,
						       const struct neighbor_ident_addr *addr);
const struct neighbor_ident_addr *neighbor_ident_lookup_cell(const struct neighbor_ident_list *nil,
							     struct gsm0808_cell_id *cell_id);
bool neighbor_ident_del(struct neighbor_ident_list *nil, const struct neighbor_ident_addr *addr);
void neighbor_ident_clear(struct neighbor_ident_list *nil);

void neighbor_ident_iter(const struct neighbor_ident_list *nil,
			 bool (* iter_cb )(const struct neighbor_ident_addr *addr,
					   const struct gsm0808_cell_id_list2 *cell_ids,
					   void *cb_data),
			 void *cb_data);

void neighbor_ident_vty_init(struct gsm_network *net);
void neighbor_ident_vty_write(struct vty *vty);
