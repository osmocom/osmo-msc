
int rcv_bcc(msc_a, msg)
{
	trans_alloc wie in gsm0408_rcv_cc()


	struct gsm0808_cell_id cid = {
		.lac = my_lac,
	};

	struct ran_peer *rp_from_neighbor_ident = NULL;
	struct ran_peer *rp_from_cell_id = NULL;
	struct ran_peer *rp;

	switch (msc_ho_find_target_cell(msc_a, cid, &e, &rp_from_neighbor_ident, &rp_from_cell_id)) {
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		ERROR

	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		rp = rp_from_neighbor_ident ? : rp_from_cell_id;
		OSMO_ASSERT(rp);
		msc_a->ho.new_cell.type = MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER;
		msc_a->ho.new_cell.ran_peer = rp;
		return true;

	default:
		break;
	}

	/* Now rp points at the ran_peer for my_lac */

	/* new conn */
	msc_a->vgcs.conn = ran_conn_create_outgoing(rp);
	msc_a->vgcs.conn->vgcs.calling_subscriber = msc_a;

	/* send first message */
	ran_conn_down_l2_co(msc_a->vgcs.conn, l3_msg, true);

	/* later */
	ran_conn_down_l2_co(msc_a->vgcs.conn, l3_msg, false);

	...
}
