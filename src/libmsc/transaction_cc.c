/* Filter/overlay codec and CSD bearer service selections for voice calls/CSD,
 * across MS, RAN and CN limitations
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Oliver Smith
 *
 * SPDX-License-Identifier: AGPL-3.0+
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

#include <osmocom/msc/transaction_cc.h>
#include <osmocom/msc/codec_filter.h>
#include <osmocom/msc/csd_filter.h>

void trans_cc_filter_init(struct gsm_trans *trans)
{
	trans->cc.codecs = (struct codec_filter){};
	trans->cc.csd = (struct csd_filter){};
}

void trans_cc_filter_set_ran(struct gsm_trans *trans, enum osmo_rat_type ran_type)
{
	codec_filter_set_ran(&trans->cc.codecs, ran_type);
	csd_filter_set_ran(&trans->cc.csd, ran_type);
}

void trans_cc_filter_set_bss(struct gsm_trans *trans, struct msc_a *msc_a)
{
	codec_filter_set_bss(&trans->cc.codecs, &msc_a->cc.compl_l3_codec_list_bss_supported);

	/* For CSD, there is no list of supported bearer services passed in
	 * Complete Layer 3. TODO: make it configurable? */
}

void trans_cc_filter_run(struct gsm_trans *trans)
{
	switch (trans->bearer_cap.transfer) {
	case GSM48_BCAP_ITCAP_SPEECH:
		codec_filter_run(&trans->cc.codecs, &trans->cc.local, &trans->cc.remote);
		LOG_TRANS(trans, LOGL_DEBUG, "codecs: %s\n",
			  codec_filter_to_str(&trans->cc.codecs, &trans->cc.local, &trans->cc.remote));
		break;
	case GSM48_BCAP_ITCAP_UNR_DIG_INF:
		csd_filter_run(&trans->cc.csd, &trans->cc.local, &trans->cc.remote);
		LOG_TRANS(trans, LOGL_DEBUG, "codec/BS: %s\n",
			  csd_filter_to_str(&trans->cc.csd, &trans->cc.local, &trans->cc.remote));
		break;
	default:
		LOG_TRANS(trans, LOGL_ERROR, "Handling of information transfer capability %d not implemented\n",
			  trans->bearer_cap.transfer);
		break;
	}
}

void trans_cc_filter_set_ms_from_bc(struct gsm_trans *trans, const struct gsm_mncc_bearer_cap *bcap)
{
	trans->cc.codecs.ms = (struct sdp_audio_codecs){0};
	trans->cc.csd.ms = (struct csd_bs_list){0};

	if (!bcap)
		return;

	switch (bcap->transfer) {
	case GSM48_BCAP_ITCAP_SPEECH:
		sdp_audio_codecs_from_bearer_cap(&trans->cc.codecs.ms, bcap);
		break;
	case GSM48_BCAP_ITCAP_UNR_DIG_INF:
		sdp_audio_codecs_set_csd(&trans->cc.codecs.ms);
		csd_bs_list_from_bearer_cap(&trans->cc.csd.ms, bcap);
		break;
	default:
		LOG_TRANS(trans, LOGL_ERROR, "Handling of information transfer capability %d not implemented\n",
			  bcap->transfer);
		break;
	}
}

void trans_cc_set_remote_from_bc(struct gsm_trans *trans, const struct gsm_mncc_bearer_cap *bcap)
{
	trans->cc.remote.audio_codecs = (struct sdp_audio_codecs){0};
	trans->cc.remote.bearer_services = (struct csd_bs_list){0};

	if (!bcap)
		return;

	switch (bcap->transfer) {
	case GSM48_BCAP_ITCAP_SPEECH:
		sdp_audio_codecs_from_bearer_cap(&trans->cc.remote.audio_codecs, bcap);
		break;
	case GSM48_BCAP_ITCAP_UNR_DIG_INF:
		sdp_audio_codecs_set_csd(&trans->cc.remote.audio_codecs);
		csd_bs_list_from_bearer_cap(&trans->cc.remote.bearer_services, bcap);
		break;
	default:
		LOG_TRANS(trans, LOGL_ERROR, "Handling of information transfer capability %d not implemented\n",
			  bcap->transfer);
		break;
	}
}
