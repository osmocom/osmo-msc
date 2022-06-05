#include <unistd.h>

#include <osmocom/core/utils.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/sms_storage.h>

static const struct sms_storage_cfg scfg = {
	.storage_dir = "/tmp/sms_storage",
	.unlink_delivered = false,
	.unlink_expired = false,
};
static struct sms_storage_inst *g_ssi;

static struct gsm_sms *generate_sms(unsigned long long id, const char *src, const char *dst,
				    uint8_t pid, uint8_t dcs, uint8_t msg_ref)
{
	struct gsm_sms *sms = sms_alloc();
	OSMO_ASSERT(sms);

	sms->id = id;
	OSMO_STRLCPY_ARRAY(sms->src.addr, src);
	OSMO_STRLCPY_ARRAY(sms->dst.addr, dst);
	sms->protocol_id = pid;
	sms->data_coding_scheme = dcs;
	sms->msg_ref = msg_ref;

	return sms;
}

static void to_storage(void)
{
	struct gsm_sms *sms = generate_sms(1234, "1111", "2222", 1, 2, 3);
	sms_storage_to_disk_req(g_ssi, sms);
	sms_storage_delete_from_disk_req(g_ssi, sms->id, SMSS_DELETE_CAUSE_DELIVERED);
}

int main(int argc, char **argv)
{
	void *ctx = NULL;

	g_ssi = sms_storage_init(ctx, &scfg);

	to_storage();

	usleep(10000000);
}

