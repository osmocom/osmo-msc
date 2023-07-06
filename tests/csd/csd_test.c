#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <osmocom/core/application.h>
#include <osmocom/msc/csd_bs.h>
#include <osmocom/msc/debug.h>

void test_csd_bs_list_remove(void)
{
	struct csd_bs_list list = {
		.count = 3,
		.bs = {
			CSD_BS_21_T_V110_0k3,
			CSD_BS_22_T_V110_1k2,
			CSD_BS_24_T_V110_2k4,
		},
	};

	printf("=== %s ===\n", __func__);
	printf("initial:\n");
	printf("  %s\n", csd_bs_list_to_str(&list));

	printf("removing BS25T (not in the list):\n");
	csd_bs_list_remove(&list, CSD_BS_25_T_V110_4k8);
	printf("  %s\n", csd_bs_list_to_str(&list));

	printf("removing BS22T:\n");
	csd_bs_list_remove(&list, CSD_BS_22_T_V110_1k2);
	printf("  %s\n", csd_bs_list_to_str(&list));

	printf("removing BS24T:\n");
	csd_bs_list_remove(&list, CSD_BS_24_T_V110_2k4);
	printf("  %s\n", csd_bs_list_to_str(&list));

	printf("removing BS21T:\n");
	csd_bs_list_remove(&list, CSD_BS_21_T_V110_0k3);
	printf("  %s\n", csd_bs_list_to_str(&list));
}

int main(void)
{
	test_csd_bs_list_remove();
	return 0;
}
