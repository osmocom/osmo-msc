#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DRLL,
	DCC,
	DMM,
	DRR,
	DMNCC,
	DPAG,
	DMSC,
	DMGCP,
	DHO,
	DDB,
	DREF,
	DCTRL,
	DSMPP,
	DRANAP,
	DVLR,
	DIUCS,
	Debug_LastEntry,
};

extern const struct log_info log_info;
