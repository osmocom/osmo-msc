#include <stdio.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include <osmocom/msc/sdp_msg.h>

struct sdp_test_data {
	const char *sdp_input;
	const char *expect_sdp_str;
};

static void dump_sdp(const char *str, const char *prefix)
{
	while (str && *str) {
		const char *line_end = sdp_msg_line_end(str);
		while (*line_end == '\r' || *line_end == '\n')
			line_end++;
		printf("%s%s\n", prefix, osmo_escape_str(str, line_end - str));
		str = line_end;
	}
}

struct sdp_test_data sdp_tests[] = {
	{
		"v=0\r\n"
		"o=- 5628250 5628250 IN IP4 192.168.11.121\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.11.121\r\n"
		"t=0 0\r\n"
		"m=audio 10020 RTP/AVP 18 0 2 4 8 96 97 98 100 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:2 G726-32/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:96 G726-40/8000\r\n"
		"a=rtpmap:97 G726-24/8000\r\n"
		"a=rtpmap:98 G726-16/8000\r\n"
		"a=rtpmap:100 NSE/8000\r\n"
		"a=fmtp:100 192-193\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 192.168.11.121\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 192.168.11.121\r\n"
		"t=0 0\r\n"
		"m=audio 10020 RTP/AVP 18 0 2 4 8 96 97 98 100 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:2 G726-32/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:96 G726-40/8000\r\n"
		"a=rtpmap:97 G726-24/8000\r\n"
		"a=rtpmap:98 G726-16/8000\r\n"
		"a=rtpmap:100 NSE/8000\r\n"
		"a=fmtp:100 192-193\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.151\r\n"
		"t=0 0\r\n"
		"m=audio 16398 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=fmtp:98 octet-align=1; mode-set=4\r\n"
		"a=ptime:20\r\n"
		"a=rtcp:16399 IN IP4 192.168.11.151\r\n"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 192.168.11.151\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 192.168.11.151\r\n"
		"t=0 0\r\n"
		"m=audio 16398 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=fmtp:98 octet-align=1; mode-set=4\r\n"
		"a=ptime:20\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=sendrecv\r\n"
		"a=rtcp:30437\r\n"
		"a=ptime:20\r\n"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 192.168.11.140\r\n" /* <- NOTE: loses the 'o=' address, uses only 'c=' */
		"s=GSM Call\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n"
		,
	},
};

void test_parse_and_compose()
{
	int i;
	bool ok = true;

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdp_tests); i++) {
		struct sdp_test_data *t = &sdp_tests[i];
		struct sdp_msg sdp = {};
		char str[1024];
		printf("\n[%d]\n", i);
		dump_sdp(t->sdp_input, "sdp input: ");

		OSMO_ASSERT(sdp_msg_from_sdp_str(&sdp, t->sdp_input) == 0);
		sdp_msg_to_sdp_str_buf(str, sizeof(str), &sdp);

		dump_sdp(str, "sdp_msg_to_sdp_str_buf: ");
		if (strcmp(str, t->expect_sdp_str)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(t->expect_sdp_str, "expect_sdp_str: ");
			for (j = 0; t->expect_sdp_str[j]; j++) {
				if (t->expect_sdp_str[j] != str[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(str + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);
	}

	OSMO_ASSERT(ok);
}

struct sdp_intersect_test_data {
	const char *descr;
	const char *sdp_a;
	const char *sdp_b;
	const char *expect_intersection;
};

#define SDP_1 \
		"v=0\r\n" \
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n" \
		"a=rtpmap:112 AMR/8000\r\n" \
		"a=fmtp:112 octet-align=1\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=rtpmap:110 GSM-EFR/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_2 \
		"v=0\r\n" \
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 112 110\r\n" \
		"a=rtpmap:112 AMR/8000\r\n" \
		"a=fmtp:112 octet-align=1\r\n" \
		"a=rtpmap:110 GSM-EFR/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_3 \
		"v=0\r\n" \
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 3 111\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=ptime:20\r\n"


struct sdp_intersect_test_data sdp_intersect_tests[] = {
	{
		"identical codecs lead to no change"
		,
		SDP_1
		,
		"c=IN IP4 5.6.7.8\r\n" \
		"m=audio 12345 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		,
		SDP_1
	},
	{
		"identical codecs in different order also lead to no change"
		,
		SDP_1
		,
		"c=IN IP4 5.6.7.8\r\n" \
		"m=audio 12345 RTP/AVP 3 110 111 112\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		,
		SDP_1
	},
	{
		"identical codecs with mismatching payload type numbers also lead to no change"
		,
		SDP_1
		,
		"c=IN IP4 5.6.7.8\r\n" \
		"m=audio 12345 RTP/AVP 96 97 98 99\r\n"
		"a=rtpmap:96 GSM/8000\r\n"
		"a=rtpmap:97 GSM-EFR/8000\r\n"
		"a=rtpmap:98 GSM-HR-08/8000\r\n"
		"a=rtpmap:99 AMR/8000\r\n"
		"a=fmtp:99 octet-align=1\r\n"
		,
		SDP_1
	},
	{
		"identical codecs plus some extra codecs also lead to no change"
		,
		SDP_1
		,
		"c=IN IP4 5.6.7.8\r\n" \
		"m=audio 12345 RTP/AVP 8 0 96 97 98 99\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:96 GSM/8000\r\n"
		"a=rtpmap:97 GSM-EFR/8000\r\n"
		"a=rtpmap:98 GSM-HR-08/8000\r\n"
		"a=rtpmap:99 AMR/8000\r\n"
		"a=fmtp:99 octet-align=1\r\n"
		,
		SDP_1
	},
	{
		"some codecs removed",
		SDP_1,
		SDP_2,
		SDP_2,
	},
	{
		"other codecs removed",
		SDP_1,
		SDP_3,
		SDP_3,
	},
	{
		"all codecs removed",
		SDP_1
		,
		"s=empty"
		,
		"v=0\r\n" \
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP\r\n" \
		"a=ptime:20\r\n"
	},
	{
		"some real world test case"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 0.0.0.0\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=audio 0 RTP/AVP 112 113 110 3 111\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1;mode-set=0,1,2,3\r\n"
		"a=rtpmap:113 AMR-WB/8000\r\n"
		"a=fmtp:113 octet-align=1\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=ptime:20\r\n"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 0.0.0.0\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=audio 0 RTP/AVP 112 113 110 3 111\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1;mode-set=0,1,2,3\r\n"
		"a=rtpmap:113 AMR-WB/8000\r\n"
		"a=fmtp:113 octet-align=1\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=ptime:20\r\n"
		,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 0.0.0.0\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=audio 0 RTP/AVP 112 113 110 3 111\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1;mode-set=0,1,2,3\r\n"
		"a=rtpmap:113 AMR-WB/8000\r\n"
		"a=fmtp:113 octet-align=1\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=ptime:20\r\n"
	}
};

const char *sdp_msg_logstr(const struct sdp_msg *sdp)
{
	static char buf[1024];
	sdp_msg_to_sdp_str_buf(buf, sizeof(buf), sdp);
	return buf;
}

static void test_intersect()
{
	int i;
	bool ok = true;
	int rc;

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdp_intersect_tests); i++) {
		struct sdp_intersect_test_data *t = &sdp_intersect_tests[i];
		struct sdp_msg sdp_a = {};
		struct sdp_msg sdp_b = {};
		char str[1024];
		printf("\n[%d] %s\n", i, t->descr);
		dump_sdp(t->sdp_a, "SDP A: ");
		dump_sdp(t->sdp_b, " SDP B: ");

		rc = sdp_msg_from_sdp_str(&sdp_a, t->sdp_a);
		if (rc) {
			printf("ERROR parsing SDP A: %d\n", rc);
			break;
		}
		dump_sdp(sdp_msg_logstr(&sdp_a), "parsed SDP A: ");
		rc = sdp_msg_from_sdp_str(&sdp_b, t->sdp_b);
		if (rc) {
			printf("ERROR parsing SDP A: %d\n", rc);
			break;
		}
		dump_sdp(sdp_msg_logstr(&sdp_b), "parsed SDP B: ");
		sdp_audio_codecs_intersection(&sdp_a.audio_codecs, &sdp_b.audio_codecs, false);
		sdp_msg_to_sdp_str_buf(str, sizeof(str), &sdp_a);

		dump_sdp(str, "sdp_msg_intersection(a,b): ");
		if (strcmp(str, t->expect_intersection)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(t->expect_intersection, "expect_intersection: ");
			for (j = 0; t->expect_intersection[j]; j++) {
				if (t->expect_intersection[j] != str[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(str + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);
	}

	OSMO_ASSERT(ok);
}

struct sdp_select_test_data {
	const char *sdp;
	unsigned int select_payload_type;
	const char *expect_sdp;
};

struct sdp_select_test_data sdp_select_tests[] = {
	{
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		112,
		NULL
	},
	{
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		3,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 3 112 111 110\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
	},
	{
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		111,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 111 112 3 110\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
	},
	{
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		110,
		"v=0\r\n"
		"o=OsmoMSC 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 110 112 3 111\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=ptime:20\r\n"
	},

};

static void test_select()
{
	int i;
	bool ok = true;
	int rc;

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdp_select_tests); i++) {
		struct sdp_select_test_data *t = &sdp_select_tests[i];
		struct sdp_msg sdp = {};
		struct sdp_audio_codec *codec;
		char buf[1024];
		const char *expect_sdp;

		printf("\n[%d]\n", i);
		rc = sdp_msg_from_sdp_str(&sdp, t->sdp);
		if (rc) {
			printf("ERROR parsing SDP: %d\n", rc);
			break;
		}
		printf("SDP: %s\n", sdp_audio_codecs_to_str(&sdp.audio_codecs));
		codec = sdp_audio_codecs_by_payload_type(&sdp.audio_codecs, t->select_payload_type, false);
		OSMO_ASSERT(codec);
		printf("Select: %s\n", sdp_audio_codec_to_str(codec));

		sdp_audio_codecs_select(&sdp.audio_codecs, codec);

		printf("SDP: %s\n", sdp_audio_codecs_to_str(&sdp.audio_codecs));
		sdp_msg_to_sdp_str_buf(buf, sizeof(buf), &sdp);

		expect_sdp = t->expect_sdp ? : t->sdp;
		if (strcmp(buf, expect_sdp)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(buf, "selection result: ");
			dump_sdp(expect_sdp, "expect result: ");
			for (j = 0; expect_sdp[j]; j++) {
				if (expect_sdp[j] != buf[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(buf + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);
	}

	OSMO_ASSERT(ok);
}

int main(void)
{
	test_parse_and_compose();
	test_intersect();
	test_select();
	return 0;
}
