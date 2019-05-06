#pragma once

enum osmux_usage {
	/* MSC won't use Osmux in call legs towards its RAN */
	OSMUX_USAGE_OFF = 0,
	/* MSC will use Osmux in call legs towards RAN as long as RAN announced support for it */
	OSMUX_USAGE_ON = 1,
	/* MSC will always use Osmux in call legs towards its RAN, and will
	   reject calls for RANs which didn't announce support for it */
	OSMUX_USAGE_ONLY = 2,
};
