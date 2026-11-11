/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit debug.vsc and run lib/libvsc/vsctool.py instead.
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include "vdef.h"
#include "vas.h"
#include "vrt.h"
#include "VSC_debug.h"

static const char vsc_debug_name[] = "DEBUG";

#define PARANOIA(a,n)				\
    v_static_assert(				\
	offsetof(struct VSC_debug, a) == n,	\
	"VSC element '" #a "' at wrong offset")

PARANOIA(count, 0);
#undef PARANOIA

static const unsigned char vsc_debug_json[307] = {
	123,34,118,101,114,115,105,111,110,34,58,34,49,34,44,34,110,97,109,101,
	34,58,34,100,101,98,117,103,34,44,34,111,110,101,108,105,110,101,114,
	34,58,34,69,120,97,109,112,108,101,32,67,111,117,110,116,101,114,115,
	34,44,34,111,114,100,101,114,34,58,55,48,44,34,100,111,99,115,34,58,
	34,92,116,84,101,115,116,32,99,111,117,110,116,101,114,115,32,102,114,
	111,109,32,118,109,111,100,95,100,101,98,117,103,34,44,34,101,108,101,
	109,101,110,116,115,34,58,49,44,34,101,108,101,109,34,58,123,34,99,111,
	117,110,116,34,58,123,34,116,121,112,101,34,58,34,99,111,117,110,116,
	101,114,34,44,34,99,116,121,112,101,34,58,34,117,105,110,116,54,52,95,
	116,34,44,34,108,101,118,101,108,34,58,34,100,101,98,117,103,34,44,34,
	111,110,101,108,105,110,101,114,34,58,34,97,114,98,105,116,114,97,114,
	121,32,99,111,117,110,116,101,114,34,44,34,102,111,114,109,97,116,34,
	58,34,105,110,116,101,103,101,114,34,44,34,105,110,100,101,120,34,58,
	48,44,34,110,97,109,101,34,58,34,99,111,117,110,116,34,44,34,100,111,
	99,115,34,58,34,92,116,74,117,115,116,32,99,111,117,110,116,105,110,
	103,32,115,111,109,101,116,104,105,110,103,34,125,125,125,0
};

// {
//   "version": "1",
//   "name": "debug",
//   "oneliner": "Example Counters",
//   "order": 70,
//   "docs": "\tTest counters from vmod_debug",
//   "elements": 1,
//   "elem": {
//     "count": {
//       "type": "counter",
//       "ctype": "uint64_t",
//       "level": "debug",
//       "oneliner": "arbitrary counter",
//       "format": "integer",
//       "index": 0,
//       "name": "count",
//       "docs": "\tJust counting something"
//     }
//   }
// }


struct VSC_debug*
VSC_debug_New(struct vsmw_cluster *vc,
    struct vsc_seg **sg, const char *fmt, ...)
{
	va_list ap;
	struct VSC_debug *retval;

	va_start(ap, fmt);
	retval = VRT_VSC_Allocv(vc, sg, vsc_debug_name, VSC_debug_size,
	    vsc_debug_json, sizeof vsc_debug_json, fmt, ap);
	va_end(ap);
	return(retval);
}

void
VSC_debug_Destroy(struct vsc_seg **sg)
{
	struct vsc_seg *p;

	AN(sg);
	p = *sg;
	*sg = NULL;
	VRT_VSC_Destroy(vsc_debug_name, p);
}
