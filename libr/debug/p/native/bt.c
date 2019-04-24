#include <r_anal.h>

#include "bt/generic.c"
#include "bt/generic-x86.c"
#include "bt/generic-x64.c"
#include "bt/fuzzy-all.c"

static void prepend_current_pc (RDebug *dbg, RList *list) {
	RDebugFrame *frame;
	const char *pcname;
	if (list) {
		pcname = r_reg_get_name (dbg->reg, R_REG_NAME_PC);
		if (pcname) {
			ut64 addr = r_reg_getv (dbg->reg, pcname);
			frame = R_NEW0 (RDebugFrame);
			frame->addr = addr;
			frame->size = 0;
			r_list_prepend (list, frame);
		}
	}
}

static RList *r_debug_native_frames(RDebug *dbg, ut64 at) {
	RList *list;

	if (!dbg->btalgo) {
		list = backtrace_x86 (dbg, at);
	} else if (!strncmp (dbg->btalgo, "fuzzy", 5)) {
		list = backtrace_fuzzy (dbg,
					!strcmp (dbg->btalgo, "fuzzy-barrier")?
					R_DEBUG_BT_FUZZ_BARRIER : R_DEBUG_BT_FUZZ_CALL,
					at);
	} else if (!strcmp (dbg->btalgo, "anal")) {
		if (dbg->bits == R_SYS_BITS_64) {
			list = backtrace_x86_64_anal (dbg, at);
		} else {
			list = backtrace_x86_32_anal (dbg, at);
		}
	} else {
		list = backtrace_x86 (dbg, at);
	}
	prepend_current_pc (dbg, list);

	return list;
}
