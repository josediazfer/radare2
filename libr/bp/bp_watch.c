/* radare - LGPL - Copyright 2010-2017 pancake<nopcode.org>, rkx1209 */

#include <r_bp.h>

static void r_bp_watch_add_hw(RBreakpoint *bp, RBreakpointItem *b) {
	if (bp->breakpoint) {
		bp->breakpoint (bp, b, true);
	}
}

R_API RBreakpointItem* r_bp_watch_add(RBreakpoint *bp, ut64 addr, int size, int type, int rw, int depth) {
	RBreakpointItem *b;
	if (addr == UT64_MAX || size < 1) {
		return NULL;
	}
	if (r_bp_get_in (bp, addr, rw)) {
		eprintf ("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = r_bp_item_new (bp);
	b->addr = addr + bp->delta;
	b->size = size;
	b->enabled = true;
	b->rwx = rw;
	b->type = type;
	b->depth = depth;
	if (type == R_BP_TYPE_HW) {
		r_bp_watch_add_hw (bp, b);
	} else {
		eprintf ("[TODO]: Watchpoint is not implmented yet (use ESIL)\n");
		/* TODO */
	}
	bp->nbps++;
	r_list_append (bp->bps, b);
	return b;
}

R_API void r_bp_watch_del() {
}
