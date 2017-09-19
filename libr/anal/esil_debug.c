/* radare - LGPL - Copyright 2017 - josediazfer */

#include <r_debug.h>
#include <r_anal.h>

static int hook_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	eprintf("read addr: 0x%llx\n", addr);
	return 0;
}

static int hook_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	eprintf("write addr: 0x%llx\n", addr);
	return 0;
}

static int hook_reg_read(RAnalEsil *esil, const char *name, ut64 *res, int *size) {
	RDebug *dbg = (RDebug *)esil->user;
	RRegItem *ri;

	eprintf("read reg\n");

	*res = 0;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_GPR);
	if (ri) {
		*res = r_reg_get_value (dbg->reg, ri);
	}
	return 0;
}

R_API void r_anal_esil_debug(void *dbg, RAnalEsil *esil) {
	esil->user = dbg;
	esil->cb.hook_reg_read = hook_reg_read;
	esil->cb.hook_mem_read = hook_mem_read;
	esil->cb.hook_mem_write = hook_mem_write;
}
