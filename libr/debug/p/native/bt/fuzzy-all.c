/* implementation */

enum {
	R_DEBUG_BT_FUZZ_CALL,
	R_DEBUG_BT_FUZZ_BARRIER
};

// 512KB .. should get the size from the regions if possible
#define MAX_STACK_SIZE (512 * 1024)

static int is_call(RDebug *dbg, ut64 addr) {
	ut8 buf[32];
	int max_call_len;

	if (addr == 0LL || addr == UT64_MAX) {
		return 0;
	}
	/* check if region is executable */
	/* check if previous instruction is a call */
	/* if x86 expect CALL to be 5 byte length */
#if 0
	if (dbg->arch && !strcmp (dbg->arch, "x86")) {
		(void)dbg->iob.read_at (dbg->iob.io, addr-5, buf, 5);
		if (buf[0] == 0xe8) return 1;
		if (buf[3] == 0xff && (buf[4] & 0xf0)==0xd0) return 1;
		// IMMAMISSINGANYOP
	} else {
#endif
	RAnalOp op;
	int i;

	if (dbg->arch && !strcmp (dbg->arch, "x86")) {
		max_call_len = dbg->bits == 32? 5 : 8;
	} else {
		max_call_len = 8;
	}
	(void) dbg->iob.read_at (dbg->iob.io, addr - max_call_len, buf, max_call_len);
	for (i = max_call_len; i > 1; i--) {
		(void) r_anal_op (dbg->anal, &op, addr - i, buf + max_call_len - i, i);
		if (op.type == R_ANAL_OP_TYPE_CALL || op.type == R_ANAL_OP_TYPE_UCALL) {
			return 1;
		}
	}
	return 0;
}

static int is_exec(RDebug *dbg, ut64 addr) {
	RDebugMap *map = r_debug_map_get (dbg, addr);

	return map && (map->perm & R_IO_EXEC) == R_IO_EXEC;
}

static RList *backtrace_fuzzy(RDebug *dbg, int type, ut64 at) {
	ut8 *stack = NULL, *ptr;
	int wordsize = dbg->bits; // XXX, dbg->bits is wordsize not bits
	ut64 sp;
	RIOBind *bio = &dbg->iob;
	int i;
	ut64 *p64, addr = 0LL;
	ut32 *p32;
	ut16 *p16;
	ut64 cursp, oldsp;
	RList *list = NULL;
	bool success = false;
	
	stack = malloc (MAX_STACK_SIZE);
	if (at == UT64_MAX) {
		RRegItem *ri;
		RReg *reg = dbg->reg;
		const char *spname = r_reg_get_name (reg, R_REG_NAME_SP);
		if (!spname) {
			eprintf ("Cannot find stack pointer register\n");
			goto err_backtrace_fuzzy;
		}
		ri = r_reg_get (reg, spname, R_REG_TYPE_GPR);
		if (!ri) {
			eprintf ("Cannot find stack pointer register\n");
			goto err_backtrace_fuzzy;
		}
		sp = r_reg_get_value (reg, ri);
	} else {
		sp = at;
	}

	list = r_list_newf ((RListFree)free);
	cursp = oldsp = sp;
	(void)bio->read_at (bio->io, sp, stack, MAX_STACK_SIZE);
	ptr = stack;
	if (type == R_DEBUG_BT_FUZZ_BARRIER) {
		r_debug_map_sync (dbg);
	}
	for (i=0; i<dbg->btdepth; i++) {
		int is_jump;

		p64 = (ut64*)ptr;
		p32 = (ut32*)ptr;
		p16 = (ut16*)ptr;
		switch (wordsize) {
		case R_SYS_BITS_64: addr = *p64; break;
		case R_SYS_BITS_32: addr = *p32; break;
		case R_SYS_BITS_16: addr = *p16; break;
		default:
			eprintf ("Invalid word size with asm.bits\n");
			goto err_backtrace_fuzzy;
		}
		is_jump = type == R_DEBUG_BT_FUZZ_CALL? is_call (dbg, addr) : is_exec (dbg, addr);
		if (is_jump) {
			RDebugFrame *frame = R_NEW0 (RDebugFrame);
			frame->addr = addr;
			frame->size = cursp - oldsp;
			frame->sp = cursp;
			frame->bp = oldsp; //addr + (i * wordsize); // -4 || -8
			// eprintf ("--------------> 0x%llx (%d)\n", addr, frame->size);
			r_list_append (list, frame);
			oldsp = cursp;
		}
		ptr += wordsize;
		cursp += wordsize;
	}
	success = true;
err_backtrace_fuzzy:
	if (!success) {
		r_list_free (list);
		list = NULL;
	}
	free (stack);
	return list;
}
