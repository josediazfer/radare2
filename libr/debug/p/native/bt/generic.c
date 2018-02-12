
static RList *backtrace_x86(RDebug *dbg, ut64 at) {
	int i;
	ut8 buf[20];
	RDebugFrame *frame;
	ut64 ptr, ebp2;
	ut64 _rsp, _rbp = 0;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;
	int btdepth = dbg->btdepth;
	const char *sp_name = reg->name[R_REG_NAME_SP];
	const char *bp_name = reg->name[R_REG_NAME_BP];
	ut8 ptr_sz = dbg->bits == R_SYS_BITS_64? 8 : 4;

	if (at == UT64_MAX) {
		_rsp = r_reg_get_value (reg, r_reg_get (reg, sp_name, R_REG_TYPE_GPR));
		_rbp = r_reg_get_value (reg, r_reg_get (reg, bp_name, R_REG_TYPE_GPR));
	} else {
		_rsp = _rbp = at;
	}
	list = r_list_newf ((RListFree)free);
	if (!list) {
		perror ("backtrace_x86/alloc RDebugFrame list");
		goto err_backtrace_x86;
	}
#if 0
	bio->read_at (bio->io, _rip, (ut8*)&buf, 8);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (!bio->read_at (bio->io, _rsp, (ut8*)&ptr, 8)) {
			eprintf ("read error at 0x%08"PFMT64x"\n", _rsp);
			r_list_purge (list);
			free (list);
			return false;
		}
		frame = R_NEW0 (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ptr;
	}
#endif
	if (bio->read_at (bio->io, _rsp, (ut8*)&buf, ptr_sz)) {
		ut64 addr;
		RDebugMap *map;

		if (dbg->bits == R_SYS_BITS_64) {
			addr = *(ut64 *)buf;
		} else {
			addr = *(ut32 *)buf;
		}
		map = r_debug_map_get (dbg, addr);
		if (map && map->perm & R_IO_EXEC) {
			RAnalOp op;
			ut64 base_addr = addr - sizeof (buf);

			if (bio->read_at (bio->io, base_addr, buf, sizeof (buf))) {
				for (i = 0; i < sizeof (buf) / sizeof (char); i++) {
					if (!r_anal_op (dbg->anal, &op, base_addr + i, buf + i, sizeof (buf)) ||
						op.type == R_ANAL_OP_TYPE_ILL) {
						continue;
					}
					switch (op.type) {
						case R_ANAL_OP_TYPE_CALL:
						case R_ANAL_OP_TYPE_CCALL:
						case R_ANAL_OP_TYPE_RCALL:
						case R_ANAL_OP_TYPE_IRCALL:
						case R_ANAL_OP_TYPE_UCALL:
							frame = R_NEW0 (RDebugFrame);
							if (!frame) {
								perror ("backtrace_x86/alloc RDebugFrame");
								goto err_backtrace_x86;
							}
							frame->addr = addr;
							frame->size = 0; // TODO ?
							r_list_append (list, frame);
							i = sizeof (buf) / sizeof (char);
							break;
					}
				}
			}
		}
	}
	for (i = 1; i < btdepth; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, (ut8*)&ebp2, ptr_sz);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at (bio->io, _rbp + ptr_sz, (ut8*)&ptr, ptr_sz);
		if (!ptr || !_rbp)
			break;
		frame = R_NEW0 (RDebugFrame);
		if (!frame) {
			perror ("backtrace_x86/alloc RDebugFrame");
			goto err_backtrace_x86;
		}
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ebp2;
	}
err_backtrace_x86:
	return list;
}
