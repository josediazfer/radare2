/* radare - LGPL - Copyright 2009-2017 - pancake, jduck, TheLemonMan, saucec0de */

#include <r_debug.h>
#include <r_core.h>
#include <signal.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#define MAX_LUA_MEM_READ_LENGTH	(4*1024*1024)

#if __WINDOWS__
void w32_break_proc(void *);
#endif

R_LIB_VERSION(r_debug);

// Size of the lookahead buffers used in r_debug functions
#define DBG_BUF_SIZE 512

R_API RDebugInfo *r_debug_info(RDebug *dbg, const char *arg) {
	if (!dbg || !dbg->h || !dbg->h->info) {
		return NULL;
	}
	return dbg->h->info (dbg, arg);
}

R_API void r_debug_info_free (RDebugInfo *rdi) {
	if (rdi) {
		free (rdi->cwd);
		free (rdi->exe);
		free (rdi->cmdline);
		free (rdi->libname);
		free (rdi->usr);
	}
	free (rdi);
}

static void r_debug_profiler_th_free(RDebugProfilerThread *th) {
	r_list_free (th->bt_match);
}

static void r_debug_event_handler_free(RDebugEventHandler *ev_handler) {
	int i;

	for (i = 0; i < ev_handler->n_args; i++) {
		free (ev_handler->args[i]);
	}
	free (ev_handler->args);
	free (ev_handler->cmd);
	free (ev_handler);
}

static void r_debug_profiler_bt(RDebug *dbg, RDebugProfilerThread *th) 
{
	RList *frames_list;
	int old_tid = dbg->tid;
	int bt_match_depth = 0;

	dbg->tid = th->tid;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	frames_list = r_debug_frames (dbg, UT64_MAX);
	if (th->bt_match) {
		RListIter *iter, *iter2;
		RDebugFrame *frame;

		iter2 = th->bt_match->tail;
		r_list_foreach_prev (frames_list, iter, frame) {
			RDebugFrame *frame2;

			if (!iter2) {
				break;
			}
			frame2 = iter2->data;
			//eprintf ("%d frame %llx %llx\n", th->tid, frame->addr, frame2->addr); fflush(stderr);
			if (frame->addr != frame2->addr) {
				break;
			}
			iter2 = iter2->p;
			bt_match_depth++;
		}
		if (!bt_match_depth) {
			th->bt_match_depth = r_list_length (frames_list);
			r_list_free (th->bt_match);
			th->bt_match = frames_list;
		} else if (!th->bt_match_depth || bt_match_depth < th->bt_match_depth) {
			th->bt_match_depth = bt_match_depth;
		}
	} else {
		th->bt_match = frames_list;
		th->bt_match_depth = 0;
	}
	dbg->tid = old_tid;
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
}

static void r_debug_profiler_th(RDebug *dbg) {
	RDebugProfiler *profiler = &dbg->profiler;
	RList *th_list, *th_pr_list;
	RListIter *iter, *iter2;
	RDebugPid *th;
	RDebugProfilerThread *th_pr;
	RList *th_list_app = NULL;
	ut64 time;

	profiler->pid = dbg->pid;
	if (!profiler->th_list) {
		profiler->th_list = r_list_newf ((RListFree)r_debug_profiler_th_free);
	} else if (dbg->pid != profiler->pid){
		r_list_free (profiler->th_list);
		profiler->th_list = r_list_newf ((RListFree)r_debug_profiler_th_free);
	}
	th_pr_list = profiler->th_list;
	profiler->pid = dbg->pid;
	th_list = dbg->h->threads (dbg, dbg->pid);
	time = r_sys_now ();
	r_list_foreach (th_list, iter, th) {
		bool exists = false;
		r_list_foreach (th_pr_list, iter2, th_pr) {
			if (th_pr->tid == th->pid) {
				exists = true;
				break;
			} 
		}
		if (!exists) {
			th_pr = R_NEW0 (RDebugProfilerThread);
			if (!th_pr) {
				perror ("r_debug_profiler_th/alloc RDebugProfilerThread");
				goto err_r_debug_profiler_thread;
			}
			th_pr->tid = th->pid;
			if (!th_list_app) {
				th_list_app = r_list_new ();
			}
			r_list_append (th_list_app, th_pr);
		}
		th_pr->time = time;
		r_debug_profiler_bt (dbg, th_pr);
	}
	// remove profile info from threads that do not exist
	r_list_foreach_safe (th_pr_list, iter, iter2, th_pr) {
		if (th_pr->time != time) {
			r_list_delete (th_pr_list, iter);
		}
	}
err_r_debug_profiler_thread:
	/* append new threads */
	if (th_list_app) {
		r_list_foreach (th_list_app, iter, th_pr) {
			r_list_append (th_pr_list, th_pr);
		}
		r_list_free (th_list_app);
	}
}

static int r_debug_profiler_entry(RThread *th) {
	RDebug *dbg = th->user;
	bool enabled = !th->breaked;
	bool is_profiler_bt = dbg->corebind.core &&
			dbg->corebind.cfggeti (dbg->corebind.core, "dbg.profiling.backtrace");

	dbg->h->profiling(dbg, enabled);
	if (is_profiler_bt) {
#if __WINDOWS__
		if (enabled && r_debug_thread_suspend (dbg, -1)) {
			r_debug_profiler_th (dbg);
			r_debug_thread_resume (dbg, -1);
		}
#else
		eprintf ("TODO dbg.profiling.backatrace unsupported platform");
#endif
	}
	return enabled;
}

static void r_debug_profiler_start(RDebug *dbg) {
	RDebugProfiler *profiler = &dbg->profiler;
	int refresh;

	if (!dbg->h || !dbg->h->profiling || !dbg->corebind.core ||
		!dbg->corebind.cfggeti (dbg->corebind.core, "dbg.profiling")) {
		return;
	}
	refresh = dbg->corebind.cfggeti (dbg->corebind.core, "dbg.profiling.refresh");
	profiler->th_profiler = r_th_new (r_debug_profiler_entry, dbg, 0, refresh);
	r_th_start (profiler->th_profiler, true);
}

static void r_debug_profiler_stop(RDebug *dbg) {
	RDebugProfiler *profiler = &dbg->profiler;
	if (profiler->th_profiler) {
		r_th_free (profiler->th_profiler);
		profiler->th_profiler = NULL;
	}
}

R_API void r_debug_profiler_free(RDebugProfiler *profiler) {
	r_list_free (profiler->th_list);
	profiler->th_list = NULL;
}

/*
 * Recoiling after a breakpoint has two stages:
 * 1. remove the breakpoint and fix the program counter.
 * 2. on resume, single step once and then replace the breakpoint.
 *
 * Thus, we have two functions to handle these situations.
 * r_debug_bp_hit handles stage 1.
 * r_debug_recoil handles stage 2.
 */
static int r_debug_bp_hit(RDebug *dbg, RRegItem *pc_ri, ut64 pc, RBreakpointItem **pb) {
	RBreakpointItem *b;

	if (!pb) {
		eprintf ("BreakpointItem is NULL!\n");
		return false;
	}
	/* initialize the output parameter */
	*pb = NULL;

	/* if we are tracing, update the tracing data */
	if (dbg->trace->enabled) {
		r_debug_trace_pc (dbg, pc);
	}

	/* remove all sw breakpoints for now. we'll set them back in stage 2
	 *
	 * this is necessary because while stopped we don't want any breakpoints in
	 * the code messing up our analysis.
	 */
	if (!r_bp_restore (dbg->bp, false)) { // unset sw breakpoints
		return false;
	}

	/* if we are recoiling, tell r_debug_step that we ignored a breakpoint
	 * event */
	if (!dbg->swstep && dbg->recoil_mode != R_DBG_RECOIL_NONE) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* The MIPS ptrace has a different behaviour */
# if __mips__
	/* see if we really have a breakpoint here... */
	b = r_bp_get_at (dbg->bp, pc);
	if (!b) { /* we don't. nothing left to do */
		return true;
	}
# else
	int pc_off = dbg->bpsize;
	/* see if we really have a breakpoint here... */
	b = r_bp_get_at (dbg->bp, pc - dbg->bpsize);
	if (!b) { /* we don't. nothing left to do */
		/* Some targets set pc to breakpoint */
		b = r_bp_get_at (dbg->bp, pc);
		if (!b) {
			return true;
		}
		pc_off = 0;
	}

	/* set the pc value back */
	if (pc_off) {
		pc -= pc_off;
		if (!r_reg_set_value (dbg->reg, pc_ri, pc)) {
			eprintf ("failed to set PC!\n");
			return false;
		}
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true)) {
			eprintf ("cannot set registers!\n");
			return false;
		}
	}
# endif

	*pb = b;

	/* if we are on a software stepping breakpoint, we hide what is going on... */
	if (b->swstep) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* setup our stage 2 */
	dbg->reason.bp_addr = b->addr;

	/* inform the user of what happened */
	if (dbg->hitinfo) {
		eprintf ("hit %spoint at: %"PFMT64x "\n",
				b->trace ? "trace" : "break", pc);
	}

	/* now that we've cleaned up after the breakpoint, call the other
	 * potential breakpoint handlers
	 */
	if (dbg->corebind.core && dbg->corebind.bphit) {
		dbg->corebind.bphit (dbg->corebind.core, b);
	}
	return true;
}

/* enable all software breakpoints */
static int r_debug_bps_enable(RDebug *dbg) {
	/* restore all sw breakpoints. we are about to step/continue so these need
	 * to be in place. */
	if (!r_bp_restore (dbg->bp, true))
		return false;

	/* done recoiling... */
	dbg->recoil_mode = R_DBG_RECOIL_NONE;
	return true;
}

/*
 * replace breakpoints before we continue execution
 *
 * this is called from r_debug_step_hard or r_debug_continue_kill
 *
 * this is a trick process because of breakpoints/tracepoints.
 *
 * if a breakpoint was just hit, we need step over that instruction before
 * allowing the caller to proceed as desired.
 *
 * if the user wants to step, the single step here does the job.
 */
static int r_debug_recoil(RDebug *dbg, RDebugRecoilMode rc_mode) {
	/* if bp_addr is not set, we must not have actually hit a breakpoint */
	if (!dbg->reason.bp_addr) {
		return r_debug_bps_enable (dbg);
	}

	/* don't do anything if we already are recoiling */
	if (dbg->recoil_mode != R_DBG_RECOIL_NONE) {
		/* the first time recoil is called with swstep, we just need to
		 * look up the bp and step past it.
		 * the second time it's called, the new sw breakpoint should exist
		 * so we just restore all except what we originally hit and reset.
		 */
		if (dbg->swstep) {
			if (!r_bp_restore_except (dbg->bp, true, dbg->reason.bp_addr)) {
				return false;
			}
			return true;
		}

		/* otherwise, avoid recursion */
		return true;
	}

	/* we have entered recoil! */
	dbg->recoil_mode = rc_mode;

	/* step over the place with the breakpoint and let the caller resume */
	if (r_debug_step (dbg, 1) != 1) {
		return false;
	}

	/* when stepping away from a breakpoint during recoil in stepping mode,
	 * the r_debug_bp_hit function tells us that it was called
	 * innapropriately by setting bp_addr back to zero. however, recoil_mode
	 * is still set. we use this condition to know not to proceed but
	 * pretend as if we had.
	 */
	if (!dbg->reason.bp_addr && dbg->recoil_mode == R_DBG_RECOIL_STEP) {
		return true;
	}

	return r_debug_bps_enable (dbg);
}

static int get_bpsz_arch(RDebug *dbg) {
#define CMP_ARCH(x) strncmp (dbg->arch, (x), R_MIN (len_arch, strlen ((x))))
	int bpsz , len_arch = strlen (dbg->arch);
	if (!CMP_ARCH ("arm")) {
		//TODO add better handle arm/thumb
		bpsz = 4;
	} else if (!CMP_ARCH ("mips")) {
		bpsz = 4;
	} else if (!CMP_ARCH ("ppc")) {
		bpsz = 4;
	} else if (!CMP_ARCH ("sparc")) {
		bpsz = 4;
	} else if (!CMP_ARCH ("sh")) {
		bpsz = 2;
	} else {
		bpsz = 1;
	}
	return bpsz;
}

/* add a breakpoint with some typical values */
R_API RBreakpointItem *r_debug_bp_add(RDebug *dbg, ut64 addr, int hw, bool watch, int rw, char *module, st64 m_delta) {
	int bpsz = get_bpsz_arch (dbg);
	RBreakpointItem *bpi;
	const char *module_name = module;
	RListIter *iter;
	RDebugMap *map;

	if (!addr && module) {
		bool detect_module, valid = false;
		int perm;

		if (m_delta) {
			detect_module = false;
			RList *list = r_debug_modules_list (dbg);
			r_list_foreach (list, iter, map) {
				if (strstr (map->file, module)) {
					addr = map->addr + m_delta;
					module_name = map->file;
					break;
				}
			}
			r_list_free (list);
		} else {
			//module holds the address
			addr = (ut64)r_num_math (dbg->num, module);
			if (!addr) return NULL;
			detect_module = true;
		}
		r_debug_map_sync (dbg);
		r_list_foreach (dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				valid = true;
				if (detect_module) {
					module_name = map->file;
					m_delta = addr - map->addr;
				}
				perm = ((map->perm & 1) << 2) | (map->perm & 2) | ((map->perm & 4) >> 2);
				if (!(perm & R_BP_PROT_EXEC)) {
					eprintf ("WARNING: setting bp within mapped memory without exec perm\n");
				}
				break;
			}
		}
		if (!valid) {
			eprintf ("WARNING: module's base addr + delta is not a valid address\n");
			return NULL;
		}
	}
	if (!module) {
		//express db breakpoints as dbm due to ASLR when saving into project
		r_debug_map_sync (dbg);
		r_list_foreach (dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				module_name = map->file;
				m_delta = addr - map->addr;
				break;
			}
		}
	}
	if (watch) {
		hw = 1; //XXX
		bpi = r_bp_watch_add (dbg->bp, addr, bpsz, hw, rw);
	} else {
		bpi = hw
			? r_bp_add_hw (dbg->bp, addr, bpsz, R_BP_PROT_EXEC)
			: r_bp_add_sw (dbg->bp, addr, bpsz, R_BP_PROT_EXEC);
	}
	if (bpi) {
		if (module_name) {
			bpi->module_name = strdup (module_name);
			bpi->name = r_str_newf ("%s+0x%" PFMT64x, module_name, m_delta);
		}
		bpi->module_delta = m_delta;
	}
	return bpi;
}

static const char *r_debug_str_callback(RNum *userptr, ut64 off, int *ok) {
	// RDebug *dbg = (RDebug *)userptr;
	eprintf ("STR CALLBACK WTF WTF WTF\n");
	return NULL;
}

static RDebugExcepState *r_debug_excep_state_new() {
	RDebugExcepState *excep = R_NEW0 (RDebugExcepState);
	if (!excep) {
		perror("alloc RDebugExcepState");
		return NULL;
	}
	excep->exceps_ign = r_list_newf ((RListFree)free);
	return excep;
}

static void r_debug_cond_free(RDebugCond *cond) {
	if (cond->data) {
		lua_State *lua = (lua_State *)cond->data;
		lua_close (lua);
	}
	free (cond->name);
	free (cond->cond);
	free (cond);
}

static void r_debug_excep_state_free(RDebugExcepState *excep) {
	if (!excep) {
		return;
	}
	r_list_free (excep->exceps_ign);
	free (excep);
}

static int event_sort_list(const RDebugEventHandler *ev_handler1, const RDebugEventHandler *ev_handler2) {
	if (ev_handler1->type == ev_handler2->type) {
		return 0;
	}
	if (ev_handler1->type < ev_handler2->type) {
		return -1;
	}
	return 1;
}

static bool r_debug_event_handler_append(RDebug *dbg, RDebugEventHandler *ev_handler) {
	RDebugEventHandler *ev_entry;
	RList *list = dbg->events;
	RListIter *iter;

	r_list_foreach (list, iter, ev_entry) {
		if (ev_handler->type == ev_entry->type && !strcmp (ev_entry->cmd, ev_handler->cmd)) {
			ev_entry->max_calls = ev_handler->max_calls;
			r_debug_event_handler_free (ev_handler);
			return false;
		}
	}
	r_list_add_sorted (list, ev_handler, (RListComparator)event_sort_list);
	return true;
}

static RDebugEventHandler* r_debug_event_handler_new(int type, char *cmd, int max_calls) {
	RDebugEventHandler *ev_handler = R_NEW0 (RDebugEventHandler);

	if (!ev_handler) {
		perror ("alloc RDebugEventHandler");
	} else {
		ev_handler->type = type;
		ev_handler->cmd = r_str_new (cmd);
		ev_handler->max_calls = max_calls;
	}
	return ev_handler;
}

static void r_debug_event_lib_append(RDebug *dbg, RDebugEventHandler *ev_handler, char *libname) {
	ev_handler->args = calloc (1, sizeof (void *));
	if (!ev_handler->args) {
		perror ("alloc RDebugEvenHandler arguments");
	} else {
		ev_handler->args[0] = r_str_new (libname);
		ev_handler->n_args = 1;
		r_debug_event_handler_append (dbg, ev_handler);
	}
}

R_API void r_debug_event_loadlib_append(RDebug *dbg, char *cmd, char *libname, int max_calls) {
	RDebugEventHandler *ev_handler = r_debug_event_handler_new (R_DEBUG_EVENT_LOAD_LIB, cmd, max_calls);

	if (ev_handler) {
		r_debug_event_lib_append (dbg, ev_handler, libname);
	}
}

R_API void r_debug_event_unloadlib_append(RDebug *dbg, char *cmd, char *libname, int max_calls) {
	RDebugEventHandler *ev_handler = r_debug_event_handler_new (R_DEBUG_EVENT_UNLOAD_LIB, cmd, max_calls);

	if (ev_handler) {
		r_debug_event_lib_append (dbg, ev_handler, libname);
	}
}

static char *r_debug_event_name_get(int type) {
	char *event_name;

	switch (type) {
	case R_DEBUG_EVENT_LOAD_LIB:
		event_name = "loadlib";
		break;
	case R_DEBUG_EVENT_UNLOAD_LIB:
		event_name = "unloadlib";
		break;
	default:
		event_name = "unknown";
	}
	return event_name;
}

R_API void r_debug_event_handlers_print(RDebug *dbg) {
	RList *list = dbg->events;
	RListIter *iter;
	RDebugEventHandler *ev_handler;
	int i = 0;

	r_list_foreach (list, iter, ev_handler) {
		int type = ev_handler->type;
		
		switch (type) {
		case R_DEBUG_EVENT_LOAD_LIB:
		case R_DEBUG_EVENT_UNLOAD_LIB:
			r_cons_printf ("[%d] %s \"%s\" %d:%d %s\n", i, r_debug_event_name_get (type),
							ev_handler->cmd,
							ev_handler->calls,
							ev_handler->max_calls,
							(char *)ev_handler->args[0]);
			break;
		default:
			r_cons_printf ("[%d] %s \"%s\" %d:%d\n", i, r_debug_event_name_get (type),
							ev_handler->cmd,
							ev_handler->calls,
							ev_handler->max_calls);
		}
		i++;
	}
}

R_API void r_debug_event_handler_delete(RDebug *dbg, int idx) {
	RList *list = dbg->events;
	RListIter *iter = list->head;
	int i = 0;

	for (;iter; iter = iter->n) {
		if (i == idx) {
			r_list_delete (list, iter);
			break;
		}	
		i++;
	}
}

R_API void r_debug_excep_ign_append(RDebug *dbg, ut64 code) {
	RListIter *iter;
	RDebugExcepState *state = dbg->excep;
	RList *list = state->exceps_ign;
	RDebugExcep *excep_ign, *excep;

	r_list_foreach (list, iter, excep_ign) {
		if (code == excep_ign->code) {
			return;
		}
	}
	excep = R_NEW0 (RDebugExcep);
	if (!excep) {
		perror ("alloc RDebugExcep");
	} else {
		excep->code = code;
		r_list_append (list, excep);
	}
}

R_API void r_debug_excep_ign_delete(RDebug *dbg, ut64 code) {
	RListIter *iter;
	RDebugExcepState *state = dbg->excep;
	RList *list = state->exceps_ign;
	RDebugExcep *excep_ign;

	r_list_foreach (list, iter, excep_ign) {
		if (code == excep_ign->code) {
			r_list_delete (list, iter);
		}
	}
}

R_API bool r_debug_excep_ign(RDebug *dbg, ut64 code) {
	RListIter *iter;
	RDebugExcepState *state = dbg->excep;
	RList *list = state->exceps_ign;
	RDebugExcep *excep_ign;

	r_list_foreach (list, iter, excep_ign) {
		if (code == excep_ign->code) {
			return true;
		}
	}
	return false;
}

R_API RDebug *r_debug_new(int hard) {
	RDebug *dbg = R_NEW0 (RDebug);
	if (!dbg) {
		return NULL;
	}
	// R_SYS_ARCH
	dbg->arch = strdup (R_SYS_ARCH);
	dbg->bits = R_SYS_BITS;
	dbg->trace_forks = 1;
	dbg->forked_pid = -1;
	dbg->main_pid = -1;
	dbg->trace_clone = 0;
	dbg->egg = r_egg_new ();
	r_egg_setup (dbg->egg, R_SYS_ARCH, R_SYS_BITS, R_SYS_ENDIAN, R_SYS_OS);
	dbg->trace_aftersyscall = true;
	dbg->follow_child = false;
	R_FREE (dbg->btalgo);
	dbg->trace_execs = 0;
	dbg->anal = NULL;
	dbg->excep = r_debug_excep_state_new ();
	dbg->snaps = r_list_newf ((RListFree)r_debug_snap_free);
	dbg->sessions = r_list_newf ((RListFree)r_debug_session_free);
	dbg->conds = r_list_newf ((RListFree)r_debug_cond_free);
	dbg->events = r_list_newf ((RListFree)r_debug_event_handler_free);
	dbg->pid = -1;
	dbg->bpsize = 1;
	dbg->tid = -1;
	dbg->tree = r_tree_new ();
	dbg->tracenodes = sdb_new0 ();
	dbg->swstep = 0;
	dbg->stop_all_threads = false;
	dbg->trace = r_debug_trace_new ();
	dbg->cb_printf = (void *)printf;
	dbg->reg = r_reg_new ();
	dbg->num = r_num_new (r_debug_num_callback, r_debug_str_callback, dbg);
	dbg->h = NULL;
	dbg->threads = NULL;
	dbg->hitinfo = 1;
	/* TODO: needs a redesign? */
	dbg->maps = r_debug_map_list_new ();
	dbg->maps_user = r_debug_map_list_new ();
	r_debug_signal_init (dbg);
	if (hard) {
		dbg->bp = r_bp_new ();
		r_debug_plugin_init (dbg);
		dbg->bp->iob.init = false;
	}
	return dbg;
}

static int free_tracenodes_entry (RDebug *dbg, const char *k, const char *v) {
	ut64 v_num = r_num_get (NULL, v);
	free((void *)(size_t)v_num);
	return true;
}

R_API void r_debug_tracenodes_reset (RDebug *dbg) {
	sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
	sdb_reset (dbg->tracenodes);
}

R_API RDebug *r_debug_free(RDebug *dbg) {
	if (dbg) {
		/* free internal native data */
		if (dbg && dbg->h && dbg->h->free) {
			dbg->h->free(dbg);
		}
		// TODO: free it correctly.. we must ensure this is an instance and not a reference..
		r_bp_free (dbg->bp);
		//r_reg_free(&dbg->reg);
		free (dbg->snap_path);
		r_debug_excep_state_free (dbg->excep);
		r_debug_profiler_free (&dbg->profiler);
		r_list_free (dbg->snaps);
		r_list_free (dbg->sessions);
		r_list_free (dbg->maps);
		r_list_free (dbg->maps_user);
		r_list_free (dbg->conds);
		r_list_free (dbg->events);
		r_num_free (dbg->num);
		sdb_free (dbg->sgnls);
		r_tree_free (dbg->tree);
		sdb_foreach (dbg->tracenodes, (SdbForeachCallback)free_tracenodes_entry, dbg);
		sdb_free (dbg->tracenodes);
		r_list_free (dbg->plugins);
		free (dbg->btalgo);
		r_debug_trace_free (dbg->trace);
		dbg->trace = NULL;
		r_egg_free (dbg->egg);
		free (dbg->arch);
		free (dbg->glob_libs);
		free (dbg->glob_unlibs);
		free (dbg);
	}
	return NULL;
}

R_API int r_debug_attach(RDebug *dbg, int pid) {
	int ret = false;

	if (dbg && dbg->h && dbg->h->attach) {
		ret = dbg->h->attach (dbg, pid);
		if (ret != -1) {
			r_debug_select (dbg, pid, ret);
		}
	}
	return ret;
}

R_API int r_debug_is_attached(RDebug *dbg, int pid) {
	int ret;

	if (dbg && dbg->h && dbg->h->attached) {
		ret = dbg->h->attached (dbg, pid);
	} else {
		ret = -1;
	}
	return ret;
}

/* stop execution of child process */
R_API int r_debug_stop(RDebug *dbg) {
	if (dbg && dbg->h && dbg->h->stop) {
		return dbg->h->stop (dbg);
	}
	return false;
}

R_API bool r_debug_set_arch(RDebug *dbg, const char *arch, int bits) {
	if (arch && dbg && dbg->h) {
		bool rc = r_sys_arch_match (dbg->h->arch, arch);
		if (rc) {
			switch (bits) {
			case 27:
				if (dbg->h->bits == 27) {
					dbg->bits = 27;
				}
				break;
			case 32:
				if (dbg->h->bits & R_SYS_BITS_32) {
					dbg->bits = R_SYS_BITS_32;
				}
				break;
			case 64:
				dbg->bits = R_SYS_BITS_64;
				break;
			}
			if (!dbg->h->bits) {
				dbg->bits = dbg->h->bits;
			} else if (!(dbg->h->bits & dbg->bits)) {
				dbg->bits = dbg->h->bits & R_SYS_BITS_64;
				if (!dbg->bits) {
					dbg->bits = dbg->h->bits & R_SYS_BITS_32;
				}
				if (!dbg->bits) {
					dbg->bits = R_SYS_BITS_32;
				}
			}
			free (dbg->arch);
			dbg->arch = strdup (arch);
			return true;
		}
	}
	return false;
}

/*
 * Save 4096 bytes from %esp
 * TODO: Add support for reverse stack architectures
 * Also known as r_debug_inject()
 */
R_API ut64 r_debug_execute(RDebug *dbg, const ut8 *buf, int len, int restore) {
	int orig_sz;
	ut8 stackbackup[4096];
	ut8 *backup, *orig = NULL;
	RRegItem *ri, *risp, *ripc;
	ut64 rsp, rpc, ra0 = 0LL;
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	ripc = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], R_REG_TYPE_GPR);
	risp = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_SP], R_REG_TYPE_GPR);
	if (ripc) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		orig = r_reg_get_bytes (dbg->reg, -1, &orig_sz);
		if (!orig) {
			eprintf ("Cannot get register arena bytes\n");
			return 0LL;
		}
		rpc = r_reg_get_value (dbg->reg, ripc);
		rsp = r_reg_get_value (dbg->reg, risp);

		backup = malloc (len);
		if (!backup) {
			free (orig);
			return 0LL;
		}
		dbg->iob.read_at (dbg->iob.io, rpc, backup, len);
		dbg->iob.read_at (dbg->iob.io, rsp, stackbackup, len);

		r_bp_add_sw (dbg->bp, rpc+len, dbg->bpsize, R_BP_PROT_EXEC);

		/* execute code here */
		dbg->iob.write_at (dbg->iob.io, rpc, buf, len);
		//r_bp_add_sw (dbg->bp, rpc+len, 4, R_BP_PROT_EXEC);
		r_debug_continue (dbg);
		//r_bp_del (dbg->bp, rpc+len);
		/* TODO: check if stopped in breakpoint or not */

		r_bp_del (dbg->bp, rpc+len);
		dbg->iob.write_at (dbg->iob.io, rpc, backup, len);
		if (restore) {
			dbg->iob.write_at (dbg->iob.io, rsp, stackbackup, len);
		}

		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_A0], R_REG_TYPE_GPR);
		ra0 = r_reg_get_value (dbg->reg, ri);
		if (restore) {
			r_reg_read_regs (dbg->reg, orig, orig_sz);
		} else {
			r_reg_set_value (dbg->reg, ripc, rpc);
		}
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, true);
		free (backup);
		free (orig);
		eprintf ("ra0=0x%08"PFMT64x"\n", ra0);
	} else eprintf ("r_debug_execute: Cannot get program counter\n");
	return (ra0);
}

R_API int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv) {
	/* TODO : r_debug_startv unimplemented */
	return false;
}

R_API int r_debug_start(RDebug *dbg, const char *cmd) {
	/* TODO: this argc/argv parser is done in r_io */
	// TODO: parse cmd and generate argc and argv
	return false;
}

R_API int r_debug_detach(RDebug *dbg, int pid) {
	if (dbg->h && dbg->h->detach) {
		return dbg->h->detach (dbg, pid);
	}
	return false;
}

R_API bool r_debug_select(RDebug *dbg, int pid, int tid) {
	if (pid < 0) {
		return false;
	}
	if (tid < 0) {
		tid = pid;
	}
	if (pid != -1 && tid != -1) {
		if (pid != dbg->pid || tid != dbg->tid) {
			eprintf ("= attach %d %d\n", pid, tid);
		}
	} else {
		if (dbg->pid != -1) {
			eprintf ("Child %d is dead\n", dbg->pid);
		}
	}
	if (pid < 0 || tid < 0) {
		return false;
	}

	if (dbg->h && dbg->h->select && !dbg->h->select (dbg, pid, tid))
		return false;

	r_io_system (dbg->iob.io, sdb_fmt (0, "pid %d", pid));

	dbg->pid = pid;
	dbg->tid = tid;

	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);

	return true;
}

R_API const char *r_debug_reason_to_string(int type) {
	switch (type) {
	case R_DEBUG_REASON_DEAD: return "dead";
	case R_DEBUG_REASON_ABORT: return "abort";
	case R_DEBUG_REASON_SEGFAULT: return "segfault";
	case R_DEBUG_REASON_NONE: return "none";
	case R_DEBUG_REASON_SIGNAL: return "signal";
	case R_DEBUG_REASON_BREAKPOINT: return "breakpoint";
	case R_DEBUG_REASON_TRACEPOINT: return "tracepoint";
	case R_DEBUG_REASON_READERR: return "read-error";
	case R_DEBUG_REASON_WRITERR: return "write-error";
	case R_DEBUG_REASON_DIVBYZERO: return "div-by-zero";
	case R_DEBUG_REASON_ILLEGAL: return "illegal";
	case R_DEBUG_REASON_UNKNOWN: return "unknown";
	case R_DEBUG_REASON_ERROR: return "error";
	case R_DEBUG_REASON_NEW_PID: return "new-pid";
	case R_DEBUG_REASON_NEW_TID: return "new-tid";
	case R_DEBUG_REASON_NEW_LIB: return "new-lib";
	case R_DEBUG_REASON_EXIT_PID: return "exit-pid";
	case R_DEBUG_REASON_EXIT_TID: return "exit-tid";
	case R_DEBUG_REASON_EXIT_LIB: return "exit-lib";
	case R_DEBUG_REASON_TRAP: return "trap";
	case R_DEBUG_REASON_SWI: return "software-interrupt";
	case R_DEBUG_REASON_INT: return "interrupt";
	case R_DEBUG_REASON_FPU: return "fpu";
	case R_DEBUG_REASON_STEP: return "step";
	case R_DEBUG_REASON_USERSUSP: return "suspended-by-user";
	}
	return "unhandled";
}

R_API RDebugReasonType r_debug_stop_reason(RDebug *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// return dbg->reason
	return dbg->reason.type;
}

static void *lua_alloc(void *ud,
                             void *ptr,
                             size_t osize,
                             size_t nsize) {
	if (nsize == 0) {
		free (ptr);
		return NULL;
	}
	return realloc (ptr, nsize);
}

static void r_debug_lua_vars_fill(RDebug *dbg, lua_State *lua, bool set) {
	int i;

	/* set registers values */
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RListIter *iter;
		RRegItem *item;
		RList *head = r_reg_get_list (dbg->reg, i);
		if (!head) {
			continue;
		}
		r_list_foreach (head, iter, item) {
			if (item->size < 80) {
				ut64 value = r_reg_get_value (dbg->reg, item);
				if (set) {
					lua_pushnumber (lua, (lua_Number)value);
				} else {
					lua_pushnil (lua);
				}
				lua_setglobal (lua, item->name);
			}
		}
	}
	/* set pid, tid */
	if (set) {
		lua_pushinteger (lua, (lua_Integer)dbg->pid);
	} else {
		lua_pushnil (lua);
	}
	lua_setglobal (lua, "pid");
	if (set) {
		lua_pushinteger (lua, (lua_Integer)dbg->tid);
	} else {
		lua_pushnil (lua);
	}
	lua_setglobal (lua, "tid");
}

RDebugCond *r_debug_cond_find(RDebug *dbg, const char *name) {
	RList *conds = dbg->conds;
	RListIter *iter;
	RDebugCond *cond_item;

	r_list_foreach (conds, iter, cond_item) {
		if (!strcmp (name, cond_item->name)) {
			return cond_item;
		}
	}
	return NULL;
}

static int lua_expr(lua_State *lua) {
	RDebug *dbg;
	int n_args = lua_gettop (lua);
	const char *expr;
	RCore *core;

	if (n_args != 1) {
		return 0;
	}
	if (!lua_isstring (lua, 1)) {
            lua_pushstring (lua, "the argument is not a string value");
            lua_error (lua);
	}
	expr = lua_tostring (lua, 2);
	dbg = (RDebug *)lua_touserdata (lua, -1);
	if (!dbg) {
            lua_pushstring (lua, "lua_mem_read internal error dbg is NULL");
            lua_error (lua);
	}
	core = (RCore *)dbg->corebind.core;
	lua_pushinteger (lua, r_num_calc (core->num, expr, NULL));
	return 1;
}

static int lua_dread(lua_State *lua) {
	ut64 addr;
	int len;
	RDebug *dbg;
	int n_args = lua_gettop (lua);
	ut8 *buff = NULL;

	if (n_args < 2) {
		return 0;
	}
	if (!lua_isinteger (lua, 1)) {
            lua_pushstring (lua, "fist argument is not address value");
            lua_error (lua);
	}
	addr = lua_tointeger (lua, 1);
	if (!lua_isinteger (lua, 2)) {
            lua_pushstring (lua, "second argument is not length value");
            lua_error (lua);
	}
	len = lua_tointeger (lua, 2);
	if (len <= 0 || len > MAX_LUA_MEM_READ_LENGTH) {
            lua_pushstring (lua, "invalid length value");
            lua_error (lua);
	}
	lua_getglobal(lua, "_dbg_");
	dbg = (RDebug *)lua_touserdata (lua, -1);
	if (!dbg) {
            lua_pushstring (lua, "lua_mem_read internal error dbg is NULL");
            lua_error (lua);
	}
	buff = (ut8 *)calloc (1, len);
	if (!buff) {
            lua_pushstring (lua, "can not reserve memory to read");
            lua_error (lua);
	}
	if (!dbg->iob.read_at (dbg->iob.io, addr, buff, len)) {
		lua_pushnil (lua);
	} else {
		int i;
		lua_newtable (lua);
		for (i = 1; i <= len; i++) {
			lua_pushnumber (lua, i);
			lua_pushinteger (lua, buff[i - 1]);
			lua_settable (lua, -3);
		}
	}
	free (buff);
	return 1;
}

static int lua_dstrcmp(lua_State *lua) {
	ut64 addr;
	int len;
	RDebug *dbg;
	int n_args = lua_gettop (lua);
	ut8 *buff = NULL;
	const char *str;

	if (n_args < 2) {
		return 0;
	}
	if (!lua_isinteger (lua, 1)) {
            lua_pushstring (lua, "fist argument is not address value");
            lua_error (lua);
	}
	addr = lua_tointeger (lua, 1);
	if (!lua_isstring (lua, 2)) {
            lua_pushstring (lua, "second argument is not string value");
            lua_error (lua);
	}
	str = lua_tostring (lua, 2);

	if (n_args < 3) {
		len = strlen (str);
	} else {
		if (!lua_isinteger (lua, 3)) {
	            lua_pushstring (lua, "second argument is not length value");
        	    lua_error (lua);
		}
		len = lua_tointeger (lua, 3);
		if (len <= 0 || len > MAX_LUA_MEM_READ_LENGTH) {
        	    lua_pushstring (lua, "invalid length value");
	            lua_error (lua);
		}
	}
	lua_getglobal(lua, "_dbg_");
	dbg = (RDebug *)lua_touserdata (lua, -1);
	if (!dbg) {
            lua_pushstring (lua, "lua_mem_read internal error dbg is NULL");
            lua_error (lua);
	}
	buff = (ut8 *)calloc (1, len);
	if (!buff) {
            lua_pushstring (lua, "can not reserve memory to read");
            lua_error (lua);
	}
	if (!dbg->iob.read_at (dbg->iob.io, addr, buff, len)) {
		lua_pushinteger (lua, -1);
	} else {
		lua_pushinteger (lua, memcmp (buff, str, len));
	}
	free (buff);
	return 1;
}

static lua_State *r_debug_cond_lua_get(RDebug *dbg, const char *cond, char **ret_err) {
	lua_State *lua;
	bool success = false;

	lua = lua_newstate (lua_alloc, NULL);
	if (!lua) {
		if (ret_err) {
			*ret_err = strdup("can not get a lua_State");
		}
		goto err_r_debug_cond_lua_get;
    	}
	luaL_openlibs (lua);
	if (luaL_loadstring (lua, cond)) {
		if (ret_err && lua_isstring (lua, -1)) {
			*ret_err = strdup (lua_tostring (lua, -1));
			lua_pop (lua, 1);
		}
	} else {
		success = true;
	}
err_r_debug_cond_lua_get:
	if (!success && lua) {
		lua_close (lua);
		lua = NULL;
	}
	return lua;
}

static bool r_debug_cond_eval(RDebug *dbg, RDebugCond *cond_item) {
	bool cond_eval = false;
	lua_State *lua = (lua_State *)cond_item->data;

	if (!lua) {
		char *cond_func = r_str_newf ("function cond()\n%s\nend", cond_item->cond);
		lua = r_debug_cond_lua_get (dbg, cond_func, NULL);
		lua_pcall (lua, 0, 0, 0);
		lua_pushlightuserdata (lua, dbg);
		lua_setglobal (lua, "_dbg_");
		lua_register (lua, "dread", lua_dread);
		lua_register (lua, "dstrcmp", lua_dstrcmp);
		lua_register (lua, "expr", lua_expr);
		cond_item->data = lua;
		free (cond_func);
	}
	if (lua) {
		r_debug_lua_vars_fill (dbg, lua, true);
		lua_getglobal (lua, "cond");
		if (!lua_pcall (lua, 0, 1, 0)) {
			if (lua_isboolean (lua, -1)) {
				cond_eval = lua_toboolean (lua, -1);
				lua_pop (lua, 1);
			}
		}
		lua_settop (lua, 0);
	}
	return (bool)cond_eval;
}

bool r_debug_cond_add(RDebug *dbg, const char *name, const char *cond, char **ret_err) {
	bool success = false;
	lua_State *lua;

	lua = r_debug_cond_lua_get (dbg, cond, ret_err);
	if (lua) {
		RDebugCond *cond_item;
	
		cond_item = r_debug_cond_find (dbg, name);	
		if (cond_item) {
			r_debug_cond_del (dbg, name);
		}
		cond_item = R_NEW0 (RDebugCond);
		if (cond_item) {
			cond_item->name = strdup (name);
			cond_item->cond = strdup (cond);
			r_list_append (dbg->conds, cond_item);
			success = true;
		} else {
			perror ("alloc RDebugCond");
		}
		lua_close (lua);
	}
	return success;
}

bool r_debug_cond_del(RDebug *dbg, const char *name) {
	RList *conds = dbg->conds;
	RListIter *iter;
	RDebugCond *cond_item;

	r_list_foreach (conds, iter, cond_item) {
		if (!strcmp (name, cond_item->name)) {
			r_list_delete (conds, iter);
			return true;
		}
	}
	return false;
}

void r_debug_cond_print(RDebug *dbg, const char *name) {
	RListIter *iter;
	RDebugCond *cond_item;
	RList *conds = dbg->conds;

	r_list_foreach (conds, iter, cond_item) {
		if (!name || !strcmp (cond_item->name, name)) {
			dbg->cb_printf ("\ncondition '%s':\n%s\n", cond_item->name, cond_item->cond);
			if (name) {
				break;
			}
		}
	}
}

/*
 * wait for an event to happen on the selected pid/tid
 *
 * Returns  R_DEBUG_REASON_*
 */
R_API RDebugReasonType r_debug_wait(RDebug *dbg, RBreakpointItem **bp) {
	RDebugReasonType reason = R_DEBUG_REASON_ERROR;
	if (!dbg) {
		return reason;
	}

	if (bp) {
		*bp = NULL;
	}
	/* default to unknown */
	dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
	if (r_debug_is_dead (dbg)) {
		return R_DEBUG_REASON_DEAD;
	}

	/* if our debugger plugin has wait */
	if (dbg->h && dbg->h->wait) {
		reason = dbg->h->wait (dbg, dbg->pid);
		if (reason == R_DEBUG_REASON_DEAD) {
			eprintf ("\n==> Process finished\n\n");
			// XXX(jjd): TODO: handle fallback or something else
			//r_debug_select (dbg, -1, -1);
			return R_DEBUG_REASON_DEAD;
		}

		/* propagate errors from the plugin */
		if (reason == R_DEBUG_REASON_ERROR) {
			return R_DEBUG_REASON_ERROR;
		}
		/* read general purpose registers */
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			return R_DEBUG_REASON_ERROR;
		}

		bool libs_bp = (dbg->glob_libs || dbg->glob_unlibs) ? true : false;
		/* if the underlying stop reason is a breakpoint, call the handlers */
		if (reason == R_DEBUG_REASON_BREAKPOINT || reason == R_DEBUG_REASON_STEP ||
			(libs_bp &&
			((reason == R_DEBUG_REASON_NEW_LIB) || (reason == R_DEBUG_REASON_EXIT_LIB)))) {
			RRegItem *pc_ri;
			RBreakpointItem *b = NULL;
			ut64 pc;

			/* get the program coounter */
			pc_ri = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], -1);
			if (!pc_ri) { /* couldn't find PC?! */
				return R_DEBUG_REASON_ERROR;
			}

			/* get the value */
			pc = r_reg_get_value (dbg->reg, pc_ri);

			if (!r_debug_bp_hit (dbg, pc_ri, pc, &b)) {
				return R_DEBUG_REASON_ERROR;
			}
			if (bp) {
				*bp = b;
			}
			/* if we hit a tracing breakpoint, we need to continue in
			 * whatever mode the user desired. */
			if (dbg->corebind.core && b) {
				if (b->cond_cmd) {
					reason = R_DEBUG_REASON_COND_CMD;
				} else if (b->cond) {
					reason = R_DEBUG_REASON_COND;
				}
			}
			if (b && b->trace) {
				reason = R_DEBUG_REASON_TRACEPOINT;
			}
		}

		dbg->reason.type = reason;
		if (reason == R_DEBUG_REASON_SIGNAL && dbg->reason.signum != -1) {
			/* handle signal on continuations here */
			eprintf ("got signal...\n");
			int what = r_debug_signal_what (dbg, dbg->reason.signum);
			const char *name = r_signal_to_string (dbg->reason.signum);
			if (name && strcmp ("SIGTRAP", name)) {
				r_cons_printf ("[+] signal %d aka %s received %d\n",
						dbg->reason.signum, name, what);
			}
		}
	}
	return reason;
}

R_API int r_debug_step_soft(RDebug *dbg) {
	ut8 buf[32];
	ut64 pc, sp, r;
	ut64 next[2];
	RAnalOp op;
	int br, i, ret;
	union {
		ut64 r64;
		ut32 r32[2];
	} sp_top;
	union {
		ut64 r64;
		ut32 r32[2];
	} memval;

	if (dbg->recoil_mode == R_DBG_RECOIL_NONE) {
		dbg->recoil_mode = R_DBG_RECOIL_STEP;
	}

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	sp = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_SP]);

	if (!dbg->iob.read_at) {
		return false;
	}
	if (!dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf))) {
		return false;
	}
	if (!r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf))) {
		return false;
	}
	if (op.type == R_ANAL_OP_TYPE_ILL) {
		return false;
	}
	switch (op.type) {
	case R_ANAL_OP_TYPE_RET:
		dbg->iob.read_at (dbg->iob.io, sp, (ut8 *)&sp_top, 8);
		next[0] = (dbg->bits == R_SYS_BITS_32) ? sp_top.r32[0] : sp_top.r64;
		br = 1;
		break;
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_CCALL:
		next[0] = op.jump;
		next[1] = op.fail;
		br = 2;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
		next[0] = op.jump;
		br = 1;
		break;
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_RCALL:
		r = r_debug_reg_get (dbg,op.reg);
		next[0] = r;
		br = 1;
		break;
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_IRJMP:
		r = r_debug_reg_get (dbg,op.reg);
		if (!dbg->iob.read_at (dbg->iob.io, r, (ut8*)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = (dbg->bits == R_SYS_BITS_32) ? memval.r32[0] : memval.r64;
		}
		br = 1;
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_MJMP:
		if (op.ireg) {
			r = r_debug_reg_get (dbg,op.ireg);
		} else {
			r = 0;
		}
		if (!dbg->iob.read_at (dbg->iob.io,
		      r*op.scale + op.disp, (ut8*)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = (dbg->bits == R_SYS_BITS_32) ? memval.r32[0] : memval.r64;
		}
		br = 1;
		break;
	case R_ANAL_OP_TYPE_UJMP:
	default:
		next[0] = op.addr + op.size;
		br = 1;
		break;
	}

	for (i = 0; i < br; i++) {
		RBreakpointItem *bpi = r_bp_add_sw (dbg->bp, next[i], dbg->bpsize, R_BP_PROT_EXEC);
		if (bpi) {
			bpi->swstep = true;
		}
	}

	ret = r_debug_continue (dbg);

	for (i = 0; i < br; i++) {
		r_bp_del (dbg->bp, next[i]);
	}

	return ret;
}

R_API int r_debug_step_hard(RDebug *dbg) {
	RDebugReasonType reason;

	dbg->reason.type = R_DEBUG_REASON_STEP;
	if (r_debug_is_dead (dbg)) {
		return false;
	}

	/* only handle recoils when not already in recoil mode. */
	if (dbg->recoil_mode == R_DBG_RECOIL_NONE) {
		/* handle the stage-2 of breakpoints */
		if (!r_debug_recoil (dbg, R_DBG_RECOIL_STEP)) {
			return false;
		}

		/* recoil already stepped once, so we don't step again. */
		if (dbg->recoil_mode == R_DBG_RECOIL_STEP) {
			dbg->recoil_mode = R_DBG_RECOIL_NONE;
			return true;
		}
	}

	if (!dbg->h->step (dbg)) {
		return false;
	}
	reason = r_debug_wait (dbg, NULL);
	/* TODO: handle better */
	if (reason == R_DEBUG_REASON_ERROR) {
		return false;
	}
	if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
		return false;
	}
	return true;
}

R_API int r_debug_step(RDebug *dbg, int steps) {
	int ret, steps_taken = 0;

	/* who calls this without giving a positive number? */
	if (steps < 1) {
		steps = 1;
	}

	if (!dbg || !dbg->h) {
		return steps_taken;
	}

	if (r_debug_is_dead (dbg)) {
		return steps_taken;
	}

	dbg->reason.type = R_DEBUG_REASON_STEP;

	for (; steps_taken < steps; steps_taken++) {
		if (dbg->swstep) {
			ret = r_debug_step_soft (dbg);
		} else {
			ret = r_debug_step_hard (dbg);
		}
		if (!ret) {
			eprintf ("Stepping failed!\n");
			return steps_taken;
		}
		dbg->steps++;
		dbg->reason.type = R_DEBUG_REASON_STEP;
	}

	return steps_taken;
}

R_API void r_debug_io_bind(RDebug *dbg, RIO *io) {
	r_io_bind (io, &dbg->bp->iob);
	r_io_bind (io, &dbg->iob);
	io->user = dbg;
}

R_API int r_debug_step_over(RDebug *dbg, int steps) {
	RAnalOp op;
	ut64 buf_pc, pc, ins_size;
	ut8 buf[DBG_BUF_SIZE];
	int steps_taken = 0;

	if (r_debug_is_dead (dbg)) {
		return steps_taken;
	}

	if (steps < 1) {
		steps = 1;
	}

	if (dbg->h && dbg->h->step_over) {
		for (; steps_taken < steps; steps_taken++)
			if (!dbg->h->step_over (dbg))
				return steps_taken;
		return steps_taken;
	}

	if (!dbg->anal || !dbg->reg)
		return steps_taken;

	// Initial refill
	buf_pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	for (; steps_taken < steps; steps_taken++) {
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc))) {
			eprintf ("Decode error at %"PFMT64x"\n", pc);
			return steps_taken;
		}
		if (op.fail == -1) {
			ins_size = pc + op.size;
		} else {
			// Use op.fail here instead of pc+op.size to enforce anal backends to fill in this field
			ins_size = op.fail;
		}
		// Skip over all the subroutine calls
		if ((op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CALL ||
			(op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL) {
			if (!r_debug_continue_until (dbg, ins_size)) {
				eprintf ("Could not step over call @ 0x%"PFMT64x"\n", pc);
				return steps_taken;
			}
		} else if ((op.prefix & (R_ANAL_OP_PREFIX_REP | R_ANAL_OP_PREFIX_REPNE | R_ANAL_OP_PREFIX_LOCK))) {
			//eprintf ("REP: skip to next instruction...\n");
			if (!r_debug_continue_until (dbg, ins_size)) {
				eprintf ("step over failed over rep\n");
				return steps_taken;
			}
		} else {
			r_debug_step (dbg, 1);
		}
	}

	return steps_taken;
}

R_API int r_debug_step_back(RDebug *dbg) {
	ut64 pc, prev = 0, end, cnt = 0;
	RDebugSession *before;

	if (r_debug_is_dead (dbg)) {
		return 0;
	}
	if (!dbg->anal || !dbg->reg) {
		return 0;
	}
	if (r_list_empty (dbg->sessions)) {
		return 0;
	}

	end = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);

	/* Get previous state */
	before = r_debug_session_get (dbg, dbg->sessions->tail);
	if (!before) {
		return 0;
	}
	//eprintf ("before session (%d) 0x%08"PFMT64x"\n", before->key.id, before->key.addr);

	/* Rollback to previous state */
	r_debug_session_set (dbg, before);

	pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	//eprintf ("execute from 0x%08"PFMT64x" to 0x%08"PFMT64x"\n", pc, end);

	/* Get the previous operation address.
	 * XXX: too slow... */
	for (;;) {
		if (r_debug_is_dead (dbg)) {
			goto fail;
		}
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		if (pc == end) {
			/* Reached the target address */
			break;
		}
		prev = pc;
		//eprintf ("executing 0x%08"PFMT64x"\n", pc);
		if (cnt > CHECK_POINT_LIMIT) {
			//eprintf ("Hit count limit %lld\n", cnt);
			r_debug_session_add (dbg, NULL);
			cnt = 0;
		}
		if (!r_debug_step (dbg, 1)) {
			goto fail;
		}
		cnt++;
	}

	/* Finally, run to the desired point */
	r_debug_session_set (dbg, before);
	if (prev) {
		eprintf ("continue until 0x%08"PFMT64x"\n", prev);
		r_debug_continue_until_nonblock (dbg, prev);
	}
	return 1;
fail:
	return 0;
}

R_API int r_debug_continue_kill(RDebug *dbg, int sig) {
	RDebugReasonType reason, ret = false;
	RBreakpointItem *bp = NULL;

	if (!dbg) {
		return false;
	}
#if __WINDOWS__
	r_cons_break_push (w32_break_proc, dbg);
#endif
repeat:
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	if (dbg->h && dbg->h->cont) {
		/* handle the stage-2 of breakpoints */
		if (!r_debug_recoil (dbg, R_DBG_RECOIL_CONTINUE)) {
#if __WINDOWS__
			r_cons_break_pop ();
#endif
			return false;
		}
		/* tell the inferior to go! */
		ret = dbg->h->cont (dbg, dbg->pid, dbg->tid, sig);
		//XXX(jjd): why? //dbg->reason.signum = 0;

		r_debug_profiler_start (dbg);
		reason = r_debug_wait (dbg, &bp);
		r_debug_profiler_stop (dbg);
		if (dbg->corebind.core && bp) {
			RCore *core = (RCore *)dbg->corebind.core;
			if (reason == R_DEBUG_REASON_COND_CMD) {
				if (bp->cond_cmd && dbg->corebind.cmd) {
					dbg->corebind.cmd (dbg->corebind.core, bp->cond_cmd);
				}
				if (core->num->value) {
					goto repeat;
				}
			} else if (reason == R_DEBUG_REASON_COND) {
				RDebugCond *cond_item = r_debug_cond_find (dbg, bp->cond);
				if (!cond_item) {
					reason = R_DEBUG_REASON_BREAKPOINT;
				} else if (!r_debug_cond_eval (dbg, cond_item)) {
					goto repeat;
				}
			}
		}
		if (reason == R_DEBUG_REASON_BREAKPOINT &&
		   ((bp && !bp->enabled) || (!bp && !r_cons_is_breaked () && dbg->corebind.core &&
			   		    dbg->corebind.cfggeti (dbg->corebind.core, "dbg.bpsysign")))) {
			goto repeat;
		}

#if __linux__
		if (reason == R_DEBUG_REASON_NEW_PID && dbg->follow_child) {
#if DEBUGGER
			/// if the plugin is not compiled link fails, so better do runtime linking
			/// until this code gets fixed
			static void (*linux_attach_new_process) (RDebug *dbg) = NULL;
			if (!linux_attach_new_process) {
				linux_attach_new_process = r_lib_dl_sym (NULL, "linux_attach_new_process");
			}
			if (linux_attach_new_process) {
				linux_attach_new_process (dbg);
			}
#endif
			goto repeat;
		}

		if (reason == R_DEBUG_REASON_NEW_TID) {
			ret = dbg->tid;
			if (!dbg->trace_clone) {
				goto repeat;
			}
		}

		if (reason == R_DEBUG_REASON_EXIT_TID) {
			goto repeat;
		}
#endif
#if __WINDOWS__
		if (reason != R_DEBUG_REASON_DEAD) {
			// XXX(jjd): returning a thread id?!
			ret = dbg->tid;
		}
		if (reason == R_DEBUG_REASON_NEW_LIB ||
			reason == R_DEBUG_REASON_EXIT_LIB ||
			reason == R_DEBUG_REASON_NEW_TID ||
			reason == R_DEBUG_REASON_EXIT_TID ) {
			goto repeat;
		}
		if (reason == R_DEBUG_REASON_EXIT_PID) {
			dbg->pid = -1;
		}
#endif

		/* if continuing killed the inferior, we won't be able to get
		 * the registers.. */
		if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
#if __WINDOWS__
			r_cons_break_pop ();
#endif
			return false;
		}

		/* if we hit a tracing breakpoint, we need to continue in
		 * whatever mode the user desired. */
		if (reason == R_DEBUG_REASON_TRACEPOINT) {
			r_debug_step (dbg, 1);
			goto repeat;
		}

		/* choose the thread that was returned from the continue function */
		// XXX(jjd): there must be a cleaner way to do this...
		r_debug_select (dbg, dbg->pid, ret);
		sig = 0; // clear continuation after signal if needed

		/* handle general signals here based on the return from the wait
		 * function */
		if (dbg->reason.signum != -1) {
			int what = r_debug_signal_what (dbg, dbg->reason.signum);
			if (what & R_DBG_SIGNAL_CONT) {
				sig = dbg->reason.signum;
				eprintf ("Continue into the signal %d handler\n", sig);
				goto repeat;
			} else if (what & R_DBG_SIGNAL_SKIP) {
				// skip signal. requires skipping one instruction
				ut8 buf[64];
				RAnalOp op = {0};
				ut64 pc = r_debug_reg_get (dbg, "PC");
				dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
				r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
				if (op.size > 0) {
					const char *signame = r_signal_to_string (dbg->reason.signum);
					r_debug_reg_set (dbg, "PC", pc+op.size);
					eprintf ("Skip signal %d handler %s\n",
						dbg->reason.signum, signame);
					goto repeat;
				} else {
					ut64 pc = r_debug_reg_get (dbg, "PC");
					eprintf ("Stalled with an exception at 0x%08"PFMT64x"\n", pc);
				}
			}
		}
	}
#if __WINDOWS__
	r_cons_break_pop ();
#endif
	return ret;

}

R_API int r_debug_continue(RDebug *dbg) {
	return r_debug_continue_kill (dbg, 0); //dbg->reason.signum);
}

#if __WINDOWS__ && !__CYGWIN__
R_API int r_debug_continue_pass_exception(RDebug *dbg) {
	return r_debug_continue_kill (dbg, DBG_EXCEPTION_NOT_HANDLED);
}
#endif

R_API int r_debug_continue_until_nontraced(RDebug *dbg) {
	eprintf ("TODO\n");
	return false;
}

R_API int r_debug_continue_until_optype(RDebug *dbg, int type, int over) {
	int ret, n = 0;
	ut64 pc, buf_pc = 0;
	RAnalOp op;
	ut8 buf[DBG_BUF_SIZE];

	if (r_debug_is_dead (dbg)) {
		return false;
	}

	if (!dbg->anal || !dbg->reg) {
		eprintf ("Undefined pointer at dbg->anal\n");
		return false;
	}

	r_debug_step (dbg, 1);
	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);

	// Initial refill
	buf_pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));

	// step first, we dont want to check current optype
	for (;;) {
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false))
			break;

		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof (buf)) {
			buf_pc = pc;
			dbg->iob.read_at (dbg->iob.io, buf_pc, buf, sizeof (buf));
		}
		// Analyze the opcode
		if (!r_anal_op (dbg->anal, &op, pc, buf + (pc - buf_pc), sizeof (buf) - (pc - buf_pc))) {
			eprintf ("Decode error at %"PFMT64x"\n", pc);
			return false;
		}
		if (op.type == type)
			break;
		// Step over and repeat
		ret = over
			? r_debug_step_over (dbg, 1)
			: r_debug_step (dbg, 1);

		if (!ret) {
			eprintf ("r_debug_step: failed\n");
			break;
		}
		n++;
	}

	return n;
}

static int r_debug_continue_until_internal(RDebug *dbg, ut64 addr, bool block) {
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	// Check if there was another breakpoint set at addr
	bool has_bp = r_bp_get_in (dbg->bp, addr, R_BP_PROT_EXEC) != NULL;
	if (!has_bp) {
		r_bp_add_sw (dbg->bp, addr, dbg->bpsize, R_BP_PROT_EXEC);
	}

	// Continue until the bp is reached
	dbg->reason.type = 0;
	for (;;) {
		if (r_debug_is_dead (dbg) || dbg->reason.type) {
			break;
		}
		ut64 pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		if (pc == addr) {
			break;
		}
		if (block && r_bp_get_at (dbg->bp, pc)) {
			break;
		}
		r_debug_continue (dbg);
	}
	// Clean up if needed
	if (!has_bp) {
		r_bp_del (dbg->bp, addr);
	}
	return true;
}

R_API int r_debug_continue_until(RDebug *dbg, ut64 addr) {
	return r_debug_continue_until_internal (dbg, addr, true);
}

R_API int r_debug_continue_until_nonblock(RDebug *dbg, ut64 addr) {
	return r_debug_continue_until_internal (dbg, addr, false);
}

R_API bool r_debug_continue_back(RDebug *dbg) {
	RDebugSession *before;
	RBreakpointItem *prev = NULL;
	int has_bp;
	ut64 pc, end_addr;
	if (!dbg) {
		return false;
	}
	if (!dbg->anal || !dbg->reg) {
		return false;
	}
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	if (r_list_empty (dbg->sessions)) {
		return false;
	}

	/* Get previous state */
	before = r_list_head (dbg->sessions)->data; //XXX: currently use first session.

	end_addr = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	//eprintf ("before session (%d) 0x%08"PFMT64x"=> to 0x%08"PFMT64x"\n", before->key.id, before->key.addr, end_addr);

	/* Rollback to previous state */
	r_debug_session_set (dbg, before);

	/* ### Get previous breakpoint ### */
	// Firstly set the breakpoint at end address
	has_bp = r_bp_get_in (dbg->bp, end_addr, R_BP_PROT_EXEC) != NULL;
	if (!has_bp) {
		r_bp_add_sw (dbg->bp, end_addr, dbg->bpsize, R_BP_PROT_EXEC);
	}

	// Continue until end_addr
	for (;;) {
		if (r_debug_is_dead (dbg)) {
			break;
		}
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		if (pc == end_addr) {
			break;
		}
		prev = r_bp_get_at (dbg->bp, pc);
		r_debug_continue (dbg);
	}
	// Clean up if needed
	if (!has_bp) {
		r_bp_del (dbg->bp, end_addr);
	}
	if (!prev) {
		return false;
	}
	//eprintf ("prev->addr = 0x%08"PFMT64x"\n", prev->addr);
	/* Now we got previous breakpoint.
	 * ### Continue until prev breakpoint ### */

	/* Rollback to previous state again */
	r_debug_session_set (dbg, before);
	for (;;) {
		if (r_debug_is_dead (dbg)) {
			break;
		}
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		if (prev == r_bp_get_at (dbg->bp, pc)) {
			break;
		}
		r_debug_continue (dbg);
	}
	return true;
}
static int show_syscall(RDebug *dbg, const char *sysreg) {
	const char *sysname;
	char regname[8];
	int reg, i, args;
	RSyscallItem *si;
	reg = (int)r_debug_reg_get (dbg, sysreg);
	si = r_syscall_get (dbg->anal->syscall, reg, -1);
	if (si) {
		sysname = si->name? si->name: "unknown";
		args = si->args;
	} else {
		sysname = "unknown";
		args = 3;
	}
	eprintf ("--> %s 0x%08"PFMT64x" syscall %d %s (", sysreg,
			r_debug_reg_get (dbg, "PC"), reg, sysname);
	for (i=0; i<args; i++) {
		ut64 val;
		snprintf (regname, sizeof (regname)-1, "A%d", i);
		val = r_debug_reg_get (dbg, regname);
		if (((st64)val<0) && ((st64)val>-0xffff)) {
			eprintf ("%"PFMT64d"%s", val, (i+1==args)?"":" ");
		} else {
			eprintf ("0x%"PFMT64x"%s", val, (i+1==args)?"":" ");
		}
	}
	eprintf (")\n");
	r_syscall_item_free (si);
	return reg;
}

R_API int r_debug_continue_syscalls(RDebug *dbg, int *sc, int n_sc) {
	int i, err, reg, ret = false;
	if (!dbg || !dbg->h || r_debug_is_dead (dbg)) {
		return false;
	}
	if (!dbg->h->contsc) {
		/* user-level syscall tracing */
		r_debug_continue_until_optype (dbg, R_ANAL_OP_TYPE_SWI, 0);
		return show_syscall (dbg, "A0");
	}

	if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
		eprintf ("--> cannot read registers\n");
		return -1;
	}
	reg = (int)r_debug_reg_get_err (dbg, "SN", &err, NULL);
	if (err) {
		eprintf ("Cannot find 'sn' register for current arch-os.\n");
		return -1;
	}
	for (;;) {
		RDebugReasonType reason;

		if (r_cons_singleton()->breaked)
			break;
#if __linux__
		// step is needed to avoid dupped contsc results
		/* XXX(jjd): actually one stop is before the syscall, the other is
		 * after.  this allows you to inspect the arguments before and the
		 * return value after... */
		r_debug_step (dbg, 1);
#endif
		dbg->h->contsc (dbg, dbg->pid, 0); // TODO handle return value
		// wait until continuation
		reason = r_debug_wait (dbg, NULL);
		if (reason == R_DEBUG_REASON_DEAD || r_debug_is_dead (dbg)) {
			break;
		}
#if 0
		if (reason != R_DEBUG_REASON_STEP) {
			eprintf ("astep\n");
			break;
		}
#endif
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			eprintf ("--> cannot sync regs, process is probably dead\n");
			return -1;
		}
		reg = show_syscall (dbg, "SN");
		if (n_sc == -1) {
			continue;
		}
		if (n_sc == 0) {
			break;
		}
		for (i = 0; i < n_sc; i++) {
			if (sc[i] == reg) {
				return reg;
			}
		}
		// TODO: must use r_core_cmd(as)..import code from rcore
	}
	return ret;
}

R_API int r_debug_continue_syscall(RDebug *dbg, int sc) {
	return r_debug_continue_syscalls (dbg, &sc, 1);
}

// TODO: remove from here? this is code injection!
R_API int r_debug_syscall(RDebug *dbg, int num) {
	bool ret = true;
	if (dbg->h->contsc) {
		ret = dbg->h->contsc (dbg, dbg->pid, num);
	}
	eprintf ("TODO: show syscall information\n");
	/* r2rc task? ala inject? */
	return (int)ret;
}

R_API int r_debug_kill(RDebug *dbg, int pid, int tid, int sig) {
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	if (dbg->h && dbg->h->kill) {
		return dbg->h->kill (dbg, pid, tid, sig);
	}
	eprintf ("Backend does not implement kill()\n");
	return false;
}

R_API RList *r_debug_frames(RDebug *dbg, ut64 at) {
	if (dbg && dbg->h && dbg->h->frames) {
		return dbg->h->frames (dbg, at);
	}
	return NULL;
}

/* TODO: Implement fork and clone */
R_API int r_debug_child_fork(RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API int r_debug_child_clone(RDebug *dbg) {
	//if (dbg && dbg->h && dbg->h->frames)
		//return dbg->h->frames (dbg);
	return 0;
}

R_API bool r_debug_is_dead (RDebug *dbg) {
	if (!dbg->h) {
		return false;
	}
	// workaround for debug.io.. should be generic
	if (!strcmp (dbg->h->name, "io")) {
		return false;
	}
	bool is_dead = (dbg->pid == -1 && strncmp (dbg->h->name, "gdb", 3)) || (dbg->reason.type == R_DEBUG_REASON_DEAD);
	if (dbg->pid > 0) {
		is_dead = !dbg->h->kill (dbg, dbg->pid, false, 0);
	}
#if 0
	if (!is_dead && dbg->h && dbg->h->kill) {
		is_dead = !dbg->h->kill (dbg, dbg->pid, false, 0);
	}
#endif
	if (is_dead) {
		dbg->reason.type = R_DEBUG_REASON_DEAD;
	}
	return is_dead;
}

R_API int r_debug_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	if (dbg && dbg->h && dbg->h->map_protect) {
		return dbg->h->map_protect (dbg, addr, size, perms);
	}
	return false;
}

R_API void r_debug_drx_list(RDebug *dbg) {
	if (dbg && dbg->h && dbg->h->drx) {
		dbg->h->drx (dbg, 0, 0, 0, 0, 0);
	}
}

R_API int r_debug_drx_set(RDebug *dbg, int idx, ut64 addr, int len, int rwx, int g) {
	if (dbg && dbg->h && dbg->h->drx) {
		return dbg->h->drx (dbg, idx, addr, len, rwx, g);
	}
	return false;
}

R_API int r_debug_drx_unset(RDebug *dbg, int idx) {
	if (dbg && dbg->h && dbg->h->drx) {
		return dbg->h->drx (dbg, idx, 0, -1, 0, 0);
	}
	return false;
}

R_API ut64 r_debug_get_baddr(RDebug *dbg, const char *file) {
	if (!dbg || !dbg->iob.io || !dbg->iob.io->desc) {
		return 0LL;
	}
	if (!strcmp (dbg->iob.io->desc->plugin->name, "gdb")) {		//this is very bad
		// Tell gdb that we want baddr, not full mem map
		dbg->iob.system(dbg->iob.io, "baddr");
	}
#if __WINDOWS__
	ut64 base;
	return r_io_desc_get_base (dbg->iob.io->desc, &base), base;
#else
	int pid = r_io_desc_get_pid (dbg->iob.io->desc);
	int tid = r_io_desc_get_tid (dbg->iob.io->desc);

	if (r_debug_attach (dbg, pid) == -1) {
		return 0LL;
	}
	r_debug_select (dbg, pid, tid);
	r_debug_map_sync (dbg);
	abspath = r_sys_pid_to_path (pid);
	if (!abspath) {
		abspath = r_file_abspath (file);
	}
	if (!abspath) {
		abspath = strdup (file);
	}
	if (abspath) {
		r_list_foreach (dbg->maps, iter, map) {
			if (!strcmp (abspath, map->name)) {
				free (abspath);
				return map->addr;
			}
		}
		free (abspath);
	}
	// fallback resolution (osx/w32?)
	// we asume maps to be loaded in order, so lower addresses come first
	r_list_foreach (dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}
	return 0LL;
#endif
}

R_API void r_debug_frame_print(RDebug *dbg, RDebugFrame *frame, int idx, bool sel) {

	char flagdesc[1024], flagdesc2[1024], pcstr[32], spstr[32];
	RCore *core = dbg->corebind.core;
	RFlagItem *f = r_flag_get_at (core->flags, frame->addr, true);
	flagdesc[0] = flagdesc2[0] = 0;

	if (f) {
		if (f->offset != UT64_MAX) {
			int delta = (int)(frame->addr - f->offset);
			if (delta > 0) {
				snprintf (flagdesc, sizeof (flagdesc),
						"%s+%d", f->name, delta);
			} else if (delta < 0) {
				snprintf (flagdesc, sizeof (flagdesc),
						"%s%d", f->name, delta);
			} else {
				snprintf (flagdesc, sizeof (flagdesc),
						"%s", f->name);
			}
		} else {
			snprintf (flagdesc, sizeof (flagdesc),
					"%s", f->name);
		}
		if (!strchr (f->name, '.') && (f = r_flag_get_at (core->flags, frame->addr - 1, true))) {
			if (f->offset != UT64_MAX) {
				int delta = (int)(frame->addr - 1 - f->offset);
				if (delta > 0) {
					snprintf (flagdesc2, sizeof (flagdesc2),
						"%s+%d", f->name, delta + 1);
				} else if (delta < 0) {
					snprintf (flagdesc2, sizeof (flagdesc2),
						"%s%d", f->name, delta + 1);
				} else {
					snprintf (flagdesc2, sizeof (flagdesc2),
						"%s+1", f->name);
				}
			} else {
				snprintf (flagdesc2, sizeof (flagdesc2),
					"%s", f->name);
			}
		}
	}
	if (core->dbg->bits & R_SYS_BITS_64) {
		snprintf (pcstr, sizeof (pcstr), "0x%-16" PFMT64x, frame->addr);
		snprintf (spstr, sizeof (spstr), "0x%-16" PFMT64x, frame->sp);
	} else if (core->dbg->bits & R_SYS_BITS_32) {
		snprintf (pcstr, sizeof (pcstr), "0x%-8" PFMT64x, frame->addr);
		snprintf (spstr, sizeof (spstr), "0x%-8" PFMT64x, frame->sp);
	} else {
		snprintf (pcstr, sizeof (pcstr), "0x%" PFMT64x, frame->addr);
		snprintf (spstr, sizeof (spstr), "0x%" PFMT64x, frame->sp);
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, frame->addr, 0);
	r_cons_printf (" %c %d  %s sp: %s  %-5d"
			"[%s]  %s %s\n", sel? '>' : ' ',
			idx,
			pcstr, spstr,
			(int)frame->size,
			fcn ? fcn->name : "??",
			flagdesc,
			flagdesc2);
}
