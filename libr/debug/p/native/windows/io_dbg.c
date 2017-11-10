/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_util.h>

#include "dbg.h"
#include "map.h"
#include "io_dbg.h"

typedef struct {
	int pid;
	int tid;
	ut64 base_addr;
	HANDLE h_proc;
} RIOW32Dbg;

static int debug_os_read_at(RIOW32Dbg *dbg, void *buf, int len, ut64 addr) {
	int ret_len = -1;

	/* If the read failed with ERROR_PARTIAL_COPY then we will to try read to end of map */
	if (!ReadProcessMemory (dbg->h_proc, (PVOID)(SIZE_T)addr, buf, len, (SIZE_T *)&ret_len)) {
		if (GetLastError() == ERROR_PARTIAL_COPY && ret_len <= 0) {
			RList *maps_list;
			RDebugMap *map;
			RListIter *iter;
			int map_len = len;

			ret_len = -1;
			/* TODO: RInterval */
			maps_list = w32_dbg_maps (dbg->pid);
			r_list_foreach (maps_list, iter, map) {
				if (addr >= map->addr && addr < map->addr_end) {
					map_len = map->addr_end - addr - 1;
					break;
				}
			}
			if (map_len != len && map_len > 0 &&
					ReadProcessMemory (dbg->h_proc, (PVOID)(SIZE_T)addr,
						buf, map_len, (SIZE_T *)&map_len)) {
				ret_len = map_len;
			}
			r_list_free (maps_list);
		}
	}
	return ret_len;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (fd->data, buf, len, io->off);
}

static int w32dbg_write_at(RIOW32Dbg *dbg, const ut8 *buf, int len, ut64 addr) {
	SIZE_T ret;
	return WriteProcessMemory (dbg->h_proc, (PVOID)(SIZE_T)addr, buf, len, &ret)? (int)ret: 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return w32dbg_write_at (fd->data, buf, len, io->off);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	if (!strncmp (file, "attach://", 9)) {
		return true;
	}
	return !strncmp (file, "w32dbg://", 9);
}

static inline int __open_proc (RIOW32Dbg *dbg_io) {
	dbg_io->tid = w32_dbg_attach (dbg_io->pid, &dbg_io->h_proc, &dbg_io->base_addr);
	return dbg_io->tid;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		char *pidpath;
		RIODesc *ret;
		RIOW32Dbg *dbg_io = R_NEW0 (RIOW32Dbg);
		if (!dbg_io) {
			return NULL;
		}
		dbg_io->pid = atoi (file + 9);
		if (__open_proc (dbg_io) == -1) {
			free (dbg_io);
			return NULL;
		}
		pidpath = r_sys_pid_to_path (dbg_io->pid);
		ret = r_io_desc_new (io, &r_io_plugin_w32dbg,
				file, rw | R_IO_EXEC, mode, dbg_io);
		ret->name = pidpath;
		return ret;
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case 0: // abs
		io->off = offset;
		break;
	case 1: // cur
		io->off += (int)offset;
		break;
	case 2: // end
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __close(RIODesc *fd) {
	// TODO: detach
	return true;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOW32Dbg *dbg_io = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strncmp (cmd, "pid", 3)) {
		if (cmd[3] == ' ') {
			int pid = atoi (cmd + 3);
			if (pid > 0 && pid != dbg_io->pid) {
				if (dbg_io->h_proc) {
					CloseHandle (dbg_io->h_proc);
				}
				dbg_io->h_proc = OpenProcess (PROCESS_ALL_ACCESS, false, pid);
				if (dbg_io->h_proc) {
					dbg_io->pid = dbg_io->tid = pid;
				} else {
					eprintf ("Cannot open process %d\n", pid);
				}
			}
			/* TODO: Implement child attach */
		}
		return r_str_newf ("%d", dbg_io->pid);
	} else {
		eprintf ("Try: '=!pid'\n");
	}
	return NULL;
}

static int __getpid (RIODesc *fd) {
	RIOW32Dbg *dbg_io = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (!dbg_io) {
		return -1;
	}
	return dbg_io->pid;
}

static int __gettid (RIODesc *fd) {
	RIOW32Dbg *dbg_io = (RIOW32Dbg *)(fd ? fd->data : NULL);
	return dbg_io? dbg_io->tid: -1;
}

static bool __getbase (RIODesc *fd, ut64 *base) {
	RIOW32Dbg *dbg_io = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (base && dbg_io) {
		*base = dbg_io->base_addr;
		return true;
	}
	return false;
}

RIOPlugin r_io_plugin_w32dbg = {
	.name = "w32dbg",
	.desc = "w32dbg io",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.gettid = __gettid,
	.getbase = __getbase,
	.isdbg = true
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg,
	.version = R2_VERSION
};
#endif

void w32_io_dbg_init (RDebug *dbg) {
#ifdef CORELIB
	r_io_plugin_add (dbg->iob.io, &r_io_plugin_w32dbg);
#endif
}
