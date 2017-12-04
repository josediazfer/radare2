#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include <r_core.h>
#include "dbg.h"
#include "map.h"
#include "io_dbg.h"

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif
#ifndef WINAPI
#define WINAPI
#endif

#ifndef EXCEPTION_HEAP_CORRUPTION
#define EXCEPTION_HEAP_CORRUPTION 0xc0000374
#endif

static int proc_dbg_continue(RDebugW32Proc *proc, bool handled);
static void load_lib_pdb(RDebug *dbg, RDebugW32Lib *lib);
static void load_lib_symbols(RDebug *dbg, RDebugW32Lib *lib);

DWORD (WINAPI *w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD) = NULL;

static DWORD (WINAPI *w32_GetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD) = NULL;
static BOOL (WINAPI *w32_DebugActiveProcessStop)(DWORD) = NULL;
static BOOL (WINAPI *w32_DebugBreakProcess)(HANDLE) = NULL;
static DWORD (WINAPI *w32_GetThreadId)(HANDLE) = NULL; // Vista
static DWORD (WINAPI *w32_GetProcessId)(HANDLE) = NULL; // XP
static BOOL (WINAPI *w32_QueryFullProcessImageName)(HANDLE, DWORD, LPTSTR, PDWORD) = NULL;
static NTSTATUS (WINAPI *w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
// fpu access API
static ut64 (WINAPI *w32_GetEnabledXStateFeatures)() = NULL;
static BOOL (WINAPI *w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
static BOOL (WINAPI *w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64) = NULL;
static PVOID(WINAPI *w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD) = NULL;
static BOOL (WINAPI *w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64) = NULL;

#ifndef XSTATE_GSSE
#define XSTATE_GSSE 2
#endif

#ifndef XSTATE_LEGACY_SSE
#define XSTATE_LEGACY_SSE 1
#endif

#if defined(XSTATE_MASK_GSSE) && defined (MINGW32)
#undef XSTATE_MASK_GSSE
#endif
#if !defined(XSTATE_MASK_GSSE)
#define XSTATE_MASK_GSSE (1LLU << (XSTATE_GSSE))
#endif

#undef CONTEXT_XSTATE
#if defined(_M_X64)
#define CONTEXT_XSTATE                      (0x00100040)
#else
#define CONTEXT_XSTATE                      (0x00010040)
#endif
#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)
#ifndef CONTEXT_ALL
#define CONTEXT_ALL 1048607
#endif

bool w32_enable_dbg_priv() {
	/////////////////////////////////////////////////////////
	//   Note: Enabling SeDebugPrivilege adapted from sample
	//     MSDN @ http://msdn.microsoft.com/en-us/library/aa446619%28VS.85%29.aspx
	// Enable SeDebugPrivilege
	bool success = false;
	TOKEN_PRIVILEGES tokenPriv;
	HANDLE h_tok = NULL;
	LUID luidDebug;

	if (!OpenProcessToken (GetCurrentProcess (),
			TOKEN_ADJUST_PRIVILEGES, &h_tok)) {
		r_sys_perror ("w32_enable_dbg_priv/OpenProcessToken");
		goto err_w32_enable_dbg_priv;
	}
	if (!LookupPrivilegeValue (NULL, SE_DEBUG_NAME, &luidDebug)) {
		r_sys_perror ("w32_enable_dbg_priv/LookupPrivilegeValue");
		goto err_w32_enable_dbg_priv;
		
	}
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luidDebug;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	success = AdjustTokenPrivileges (h_tok, FALSE, &tokenPriv, 0, NULL, NULL);
	if (!success) {
		r_sys_perror ("Failed to change token privileges");
	}
err_w32_enable_dbg_priv:
	if (h_tok) {
		CloseHandle (h_tok);
	}
	return success;
}

static RDebugW32Proc *proc_dbg_find(RDebugW32 *dbg_w32, int pid, RListIter **iter) {
	RList *proc_list = dbg_w32->proc_list;
	RListIter *iter_;
	RDebugW32Proc *proc;

	r_list_foreach (proc_list, iter_, proc) {
		if (proc->pid == pid) {
			if (iter) {
				*iter = iter_;
			}
			return proc;
		}
	}
	return NULL;
}

static RDebugW32Thread *th_dbg_find(RDebugW32Proc *proc, int tid, RListIter **iter) {
	RList *th_list = proc->th_list;
	RListIter *iter_;
	RDebugW32Thread *th;

	r_list_foreach (th_list, iter_, th) {
		if (th->tid == tid) {
			if (iter) {
				*iter = iter_;
			}
			return th;
		}
	}
	return NULL;
}

static RDebugW32Lib *lib_dbg_find(RDebugW32Proc *proc, ut64 base_addr, RListIter **iter) {
	RList *lib_list = proc->lib_list;
	RListIter *iter_;
	RDebugW32Lib *lib;

	r_list_foreach (lib_list, iter_, lib) {
		if (lib->base_addr == base_addr) {
			if (iter) {
				*iter = iter_;
			}
			return lib;
		}
	}
	return NULL;
}


static void proc_dbg_delete(RDebugW32 *dbg_w32, RDebugW32Proc *proc) {
	RListIter *iter;

	if (proc_dbg_find (dbg_w32, proc->pid, &iter)) {
		r_list_delete (dbg_w32->proc_list, iter);
	}
}

static void th_dbg_delete(RDebugW32Proc *proc, RDebugW32Thread *th) {
	RListIter *iter;

	if (th_dbg_find (proc, th->tid, &iter)) {
		r_list_delete (proc->th_list, iter);
	}
}

static void th_dbg_free(RDebugW32Thread *th) {
	if (th->h_th) {
		CloseHandle (th->h_th);
		th->h_th = NULL;
		free (th);
	}
}

static void lib_dbg_free(RDebugW32Lib *lib) {
	free (lib->path);
	free (lib->name);
	free (lib);
}

static void proc_dbg_free(RDebugW32Proc *proc) {
	if (!proc) {
		return;
	}
	r_list_free (proc->lib_list);
	proc->lib_list = NULL;
	r_list_free (proc->th_list);
	proc->th_list = NULL;
	if (proc->h_proc) {
		CloseHandle (proc->h_proc);
		proc->h_proc = NULL;
	}
	free (proc);
}

static RDebugW32Proc *proc_dbg_cur(RDebug *dbg) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;

	return proc_dbg_find (dbg_w32, dbg->pid, NULL);
}

static RDebugW32Thread *th_dbg_cur(RDebug *dbg) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RDebugW32Proc *proc = proc_dbg_find (dbg_w32, dbg->pid, NULL);
	RDebugW32Thread *th = NULL;

	if (proc) {
		th = th_dbg_find (proc, dbg->tid, NULL);
	}
	return th;
}

void w32_dbg_free(RDebug *dbg) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	r_list_free (dbg_w32->proc_list);
	R_FREE (dbg->native_ptr);
}

int w32_dbg_init(RDebug *dbg) {
	HMODULE h_mod;
	RDebugW32 *dbg_w32;

	if (dbg->native_ptr) {
		return true;
	}
	/* escalate privs (required for win7/vista) */
	w32_enable_dbg_priv ();
	/****** KERNEL32 functions *****/
	h_mod = GetModuleHandle (TEXT ("kernel32"));
	/* lookup function pointers for portability */
	w32_DebugActiveProcessStop = (BOOL (WINAPI *)(DWORD))
		GetProcAddress (h_mod,"DebugActiveProcessStop");
	w32_DebugBreakProcess = (BOOL (WINAPI *)(HANDLE))
		GetProcAddress (h_mod, "DebugBreakProcess");
	// only windows vista :(
	w32_GetThreadId = (DWORD (WINAPI *)(HANDLE))
		GetProcAddress (h_mod, "GetThreadId");
	// from xp1
	w32_GetProcessId = (DWORD (WINAPI *)(HANDLE))
		GetProcAddress (h_mod, "GetProcessId");
	w32_QueryFullProcessImageName = (BOOL (WINAPI *)(HANDLE, DWORD, LPTSTR, PDWORD))
		GetProcAddress (h_mod, W32_TCALL ("QueryFullProcessImageName"));
	// api to retrieve YMM from w7 sp1
	w32_GetEnabledXStateFeatures = (ut64 (WINAPI *) ())
		GetProcAddress (h_mod, "GetEnabledXStateFeatures");
	w32_InitializeContext = (BOOL (WINAPI *) (PVOID, DWORD, PCONTEXT*, PDWORD))
		GetProcAddress (h_mod, "InitializeContext");
	w32_GetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, PDWORD64))
		GetProcAddress (h_mod, "GetXStateFeaturesMask");
	w32_LocateXStateFeature = (PVOID (WINAPI *) (PCONTEXT Context, DWORD ,PDWORD))
		GetProcAddress (h_mod, "LocateXStateFeature");
	w32_SetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, DWORD64))
		GetProcAddress (h_mod, "SetXStateFeaturesMask");
	/****** PSAPI functions *****/
	h_mod = LoadLibrary (TEXT("psapi.dll"));
	if (!h_mod) {
		eprintf ("Cannot load psapi.dll. Aborting\n");
		return false;
	}
	w32_GetMappedFileName = (DWORD (WINAPI *)(HANDLE, LPVOID, LPTSTR, DWORD))
		GetProcAddress (h_mod, W32_TCALL ("GetMappedFileName"));
	w32_GetModuleFileNameEx = (DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (h_mod, W32_TCALL ("GetModuleFileNameEx"));
	/****** NTDLL functions *****/
	h_mod = GetModuleHandle (TEXT ("ntdll"));
	w32_NtQuerySystemInformation = (NTSTATUS  (WINAPI *)(ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (h_mod, "NtQuerySystemInformation");
	w32_NtDuplicateObject = (NTSTATUS  (WINAPI *)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG))
		GetProcAddress (h_mod, "NtDuplicateObject");
	w32_NtQueryObject = (NTSTATUS  (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (h_mod, "NtQueryObject");
	w32_NtQueryInformationThread = (NTSTATUS  (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (h_mod, "NtQueryInformationThread");
	if (!w32_DebugActiveProcessStop || !w32_DebugBreakProcess || !w32_GetThreadId) {
		// OOPS!
		eprintf ("debug_init_calls:\n"
			"DebugActiveProcessStop: 0x%p\n"
			"DebugBreakProcess: 0x%p\n"
			"GetThreadId: 0x%p\n",
			w32_DebugActiveProcessStop, w32_DebugBreakProcess, w32_GetThreadId);
		return false;
	}

	dbg_w32 = R_NEW0 (RDebugW32);
	dbg_w32->proc_list = r_list_newf ((RListFree)proc_dbg_free);
	dbg->native_ptr = dbg_w32;
	return true;
}

static char *get_w32_excep_name(unsigned long code) {
	char *desc;
	switch (code) {
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
		desc = "access violation";
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		desc = "array bounds exceeded";
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		desc = "illegal instruction";
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		desc = "divide by zero";
		break;
	case EXCEPTION_STACK_OVERFLOW:
		desc = "stack overflow";
		break;
	case EXCEPTION_HEAP_CORRUPTION:
		desc = "heap corruption";
		break;
	default:
		desc = "unknown";
	}

	return desc;
}

static int dbg_exception_event(DEBUG_EVENT *de) {
	unsigned long code = de->u.Exception.ExceptionRecord.ExceptionCode;
	switch (code) {
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
	case EXCEPTION_HEAP_CORRUPTION:
		eprintf ("(%d) Fatal exception (%s) in thread %d\n",
			(int)de->dwProcessId, 
			get_w32_excep_name (code),
			(int)de->dwThreadId);
		break;
	/* MS_VC_EXCEPTION */
	case 0x406D1388:
		eprintf ("(%d) MS_VC_EXCEPTION (%x) in thread %d\n",
			(int)de->dwProcessId, (int)code, (int)de->dwThreadId);
		return 1;
	default:
		eprintf ("(%d) Unknown exception %x in thread %d\n",
			(int)de->dwProcessId, (int)code, (int)de->dwThreadId);
		break;
	}
	return 0;
}

static char *get_file_name_from_handle(HANDLE handle_file) {
	HANDLE handle_file_map = NULL;
	LPTSTR filename = NULL, name = NULL;
	DWORD file_size_high = 0;
	LPVOID map = NULL;
	char *ret_filename = NULL;
	DWORD file_size_low = GetFileSize (handle_file, &file_size_high);

	if (file_size_low == 0 && file_size_high == 0) {
		return NULL;
	}
	handle_file_map = CreateFileMapping (handle_file, NULL, PAGE_READONLY, 0, 1, NULL);
	if (!handle_file_map) {
		goto err_get_file_name_from_handle;
	}
	filename = (LPTSTR)malloc ((MAX_PATH + 1) * sizeof (TCHAR));
	if (!filename) {
		goto err_get_file_name_from_handle;
	}
	/* Create a file mapping to get the file name. */
	map = MapViewOfFile (handle_file_map, FILE_MAP_READ, 0, 0, 1);
	if (!map || !w32_GetMappedFileName (GetCurrentProcess (), map, filename, MAX_PATH)) {
		goto err_get_file_name_from_handle;
	}
	TCHAR temp_buffer[512];
	/* Translate path with device name to drive letters. */
	if (!GetLogicalDriveStrings (sizeof (temp_buffer) - 1, temp_buffer)) {
		goto err_get_file_name_from_handle;
	}
	name = (LPTSTR)malloc ((MAX_PATH + 1) * sizeof (TCHAR));
	if (!name) {
		goto err_get_file_name_from_handle;
	}
	TCHAR drive[3] =  TEXT (" :");
	LPTSTR cur_drive = temp_buffer;
	while (*cur_drive) {
		/* Look up each device name */
		*drive = *cur_drive;
		if (QueryDosDevice (drive, name, MAX_PATH)) {
			size_t name_length = _tcslen (name);

			if (name_length < MAX_PATH) {
				if (_tcsnicmp (filename, name, name_length) == 0
					&& *(filename + name_length) == TEXT ('\\')) {
					TCHAR temp_filename[MAX_PATH];
					_sntprintf (temp_filename, MAX_PATH, TEXT ("%s%s"),
						drive, filename + name_length);
					_tcsncpy (filename, temp_filename,
						_tcslen (temp_filename) + 1);
					break;
				}
			}
		}
		cur_drive++;
	} 
err_get_file_name_from_handle:
	free (name);
	if (map) {
		UnmapViewOfFile (map);
	}
	if (handle_file_map) {
		CloseHandle (handle_file_map);
	}
	if (filename) {
		ret_filename = r_sys_conv_utf16_to_utf8(filename);
		free (filename);
	}	
	return ret_filename;
}

static RDebugW32Proc *proc_dbg_new(RDebugW32 *dbg_w32, int pid, int state) {
	RDebugW32Proc *proc;
	bool success = false;

	proc = R_NEW0 (RDebugW32Proc);
	if (!proc) {
		return NULL;
	}
	proc->lib_list = r_list_newf ((RListFree)lib_dbg_free);
	if (!proc->lib_list) {
		goto err_proc_dbg_new;
	}
	proc->th_list = r_list_newf ((RListFree)th_dbg_free);
	if (!proc->th_list) {
		goto err_proc_dbg_new;
	}
	proc->pid = pid;
	proc->state = state;
	r_list_append (dbg_w32->proc_list, proc);
	success = true;
err_proc_dbg_new:
	if (!success) {
		free (proc->lib_list);
		free (proc->th_list);
		R_FREE (proc);
	}
	return proc;
}

static RDebugW32Thread *th_dbg_new(RDebugW32Proc *proc, int tid, int state) {
	RDebugW32Thread *th;

	th = th_dbg_find (proc, tid, NULL);
	if (!th) {
		th = R_NEW0 (RDebugW32Thread);
		if (!th) {
			return NULL;
		}
		th->tid = tid;
		r_list_append (proc->th_list, th);
	}
	th->state = state;
	return th;
}

static RDebugW32Lib *lib_dbg_new(RDebugW32Proc *proc, ut64 base_addr, int state) {
	RDebugW32Lib *lib;

	lib = lib_dbg_find (proc, base_addr, NULL);
	if (!lib) {
		lib = R_NEW0 (RDebugW32Lib);
		if (!lib) {
			return NULL;
		}
		lib->base_addr = base_addr;
		r_list_append (proc->lib_list, lib);
	}
	lib->state = state;
	return lib;
}

static char *get_lib_from_mod(RDebugW32Proc *proc, ut64 lib_addr) {
	RListIter *iter;
	RDebugMap *map;
	RList *mods_list = w32_dbg_modules (proc->pid);
	char *path = NULL;

	r_list_foreach (mods_list, iter, map) {
		if (map->file && lib_addr >= map->addr && lib_addr < map->addr_end) {
			path = strdup (map->file);
			break;
		}
	}
	r_list_free (mods_list);
	return path;
}

static void proc_lib_init(RDebug *dbg, RDebugW32Proc *proc, RDebugW32Lib *lib, HANDLE h_file) {
	char *path;

	if (h_file) {
		path = get_file_name_from_handle (h_file);
	} else {
		path = get_lib_from_mod (proc, lib->base_addr); 
	}
	if (path && (!lib->path || strcmp (lib->path, path))) {
		char *p = strchr (path, '\\');

		free (lib->path);
		free (lib->name);
		lib->path = path;
		if (p) {
			lib->name = strdup (p + 1);
		} else {
			lib->name = strdup (path);
		}
		load_lib_pdb (dbg, lib);
		load_lib_symbols (dbg, lib);
	} else {
		free (path);
	}
}

static void proc_lib_names_resolv(RDebug *dbg, RDebugW32Proc *proc) {
	RList *lib_list = proc->lib_list;
	RListIter *iter;
	RDebugW32Lib *lib;

	r_list_foreach (lib_list, iter, lib) {
		proc_lib_init (dbg, proc, lib, NULL);
	}
}

static void load_lib_pdb(RDebug *dbg, RDebugW32Lib *lib) {
	/* Check if autoload PDB is set, and load PDB information if yes */
	RCore* core = dbg->corebind.core;
	bool autoload_pdb = dbg->corebind.cfggeti (core, "pdb.autoload");
	if (autoload_pdb) {
		char* o_res = dbg->corebind.cmdstrf (core, "o %s", lib->path);
		// File exists since we loaded it, however the "o" command fails sometimes hence the while loop
		while (*o_res == 0) {
			o_res = dbg->corebind.cmdstrf (core, "o %s", lib->path);
		}
		int fd = atoi (o_res);
		dbg->corebind.cmdf (core, "o %d", fd);
		char* pdb_path = dbg->corebind.cmdstr (core, "i~pdb");
		if (*pdb_path == 0) {
			eprintf ("Failure...\n");
			dbg->corebind.cmd (core, "i");
		} else {
			pdb_path = strchr (pdb_path, ' ') + 1;
			dbg->corebind.cmdf (core, ".idp* %s", pdb_path);
		}
		dbg->corebind.cmdf (core, "o-%d", fd);
	}
}

static void load_lib_symbols(RDebug *dbg, RDebugW32Lib *lib) {
	RCore* core = dbg->corebind.core;
	char *path = r_str_escape (lib->path);
	char *name = r_str_escape (lib->name);

	dbg->corebind.cmdf (core, "f mod.%s = 0x%08"PFMT64x"\n", name, lib->base_addr);
	/* too slowly, call native functions? */
	dbg->corebind.cmdf (core, ".!rabin2 -rsB 0x%08"PFMT64x" \"%s\"\n", lib->base_addr, path);
	free (path);
	free (name);
}

static RDebugW32Lib *set_lib_info(RDebug *dbg, RDebugW32Proc *proc, DEBUG_EVENT *de, int state) {
	RDebugW32Lib *lib = NULL;

	if (state == LIB_STATE_LOADED) {
		ut64 base_addr = (ut64)(size_t)de->u.LoadDll.lpBaseOfDll;

		lib =  lib_dbg_new (proc, base_addr, LIB_STATE_LOADED);
		if (!lib) {
			perror ("set_lib_info/lib_dbg_new alloc");
			goto err_set_lib_info;
		}
		proc_lib_init (dbg, proc, lib, de->u.LoadDll.hFile);
	} else {
		ut64 base_addr = (ut64)(size_t)de->u.UnloadDll.lpBaseOfDll;

		lib = lib_dbg_find (proc, base_addr, NULL);
		if (!lib) {
			eprintf ("(%d) unregistered unloaded library at %08"PFMT64x"\n", proc->pid, base_addr);
		} else {
			lib->state = state;
		}
	}
err_set_lib_info:
	return lib;
}

static RDebugW32Thread *set_th_info(RDebugW32Proc *proc, DEBUG_EVENT *de, int state) {
	RDebugW32Thread *th = NULL;
	PVOID th_entry_addr;

	if (state == THREAD_STATE_CREATED) {
		HANDLE h_th;

		th = th_dbg_new (proc, proc->tid, state);
		if (!th) {
			perror ("set_th_info/th alloc");
			goto err_set_th_info;
		}
		h_th = de->u.CreateThread.hThread;
		if (!h_th) {
			h_th = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, th->tid); 
		}
		if (w32_NtQueryInformationThread (h_th, 0x9 /*ThreadQuerySetWin32StartAddress*/, &th_entry_addr,
					sizeof (PVOID), NULL) == 0) { 
			th->entry_addr = (ut64)(size_t)th_entry_addr;
		} else {
			th->entry_addr = (ut64)(size_t)de->u.CreateThread.lpStartAddress;
		}
		th->h_th = h_th;
	} else {
		th = th_dbg_find (proc, proc->tid, NULL);
		if (!th) {
			eprintf ("(%d) unregistered tid %d\n", proc->pid, th->tid);
			goto err_set_th_info;
		}
		th->exit_code = (int)de->u.ExitThread.dwExitCode;
	}	
	th->state = state;
err_set_th_info:
	return th;
}

static void print_dbg_output(RDebugW32Proc *proc, DEBUG_EVENT *de) {
	LPVOID addr = de->u.DebugString.lpDebugStringData;
	WORD len = de->u.DebugString.nDebugStringLength;
	LPVOID msg = NULL;
	bool unicode;
	SIZE_T ret_len;

	if (!addr || len <= 0) {
		return;
	}
	unicode = de->u.DebugString.fUnicode != 0;
	if (unicode) {
		msg = (LPVOID)malloc (sizeof (WCHAR) * len);
	} else {
		msg = (LPVOID)malloc (sizeof (char) * len);
	}
	if (!msg) {
		perror ("print_dbg_output/malloc");
		goto err_print_dbg_output;
	}
	if (!ReadProcessMemory (proc->h_proc, addr, msg, len, &ret_len)) {
		r_sys_perror ("print_dbg_output/ReadProcessMemory");
		goto err_print_dbg_output;
	}
	if (unicode) {
		eprintf ("(%d) debug output \"%S\"\n", proc->pid, (wchar_t *)msg);
	} else {
		eprintf ("(%d) debug output \"%s\"\n", proc->pid, (char *)msg);
	}
err_print_dbg_output:
	free (msg);
}

static bool tracelib(RDebug *dbg, RDebugW32Proc *proc, RDebugW32Lib *lib, char *mode) {
	const char *needle = NULL;
	int tmp = 0;
	if (mode) {
		switch (mode[0]) {
		case 'l': needle = dbg->glob_libs; break;
		case 'u': needle = dbg->glob_unlibs; break;
		}
	}
	eprintf ("(%d) %sing library at %08"PFMT64x, proc->pid, mode, lib->base_addr);
	if (lib->path) {
		printf (" (%s)", lib->path);
	}
	if (lib->name) {
		printf (" %s", lib->name);
	}
	printf ("\n");
	if (needle && strlen (needle)) {
		tmp = r_str_glob (lib->name, needle);
	}
	return !mode || !needle || tmp ;
}

int w32_dbg_wait(RDebug *dbg, RDebugW32Proc **ret_proc) {
	DEBUG_EVENT de;
	int tid, pid, next_event = 0;
	unsigned int code;
	int ret = R_DEBUG_REASON_UNKNOWN;
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;

	/* handle debug events */
	do {
		RDebugW32Proc *proc;

		memset (&de, 0, sizeof (DEBUG_EVENT));
		if (WaitForDebugEvent (&de, INFINITE) == 0) {
			r_sys_perror ("w32_dbg_wait/WaitForDebugEvent");
			return -1;
		}
		code = de.dwDebugEventCode;
		tid = (int)de.dwThreadId;
		pid = (int)de.dwProcessId;
		proc = proc_dbg_find (dbg_w32, pid, NULL);
		if (!proc) {
			eprintf ("unregistered pid %d\n", pid);
			return -1;
		}
		proc->tid = tid;
		proc->cont = true;
		if (ret_proc) {
			*ret_proc = proc;
		}
		dbg->pid = pid;
		dbg->tid = tid;
		switch (code) {
		case CREATE_PROCESS_DEBUG_EVENT:
			if (proc->state == PROC_STATE_ATTACHED) {
				proc->state = PROC_STATE_STARTING;
			} else {
				eprintf ("(%d) created process (%p)\n", pid, de.u.CreateProcessInfo.lpStartAddress);
			}
			proc->base_addr = (ut64)de.u.CreateProcessInfo.lpBaseOfImage;
			if (!proc->h_proc) {
				proc->h_proc = de.u.CreateProcessInfo.hProcess;
			}
			if (de.u.CreateProcessInfo.hThread) {
				RDebugW32Thread *th = th_dbg_new (proc, tid, THREAD_STATE_CREATED);
				if (th) {
					th->h_th = de.u.CreateProcessInfo.hThread;
				}
			}
			if (de.u.CreateProcessInfo.hFile) {
				CloseHandle (de.u.CreateProcessInfo.hFile);
			}
			proc_dbg_continue (proc, true);
			next_event = 1;
			ret = R_DEBUG_REASON_NEW_PID;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) process %d exited with exit code %d\n", pid, pid,
				(int)de.u.ExitProcess.dwExitCode);
			next_event = 0;
			proc_dbg_continue (proc, true);
			proc_dbg_delete (dbg_w32, proc);
			ret = R_DEBUG_REASON_EXIT_PID;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			{
			RDebugW32Thread *th = set_th_info (proc, &de, THREAD_STATE_CREATED);
			if (th) {
				eprintf ("(%d) created thread %d (start @ %08"PFMT64x")\n", pid, th->tid, th->entry_addr);
			}
			if (proc->state == PROC_STATE_STARTING) {
				proc_dbg_continue (proc, true);
				next_event = 1;
			} else {
				next_event = 0;
			}
			ret = R_DEBUG_REASON_NEW_TID;
			}
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			{
			RDebugW32Thread *th = set_th_info (proc, &de, THREAD_STATE_FINISHED);
			if (th) {
				eprintf ("(%d) finished thread %d exit code %d\n", pid, th->tid, th->exit_code);
			}
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_TID;
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:
			{
			RDebugW32Lib *lib = set_lib_info (dbg, proc, &de, LIB_STATE_LOADED);
			if (de.u.LoadDll.hFile) {
				CloseHandle (de.u.LoadDll.hFile);
			}
			if (proc->state == PROC_STATE_STARTING) {
				proc_dbg_continue (proc, true);
				next_event = 1;
			} else if (lib) {
				if (tracelib (dbg, proc, lib, "load")) {
					ret = R_DEBUG_REASON_TRAP;
				}
				next_event = 0;
			}
			}
			ret = R_DEBUG_REASON_NEW_LIB;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			{
			RDebugW32Lib *lib = set_lib_info (dbg, proc, &de, LIB_STATE_UNLOADED);
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_LIB;
			if (lib) {
				if (tracelib (dbg, proc, lib, "unload")) {
					ret = R_DEBUG_REASON_TRAP;
				}
			}
			}
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			print_dbg_output (proc, &de);
			proc_dbg_continue (proc, true);
			next_event = 1;
			break;
		case RIP_EVENT:
			eprintf ("(%d) RIP event\n", pid);
			proc_dbg_continue (proc, true);
			next_event = 1;
			// XXX unknown ret = R_DEBUG_REASON_TRAP;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
#if __MINGW64__ || _WIN64
			case 0x4000001f: /* STATUS_WX86_BREAKPOINT */
#endif
			case EXCEPTION_BREAKPOINT:
				if (proc->state == PROC_STATE_STARTING) {
					proc_lib_names_resolv (dbg, proc);
					proc->state = PROC_STATE_STARTED;
				}
				ret = R_DEBUG_REASON_BREAKPOINT;
				next_event = 0;
				break;
#if __MINGW64__ || _WIN64
			case 0x4000001e: /* STATUS_WX86_SINGLE_STEP */
#endif
			case EXCEPTION_SINGLE_STEP:
				ret = R_DEBUG_REASON_STEP;
				next_event = 0;
				break;
			case DBG_CONTROL_C:
				eprintf ("(%d) control+c event\n", proc->pid); 
				next_event = 1;
				proc_dbg_continue (proc, false);
				break;
			default:
				if (!dbg_exception_event (&de)) {
					ret = R_DEBUG_REASON_TRAP;
					next_event = 0;
				}
				else {
					next_event = 1;
					proc_dbg_continue (proc, true);
				}

			}
			break;
		default:
			eprintf ("(%d) unknown event: %d\n", pid, code);
			return -1;
		}
	} while (next_event);
	return ret;
}

inline int is_pe_hdr(unsigned char *pe_hdr) {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)pe_hdr;
	IMAGE_NT_HEADERS *nt_headers;

	if (dos_header->e_magic==IMAGE_DOS_SIGNATURE) {
		nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
				+ dos_header->e_lfanew);
		if (nt_headers->Signature==IMAGE_NT_SIGNATURE)
			return 1;
	}
	return 0;
}

RList *w32_thread_list(int pid) {
        HANDLE h_proc_snap = INVALID_HANDLE_VALUE;
        THREADENTRY32 te32;
	RList *list = NULL;
	bool success = false;

        h_proc_snap = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, pid);
        if (h_proc_snap == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_thread_list/CreateToolhelp32Snapshot");
                goto err_w32_thread_list;
	}
        te32.dwSize = sizeof (THREADENTRY32);
	if (!Thread32First (h_proc_snap, &te32)) {
		r_sys_perror ("w32_thread_list/Thread32First");
                goto err_w32_thread_list;
	}
	list = r_list_newf ((RListFree)r_debug_pid_free);
        do {
                /* get all threads of process */
                if (te32.th32OwnerProcessID == pid) {
			HANDLE h_th;

                        /* open a new handler */
			h_th = OpenThread (THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (!h_th) {
				r_sys_perror ("w32_thread_list/OpenThread");
                                goto err_w32_thread_list;
			}
			CloseHandle (h_th);
			r_list_append (list, r_debug_pid_new ("???", te32.th32ThreadID, 0, 's', 0));
                }
        } while (Thread32Next (h_proc_snap, &te32));
	success = true;
err_w32_thread_list:
	if (!success) {
		r_list_free (list);
		list = NULL;
	}
        if (h_proc_snap != INVALID_HANDLE_VALUE) {
                CloseHandle (h_proc_snap);
	}
	return list;
}

static RDebugPid *build_debug_pid(PROCESSENTRY32 *pe) {
	TCHAR image_name[MAX_PATH + 1];
	DWORD length = MAX_PATH;
	RDebugPid *ret;
	char *name;
	HANDLE process = OpenProcess (0x1000, //PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE, pe->th32ProcessID);

	*image_name = '\0';
	if (process) {
		if (w32_QueryFullProcessImageName) {
			w32_QueryFullProcessImageName (process, 0, image_name, &length);
		}
		CloseHandle (process);
	}
	if (*image_name) {
		name = r_sys_conv_utf16_to_utf8 (image_name);
	} else {
		name = r_sys_conv_utf16_to_utf8 (pe->szExeFile);
	}
	ret = r_debug_pid_new (name, pe->th32ProcessID, 0, 's', 0);
	free (name);
	return ret;
}

RList *w32_pids (int pid, RList *list) {
	HANDLE h_proc_snap;
	PROCESSENTRY32 pe;
	DWORD my_pid;
	int show_all_pids = (pid == 0);

	h_proc_snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, pid);
	if (h_proc_snap == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_pids/CreateToolhelp32Snapshot");
		goto err_w32_pids;
	}
	pe.dwSize = sizeof (PROCESSENTRY32);
	if (!Process32First (h_proc_snap, &pe)) {
		r_sys_perror ("w32_pids/Process32First");
		goto err_w32_pids;
	}
	my_pid = GetCurrentProcessId ();
	do {
		if (my_pid != pe.th32ProcessID && (show_all_pids ||
			pe.th32ProcessID == pid ||
			pe.th32ParentProcessID == pid)) {

			RDebugPid *debug_pid = build_debug_pid (&pe);
			if (debug_pid) {
				r_list_append (list, debug_pid);
			}
		}
	} while (Process32Next (h_proc_snap, &pe));
err_w32_pids:
	if (h_proc_snap != INVALID_HANDLE_VALUE) {
		CloseHandle (h_proc_snap);
	}
	return list;
}

static int proc_dbg_continue(RDebugW32Proc *proc, bool handled) {
	if (proc->cont) {
		RDebugW32Thread *th;

		if (ContinueDebugEvent (proc->pid, proc->tid, handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED) == 0) {
			eprintf ("failed debug_contp pid %d tid %d\n", proc->pid, proc->tid);
			r_sys_perror ("proc_dbg_continue/ContinueDebugEvent");
			return -1;
		}
		/* on continue a thread finished, hThread is a invalid handler */
		th = th_dbg_find (proc, proc->tid, NULL);
		if (th && th->state == THREAD_STATE_FINISHED) {
			th_dbg_delete (proc, th);
		}
		proc->cont  = false;
	}
	return 0;
}

int w32_dbg_continue(RDebug *dbg, int pid) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RList *proc_list = dbg_w32->proc_list;
	RListIter *iter;
	RDebugW32Proc *proc;
	int ret_cont = -1;

	r_list_foreach (proc_list, iter, proc) {
		if (proc->state == PROC_STATE_STARTED) {
			int ret = proc_dbg_continue (proc, true);

			proc->state = PROC_STATE_READY;
			if (proc->pid == pid) {
				ret_cont = ret;
			}
		} else if (proc->pid == pid) {
			ret_cont = proc_dbg_continue (proc, true);
		}
	}
	return ret_cont;
}

int w32_dbg_detach(RDebug *dbg, int pid) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RDebugW32Proc *proc = proc_dbg_find (dbg_w32, pid, NULL);
	int ret;

	if (!proc) {
		return -1;
	}
	proc_dbg_continue (proc, true);
	ret = w32_DebugActiveProcessStop (pid)? 0 : -1;
	proc_dbg_delete (dbg_w32, proc);
	dbg->pid = -1;
	dbg->tid = -1;
	return ret;
}

static void proc_dbg_enable_excep (RDebug *dbg, int pid, boolean enable) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RList *proc_list = dbg_w32->proc_list;
	RListIter *iter;
	RDebugW32Proc *proc;

	r_list_foreach (proc_list, iter, proc) {
		if (proc->pid == pid) {
			continue;
		}
		if (enable) {
			if (DebugActiveProcess (proc->pid)) {
				proc->state = PROC_STATE_ATTACHED;
			}
		} else if (w32_DebugActiveProcessStop (proc->pid)) {
			proc->state = PROC_STATE_DETACHED;
			r_list_free (proc->th_list);
			proc->th_list = r_list_newf ((RListFree) th_dbg_free);
		}
	}
	if (enable) {
		bool proc_attach;
		do {
			proc_attach = false;
			r_list_foreach (proc_list, iter, proc) {
				if (proc->pid != pid && proc->state == PROC_STATE_ATTACHED) {
					w32_dbg_wait (dbg, NULL);
					proc_attach = true;
					break;
				}
			}	
		} while (proc_attach);
	}
}

static int proc_dbg_wait(RDebug *dbg, int pid, RDebugW32Proc **ret_proc) {
	int reason;

	proc_dbg_enable_excep (dbg, pid, false);
	reason = w32_dbg_wait (dbg, ret_proc);
	proc_dbg_enable_excep (dbg, pid, true);
	return reason;
}

int w32_dbg_attach(RDebug *dbg, int pid, RDebugW32Proc **ret_proc) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RDebugW32Proc *proc = NULL;
	int ret = -1;

	proc = proc_dbg_find (dbg_w32, pid, NULL);
	if (proc) {
		if (ret_proc) {
			*ret_proc = proc;
		}
		return proc->tid;
	}
	if (!DebugActiveProcess (pid)) {
		r_sys_perror ("w32_dbg_attach/DebugActiveProcess");
		goto err_w32_dbg_attach;
	}
	proc = proc_dbg_new (dbg_w32, pid, PROC_STATE_ATTACHED);
	if (!proc) {
		perror ("w32_dbg_attach/proc_dbg_new");
		goto err_w32_dbg_attach;
	}
	if (proc_dbg_wait (dbg, proc->pid, ret_proc) != R_DEBUG_REASON_BREAKPOINT) {
		eprintf ("w32_dbg_attach/w32_dbg_wait != R_DEBUG_REASON_BREAKPOINT\n");
		goto err_w32_dbg_attach;
	}
	ret = proc->tid;
err_w32_dbg_attach:
	if (ret == -1 && proc) {
		proc_dbg_delete (dbg_w32, proc);
	}
	return ret; 
}

int w32_dbg_new_proc(RDebug *dbg, const char *cmd, char *args, RDebugW32Proc **ret_proc) {
	PROCESS_INFORMATION pi;
	STARTUPINFO si = {0};
	int pid = -1;
	LPTSTR appname_ = NULL, cmdline_ = NULL;
	char *cmdline = NULL;
	int i, len;
	char *appname = NULL;
	RDebugW32Proc *proc = NULL;
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;

	if (!*cmd) {
		return -1;
	}
	len = strlen (cmd);
	for (i = 0; i < len; i++) {
		if (cmd[i] == '.') {
			if (!strncasecmp (cmd + i + 1, "exe ", 4) || !strncasecmp (cmd + i + 1, "dll ", 4)) {
				appname = (char *)malloc (i + 5);
				if (appname) {
					memcpy (appname, cmd, i + 4);
					appname[i + 4] = '\0';
				}
				break;
			}
		}
	}
	if (!appname) {
		appname = strdup (cmd);
		cmd = NULL;
	} else if (len > 5) {
		cmd = cmd + i + 5;
	} else {
		cmd = NULL;
	}
	
	/* is relative path? If so find executable from PATH environment variable */
	if (_access (appname, 0) == -1 && (strlen(appname) <= 2 || *(appname + 1) != ':'
		|| (tolower (*appname) < 'a' || tolower (*appname) > 'z'))) {
		char *path = r_sys_getenv ("PATH");
		if (path) {
			char *rpath = path;

			len = strlen (path);
			for (i = 0; i < len; i++) {
				if (path[i] == ';') {
					char *fpath;

					path[i] = '\0';
					fpath = r_str_newf ("%s\\%s", rpath, appname);
					if (_access (fpath, 0) == 0) {
						free (appname);
						appname = fpath;
						break;
					}
					rpath = &path[i + 1];
					free (fpath);
				}	
			}
			free (path);
		}
	}

	if (args) {
		if (cmd) {
			cmdline = r_str_newf ("\"%s\" %s %s", appname, cmd, args);
		} else {
			cmdline = r_str_newf ("\"%s\" %s", appname, args);
		}
	} else {	
		if (cmd) {
			cmdline = r_str_newf ("\"%s\" %s", appname, cmd);
		} else {
			cmdline = r_str_newf ("\"%s\"", appname);
		}
	}
	appname_ = r_sys_conv_utf8_to_utf16 (appname);
	cmdline_ = r_sys_conv_utf8_to_utf16 (cmdline);
	if (!CreateProcess (appname_, cmdline_, NULL, NULL, FALSE,
				CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS,
				NULL, NULL, &si, &pi)) {
		r_sys_perror ("w32_dbg_new_proc/CreateProcess");
		goto err_w32_new_proc;
	}
	CloseHandle (pi.hProcess);	
	CloseHandle (pi.hThread);
	proc = proc_dbg_new (dbg_w32, (int)pi.dwProcessId, PROC_STATE_ATTACHED);
	if (!proc) {
		perror ("w32_dbg_new_proc/proc_dbg_new");
		goto err_w32_new_proc;
	}
	if (proc_dbg_wait (dbg, proc->pid, ret_proc) != R_DEBUG_REASON_BREAKPOINT) {
		eprintf ("w32_dbg_new_proc/w32_dbg_wait != R_DEBUG_REASON_BREAKPOINT\n");
		goto err_w32_new_proc;
	}
	pid = proc->pid;
err_w32_new_proc:
	if (pid == -1) {
		if (proc) {
			proc_dbg_delete (dbg_w32, proc);
		}
	}
	free (appname_);
	free (appname);
	free (cmdline_);
	free (cmdline);
	return pid;
}

bool w32_dbg_proc_kill (RDebug *dbg, int pid) {
	bool ret = false;
	HANDLE h_proc = NULL;

	/* stop debugging if we are still attached */
	if (w32_dbg_detach(dbg, pid) == -1) {
		goto err_w32_dbg_proc_kill;
	}
	h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h_proc) {
		r_sys_perror ("w32_dbg_proc_kill/OpenProcess");
		goto err_w32_dbg_proc_kill;
	}
	if (TerminateProcess (h_proc, 1) == 0) {
		r_sys_perror ("w32_dbg_proc_kill/TerminateProcess");
		goto err_w32_dbg_proc_kill;

	}
	/* wait up to one second to give the process some time to exit */
	DWORD ret_wait = WaitForSingleObject (h_proc, 1000);
	if (ret_wait == WAIT_FAILED) {
		r_sys_perror ("w32_dbg_proc_kill/WaitForSingleObject");
		goto err_w32_dbg_proc_kill;
	}
	if (ret_wait == WAIT_TIMEOUT) {
		eprintf ("(%d) waiting for process to terminate timed out.\n", pid);
		goto err_w32_dbg_proc_kill;
	}
	ret = true;
err_w32_dbg_proc_kill:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

void w32_break_process (void *d) {
	RDebug *dbg = (RDebug *)d;
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RDebugW32Proc *proc = proc_dbg_find (dbg_w32, dbg->pid, NULL);
	
	if (proc && !w32_DebugBreakProcess (proc->h_proc)) {
		r_sys_perror ("w32_break_process/w32_DebugBreakProcess");
	}
}

static int get_avx (HANDLE hThread, ut128 * xmm, ut128 * ymm) {
	BOOL Success;
	int nRegs = 0, Index = 0;
	DWORD ContextSize = 0;
	DWORD FeatureLength = 0;
	ut64 FeatureMask = 0;
	ut128 * Xmm = NULL;
	ut128 * Ymm = NULL;
	void * buffer = NULL;
	PCONTEXT Context;

	if (!w32_GetEnabledXStateFeatures) {
		return 0;
	}
	// Check for AVX extension
	FeatureMask = w32_GetEnabledXStateFeatures ();
	if ((FeatureMask & XSTATE_MASK_AVX) == 0) {
		r_sys_perror ("get_avx/GetEnabledXStateFeatures");
		goto err_get_avx;
	}
	Success = w32_InitializeContext (NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &ContextSize);
	if ((Success == TRUE) || (GetLastError () != ERROR_INSUFFICIENT_BUFFER)) {
		r_sys_perror ("get_avx/InitializeContext");
		goto err_get_avx;
	}
	buffer = malloc (ContextSize);
	if (!buffer) {
		perror ("get_avx/malloc");
		goto err_get_avx;
	}
	if (!w32_InitializeContext (buffer, CONTEXT_ALL | CONTEXT_XSTATE, &Context, &ContextSize)) {
		r_sys_perror ("get_avx/InitializeContext buffer");
		goto err_get_avx;
	}
	if (!w32_SetXStateFeaturesMask (Context, XSTATE_MASK_AVX)) {
		r_sys_perror ("get_avx/SetXStateFeaturesMask");
		goto err_get_avx;
	}
	if (!GetThreadContext (hThread, Context)) {
		r_sys_perror ("get_avx/GetThreadContext");
		goto err_get_avx;
	}
	if (!w32_GetXStateFeaturesMask (Context, &FeatureMask)) {
		r_sys_perror ("get_avx/GetXStateFeaturesMask");
		goto err_get_avx;
	}
	Xmm = (ut128 *)w32_LocateXStateFeature (Context, XSTATE_LEGACY_SSE, &FeatureLength);
        nRegs = FeatureLength / sizeof (*Xmm);
	for (Index = 0; Index < nRegs; Index++) {
		ymm[Index].High = 0;
		xmm[Index].High = 0;
		ymm[Index].Low = 0;
		xmm[Index].Low = 0;
	}
	if (Xmm != NULL) {
		for (Index = 0; Index < nRegs; Index++) {
			xmm[Index].High = Xmm[Index].High;
			xmm[Index].Low = Xmm[Index].Low;
		}
	}
	if ((FeatureMask & XSTATE_MASK_AVX) != 0) {
		// check for AVX initialization and get the pointer.
		Ymm = (ut128 *)w32_LocateXStateFeature (Context, XSTATE_AVX, NULL);
		for (Index = 0; Index < nRegs; Index++) {
			ymm[Index].High = Ymm[Index].High;
			ymm[Index].Low = Ymm[Index].Low;
		}
	}
err_get_avx:
	free (buffer);
	return nRegs;
}

static void show_ctx(HANDLE hThread, CONTEXT * ctx) {
	ut128 xmm[16];
	ut128 ymm[16];
	ut80 st[8];
	ut64 mm[8];
	ut16 top = 0;
	int x = 0, nxmm = 0, nymm = 0;
#if __MINGW64__ || _WIN64
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", (ut32)ctx->FltSave.ControlWord, (ut32)ctx->FltSave.StatusWord);
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", (ut32)ctx->MxCsr, (ut32)ctx->FltSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", (ut32)ctx->FltSave.ErrorOffset, (ut32)ctx->FltSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", (ut32)ctx->FltSave.ErrorSelector, (ut32)ctx->FltSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].Low = ctx->FltSave.FloatRegisters[x].Low;
		st[x].High = (ut16)ctx->FltSave.FloatRegisters[x].High;
	}
	top = (ctx->FltSave.StatusWord & 0x3fff) >> 11;
	x = 0;
	for (x = 0; x < 8; x++) {
		mm[top] = ctx->FltSave.FloatRegisters[x].Low;
		top++;
		if (top > 7) {
			top = 0;
		}
	}
	for (x = 0; x < 16; x++) {
		xmm[x].High = ctx->FltSave.XmmRegisters[x].High;
		xmm[x].Low = ctx->FltSave.XmmRegisters[x].Low;
	}
	nxmm = 16;
#else
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", (ut32) ctx->FloatSave.ControlWord, (ut32) ctx->FloatSave.StatusWord);
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", *(ut32 *)&ctx->ExtendedRegisters[24], (ut32)ctx->FloatSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", (ut32)ctx->FloatSave.ErrorOffset, (ut32)ctx->FloatSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", (ut32)ctx->FloatSave.ErrorSelector, (ut32) ctx->FloatSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].High = (ut16) *((ut16 *)(&ctx->FloatSave.RegisterArea[x * 10] + 8));
		st[x].Low = (ut64)  *((ut64 *)&ctx->FloatSave.RegisterArea[x * 10]);
	}
	top = (ctx->FloatSave.StatusWord & 0x3fff) >> 11;
	for (x = 0; x < 8; x++) {
		mm[top] = *((ut64 *)&ctx->FloatSave.RegisterArea[x * 10]);
		top++;
		if (top>7) {
			top = 0;
		}
	}
	for (x = 0; x < 8; x++) {
		xmm[x] = *((ut128 *)&ctx->ExtendedRegisters[(10 + x) * 16]);
	}
	nxmm = 8;
#endif
	// show fpu,mm,xmm regs
	for (x = 0; x < 8; x++) {
		// the conversin from long double to double only work for compilers
		// with long double size >=10 bytes (also we lost 2 bytes of precision)
		//   in mingw long double is 12 bytes size
		//   in msvc long double is alias for double = 8 bytes size
		//   in gcc long double is 10 bytes (correct representation)
		eprintf ("ST%i %04x %016"PFMT64x" (%f)\n", x, st[x].High, st[x].Low, (double)(*((long double *)&st[x])));
	}
	for (x = 0; x < 8; x++) {
		eprintf ("MM%i %016"PFMT64x"\n", x, mm[x]);
	}
	for (x = 0; x < nxmm; x++) {
		eprintf ("XMM%i %016"PFMT64x" %016"PFMT64x"\n", x, xmm[x].High, xmm[x].Low);
	}
	// show Ymm regs
	nymm = get_avx (hThread, (ut128 *)&xmm, (ut128 *)&ymm);
	if (nymm) {
		for (x = 0; x < nymm; x++) {
			eprintf ("Ymm%d: %016"PFMT64x" %016"PFMT64x" %016"PFMT64x" %016"PFMT64x"\n", x, ymm[x].High, ymm[x].Low, xmm[x].High, xmm[x].Low );
		}
	}
}

int w32_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
#ifdef _MSC_VER
	CONTEXT ctx;
#else
	CONTEXT ctx __attribute__ ((aligned (16)));
#endif
	int showfpu = false;
	int ret_size = 0;
	HANDLE h_th;
	RDebugW32Thread *th;

	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	th = th_dbg_cur (dbg);
	if (!th) {
		goto err_w32_reg_read;
	}
	h_th = th->h_th;
	memset (&ctx, 0, sizeof (CONTEXT));
	ctx.ContextFlags = CONTEXT_ALL ;
	if (!GetThreadContext (h_th, &ctx)) {
		r_sys_perror ("w32_reg_read/GetThreadContext");
		goto err_w32_reg_read;
	}
	if (type == R_REG_TYPE_GPR) {
		if (size > sizeof (CONTEXT)) {
			ret_size = sizeof (CONTEXT);
		} else {
			ret_size = size;
		}
		memcpy (buf, &ctx, ret_size);
	} 
	if (showfpu) {
		show_ctx (h_th, &ctx);
	}
err_w32_reg_read:
	return ret_size;
}

int w32_reg_write (RDebug *dbg, int type, const ut8* buf, int size) {
	BOOL ret = false;
	HANDLE h_th;
#if _MSC_VER
	CONTEXT ctx;
#else
	CONTEXT ctx __attribute__((aligned (16)));
#endif
	RDebugW32Thread *th = th_dbg_cur (dbg);

	if (!th) {
		goto err_w32_reg_write;
	}
	h_th = th->h_th;
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext (h_th, &ctx)) {
		r_sys_perror ("w32_reg_write/GetThreadContext");
		goto err_w32_reg_write;
	}
	if (type == R_REG_TYPE_GPR) {
		if (size > sizeof (CONTEXT)) {
			size = sizeof (CONTEXT);
		}
		memcpy (&ctx, buf, size);
		ret = SetThreadContext (h_th, &ctx)? true: false;
	}
err_w32_reg_write:
	return ret;
}

static void w32_info_user(RDebug *dbg, RDebugInfo *rdi) {
	HANDLE h_tok = NULL;
	DWORD tok_len = 0;
	PTOKEN_USER tok_usr = NULL;
	LPTSTR usr = NULL, usr_dom = NULL;
	DWORD usr_len = 512;
	DWORD usr_dom_len = 512;
	SID_NAME_USE snu = {0};
	RDebugW32Proc *proc = proc_dbg_cur (dbg);
	HANDLE h_proc;

	if (!proc) {
		goto err_w32_info_user;
	}
	h_proc = proc->h_proc;
	if (!OpenProcessToken (h_proc, TOKEN_QUERY, &h_tok)) {
		r_sys_perror ("w32_info_user/OpenProcessToken");
		goto err_w32_info_user;
	}
	if (!GetTokenInformation (h_tok, TokenUser, (LPVOID)&tok_usr, 0, &tok_len) && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
		r_sys_perror ("w32_info_user/GetTokenInformation");
		goto err_w32_info_user;
	}
	tok_usr = (PTOKEN_USER)malloc (tok_len);
	if (!tok_usr) {
		perror ("w32_info_user/malloc tok_usr");
		goto err_w32_info_user;
	}
	if (!GetTokenInformation (h_tok, TokenUser, (LPVOID)tok_usr, tok_len, &tok_len)) {
		r_sys_perror ("w32_info_user/GetTokenInformation");
		goto err_w32_info_user;
	}
	usr = (LPTSTR)malloc (usr_len);
	if (!usr) {
		perror ("w32_info_user/malloc usr");
		goto err_w32_info_user;
	}
	*usr = '\0';
	usr_dom = (LPTSTR)malloc (usr_dom_len);
	if (!usr_dom) {
		perror ("w32_info_user/malloc usr_dom");
		goto err_w32_info_user;
	}
	*usr_dom = '\0';
	if (!LookupAccountSid (NULL, tok_usr->User.Sid, usr, &usr_len, usr_dom, &usr_dom_len, &snu)) {
		r_sys_perror ("w32_info_user/LookupAccountSid");
		goto err_w32_info_user;
	}
	if (*usr_dom) {
		rdi->usr = r_str_newf (W32_TCHAR_FSTR"\\"W32_TCHAR_FSTR, usr_dom, usr);		
	} else {
		rdi->usr = r_sys_conv_utf16_to_utf8 (usr);
	}
err_w32_info_user:
    if (h_tok) {
	CloseHandle (h_tok);
    }
    free (usr);
    free (usr_dom);
    free (tok_usr);
}

void w32_info_exe(RDebug *dbg, RDebugInfo *rdi) {
	LPTSTR path = NULL;
	RDebugW32Proc *proc;
	HANDLE h_proc;
	DWORD len;

	if (!w32_QueryFullProcessImageName) {
		return;
	}
	proc = proc_dbg_cur (dbg);
	if (!proc) {
		goto err_w32_info_exe;
	}
	h_proc = proc->h_proc;
	path = (LPTSTR)malloc (MAX_PATH + 1);
	if (!path) {
		perror ("w32_info_exe/malloc path");
		goto err_w32_info_exe;
	}
	len = MAX_PATH;
	if (w32_QueryFullProcessImageName (h_proc, 0, path, &len)) {
		path[len] = '\0';
		rdi->exe = r_sys_conv_utf16_to_utf8 (path);
	} else {
		r_sys_perror ("w32_info_exe/QueryFullProcessImageName");
	}
err_w32_info_exe:
	free (path);
}

RDebugInfo* w32_info (RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;
	rdi->gid = -1;
	rdi->cwd = NULL;
	rdi->exe = NULL;
	rdi->cmdline = NULL;
	rdi->libname = NULL;
	w32_info_user (dbg, rdi);
	w32_info_exe (dbg, rdi);
	return rdi;
}

/* TODO: refactory, leaks */
RList *w32_desc_list (int pid) {
	RDebugDesc *desc;
	RList *ret = r_list_new ();
	int i;
	HANDLE processHandle;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	LPVOID buff;
	if (!(processHandle = OpenProcess (0x0040, FALSE, pid))) {
		eprintf ("win_desc_list: Error opening process.\n");
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc (handleInfoSize);
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	#define SystemHandleInformation 16
	while ((status = w32_NtQuerySystemInformation (SystemHandleInformation,handleInfo,handleInfoSize,NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc (handleInfo, handleInfoSize *= 2);
	if (status) {
		eprintf ("win_desc_list: NtQuerySystemInformation failed!\n");
		return NULL;
	}
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		if (handle.ProcessId != pid)
			continue;
		if (handle.ObjectTypeNumber != 0x1c)
			continue;
		if (w32_NtDuplicateObject (processHandle, &handle.Handle, GetCurrentProcess (), &dupHandle, 0, 0, 0))
			continue;
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc (0x1000);
		if (w32_NtQueryObject (dupHandle,2,objectTypeInfo,0x1000,NULL)) {
			CloseHandle (dupHandle);
			continue;
		}
		objectNameInfo = malloc (0x1000);
		if (w32_NtQueryObject (dupHandle,1,objectNameInfo,0x1000,&returnLength)) {
			objectNameInfo = realloc (objectNameInfo, returnLength);
			if (w32_NtQueryObject (dupHandle, 1, objectNameInfo, returnLength, NULL)) {
				free (objectTypeInfo);
				free (objectNameInfo);
				CloseHandle (dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length) {
			//objectTypeInfo->Name.Length ,objectTypeInfo->Name.Buffer,objectName.Length / 2,objectName.Buffer
			buff=malloc ((objectName.Length/2)+1);
			wcstombs (buff,objectName.Buffer,objectName.Length/2);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free (buff);
		} else {
			buff=malloc ((objectTypeInfo->Name.Length / 2)+1);
			wcstombs (buff,objectTypeInfo->Name.Buffer,objectTypeInfo->Name.Length);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free (buff);
		}
		free (objectTypeInfo);
		free (objectNameInfo);
		CloseHandle (dupHandle);
	}
	free (handleInfo);
	CloseHandle (processHandle);
	return ret;
}
