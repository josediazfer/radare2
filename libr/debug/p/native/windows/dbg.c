#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include "dbg.h"
#include "map.h"
#include "io_dbg.h"

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif
#ifndef WINAPI
#define WINAPI
#endif

DWORD (WINAPI *w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD) = NULL;

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
	bool ret = false;
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
	ret = AdjustTokenPrivileges (h_tok, FALSE, &tokenPriv, 0, NULL, NULL);
	if (!ret) {
		r_sys_perror ("Failed to change token privileges");
	}
err_w32_enable_dbg_priv:
	if (h_tok) {
		CloseHandle (h_tok);
	}
	return ret;
}

static void r_lib_info_free(RDebugW32LibInfo *lib_info) {
	free (lib_info->path);
	free (lib_info->name);
	free (lib_info);
}

void w32_dbg_free(RDebug *dbg) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	if (dbg_w32) {
		r_list_free (dbg_w32->libs_loaded_list);
		dbg_w32->libs_loaded_list = NULL;
		if (dbg_w32->lib_info && !dbg_w32->lib_info->loaded) {
			r_lib_info_free (dbg_w32->lib_info);
		}
		dbg_w32->lib_info = NULL;
		dbg->native_ptr = NULL;
	}
}

RDebugW32 *w32_dbg_get(RDebug *dbg) {
	RDebugW32 *dbg_w32;

	if (dbg->native_ptr) {
		dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	} else {
		dbg_w32 = R_NEW0 (RDebugW32);
		dbg->native_ptr = dbg_w32;
	}
	return dbg_w32;
}

int w32_dbg_init() {
	HMODULE h_mod;

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
		GetProcAddress(h_mod, "GetEnabledXStateFeatures");
	w32_InitializeContext = (BOOL (WINAPI *) (PVOID, DWORD, PCONTEXT*, PDWORD))
		GetProcAddress(h_mod, "InitializeContext");
	w32_GetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, PDWORD64))
		GetProcAddress(h_mod, "GetXStateFeaturesMask");
	w32_LocateXStateFeature = (PVOID (WINAPI *) (PCONTEXT Context, DWORD ,PDWORD))
		GetProcAddress(h_mod, "LocateXStateFeature");
	w32_SetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, DWORD64))
		GetProcAddress(h_mod, "SetXStateFeaturesMask");
	/****** PSAPI functions *****/
	h_mod = LoadLibrary (TEXT("psapi.dll"));
	if (!h_mod) {
		eprintf ("Cannot load psapi.dll. Aborting\n");
		return false;
	}
	w32_GetMappedFileName = (DWORD (WINAPI *)(HANDLE, LPVOID, LPTSTR, DWORD))
		GetProcAddress (h_mod, W32_TCALL ("GetMappedFileName"));
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
	return true;
}

inline static int w32_h2t(HANDLE h) {
	if (w32_GetThreadId != NULL) // >= Windows Vista
		return w32_GetThreadId (h);
	if (w32_GetProcessId != NULL) // >= Windows XP1
		return w32_GetProcessId (h);
	return (int)(size_t)h; // XXX broken
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
		eprintf ("(%d) Fatal exception (%s) in thread %d\n",
			(int)de->dwProcessId, 
			get_w32_excep_name(code),
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

static char *get_lib_from_mod(RDebug *dbg, ut64 lib_addr) {
	RListIter *iter;
	RDebugMap *map;
	RList *mods_list = w32_dbg_modules (dbg->pid);
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

static void set_lib_info(RDebug *dbg, DEBUG_EVENT *de, bool loaded) {
	RDebugW32 *dbg_w32 = w32_dbg_get (dbg);
	char *path = NULL;
	RDebugW32LibInfo *lib_info;
	RList *libs_loaded_list;

	if (!dbg_w32->libs_loaded_list) {
		dbg_w32->libs_loaded_list = r_list_newf ((RListFree)r_lib_info_free);	
	}
	libs_loaded_list = dbg_w32->libs_loaded_list;
	lib_info = R_NEW0 (RDebugW32LibInfo);
	if (!lib_info) {
		perror ("RDebugW32LibInfo alloc");
		goto err_set_lib_info;
	}
	if (dbg_w32->lib_info && !dbg_w32->lib_info->loaded) {
		r_lib_info_free (dbg_w32->lib_info);
	}
	lib_info->loaded = loaded;
	dbg_w32->lib_info = lib_info;
	if (loaded) {
		lib_info->base_addr = (ut64)(size_t)de->u.LoadDll.lpBaseOfDll;
		r_list_append (libs_loaded_list, lib_info);
		if (de->u.LoadDll.hFile) {
			path = get_file_name_from_handle (de->u.LoadDll.hFile);
		} else {
			path = get_lib_from_mod (dbg, lib_info->base_addr); 
		}
		if (!path && de->u.LoadDll.lpImageName) {
			LPVOID *image_name = de->u.LoadDll.lpImageName;
			if (de->u.LoadDll.fUnicode) {
				path = r_sys_conv_utf16_to_utf8 ((WCHAR *)image_name);
			} else {
				path = strdup ((const char *)image_name);
			}
		}
	} else {
		RListIter *iter;
		RDebugW32LibInfo *lib_loaded;

		lib_info->base_addr = (ut64)(size_t)de->u.UnloadDll.lpBaseOfDll;
		r_list_foreach (libs_loaded_list, iter, lib_loaded) {
			if (lib_loaded->base_addr == lib_info->base_addr) {
				path = strdup (lib_loaded->path);
				r_list_delete (libs_loaded_list, iter);
				break;
			}	
		}
	}
	lib_info->path = path;
	if (path && *path) {
		char *p;
	     	char *sep = NULL;

		for (p = path; *p; p++) {
			if (*p == '\\') {
				sep = p;
			}
		}	
		if (sep) {
			lib_info->name = strdup (sep + 1);
		}
	}
err_set_lib_info:
	if (loaded) {
		CloseHandle (de->u.LoadDll.hFile);
	}
}

static void set_thread_info(RDebug *dbg, DEBUG_EVENT *de) {
	RDebugW32 *dbg_w32 = w32_dbg_get (dbg);
	RDebugW32ThreadInfo *th_info = &dbg_w32->th_info;
	HANDLE h_th;
	PVOID th_entry_addr;
	
	h_th = de->u.CreateThread.hThread;
	if (w32_NtQueryInformationThread (h_th, 0x9 /*ThreadQuerySetWin32StartAddress*/, &th_entry_addr,
					sizeof (PVOID), NULL) == 0) { 
		th_info->entry_addr = (ut64)(size_t)th_entry_addr;
	} else {
		th_info->entry_addr = (ut64)(size_t)de->u.CreateThread.lpStartAddress;
	}
	th_info->exit_code = (int)de->u.ExitThread.dwExitCode;
}

int w32_dbg_wait(RDebug *dbg, int pid) {
	DEBUG_EVENT de;
	int tid, next_event = 0;
	unsigned int code;
	int ret = R_DEBUG_REASON_UNKNOWN;
	static int exited_already = 0;
	/* handle debug events */
	do {
		/* do not continue when already exited but still open for examination */
		if (exited_already == pid) {
			return -1;
		}
		memset (&de, 0, sizeof (DEBUG_EVENT));
		if (WaitForDebugEvent (&de, INFINITE) == 0) {
			r_sys_perror ("w32_dbg_wait/WaitForDebugEvent");
			return -1;
		}
		code = de.dwDebugEventCode;
		tid = de.dwThreadId;
		pid = de.dwProcessId;
		dbg->tid = tid;
		dbg->pid = pid;
		/* TODO: DEBUG_CONTROL_C */
		switch (code) {
		case CREATE_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) created process (%d:%p)\n",
				pid, w32_h2t (de.u.CreateProcessInfo.hProcess),
				de.u.CreateProcessInfo.lpStartAddress);
			w32_dbg_continue (dbg, pid, tid);
			next_event = 1;
			ret = R_DEBUG_REASON_NEW_PID;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) Process %d exited with exit code %d\n", (int)de.dwProcessId, (int)de.dwProcessId,
				(int)de.u.ExitProcess.dwExitCode);
			next_event = 0;
			exited_already = pid;
			ret = R_DEBUG_REASON_EXIT_PID;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			set_thread_info (dbg, &de);
			ret = R_DEBUG_REASON_NEW_TID;
			next_event = 0;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			set_thread_info (dbg, &de);
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_TID;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			set_lib_info (dbg, &de, true);
			next_event = 0;
			ret = R_DEBUG_REASON_NEW_LIB;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			set_lib_info (dbg, &de, false);
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_LIB;
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			eprintf ("(%d) Debug string\n", pid);
			w32_dbg_continue (dbg, pid, tid);
			next_event = 1;
			break;
		case RIP_EVENT:
			eprintf ("(%d) RIP event\n", pid);
			w32_dbg_continue (dbg, pid, tid);
			next_event = 1;
			// XXX unknown ret = R_DEBUG_REASON_TRAP;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
#if __MINGW64__ || _WIN64
			case 0x4000001f: /* STATUS_WX86_BREAKPOINT */
#endif
			case EXCEPTION_BREAKPOINT:
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
			default:
				if (!dbg_exception_event (&de)) {
					ret = R_DEBUG_REASON_TRAP;
					next_event = 0;
				}
				else {
					next_event = 1;
					w32_dbg_continue (dbg, pid, tid);
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

RList *w32_thread_list(int pid, RList *list) {
        HANDLE h_proc_snap = INVALID_HANDLE_VALUE;
        THREADENTRY32 te32;

        h_proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if (h_proc_snap == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_thread_list/CreateToolhelp32Snapshot");
                goto err_w32_thread_list;
	}
        te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First (h_proc_snap, &te32)) {
		r_sys_perror ("w32_thread_list/Thread32First");
                goto err_w32_thread_list;
	}
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
err_w32_thread_list:
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
	do {
		if (show_all_pids ||
			pe.th32ProcessID == pid ||
			pe.th32ParentProcessID == pid) {

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

int w32_dbg_detach(int pid) {
	if (pid == -1) {
		return -1;
	}
	return w32_DebugActiveProcessStop (pid)? 0 : -1;
}

int w32_dbg_continue(RDebug *dbg, int pid, int tid)
{ 
	/* Honor the Windows-specific signal that instructs threads to process exceptions */
	/* DWORD continue_status = (sig == DBG_EXCEPTION_NOT_HANDLED)
		? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
		*/
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		eprintf ("failed debug_contp pid %d tid %d\n", pid, tid);
		r_sys_perror ("w32_dbg_continue/ContinueDebugEvent");
		return -1;
	}
	return tid;
}

int w32_dbg_attach(int pid, PHANDLE h_proc_, ut64 *base_addr)
{
	HANDLE h_proc = NULL;
	DEBUG_EVENT de = {0};
	int ret = -1;
	bool attached = false;

	/* we only can attach one process at a time */
	w32_dbg_detach(pid);
	h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h_proc) {
		r_sys_perror ("r_debug_native_attach/OpenProcess");
		goto err_w32_dbg_attach;
	}
	if (!DebugActiveProcess (pid)) {
		r_sys_perror ("r_debug_native_attach/DebugActiveProcess");
		goto err_w32_dbg_attach;
	}
	attached = true;
	if (WaitForDebugEvent (&de, INFINITE) == 0) {
		r_sys_perror ("r_debug_native_attach/WaitForDebugEvent");
		goto err_w32_dbg_attach;
	}	
	if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
		eprintf ("r_debug_native_attach: unexpected debug event %04x\n", (uint32_t)de.dwDebugEventCode);
		goto err_w32_dbg_attach;
	}
	if (base_addr) {
		*base_addr = (ut64)(SIZE_T)de.u.CreateProcessInfo.lpBaseOfImage;
	}
	ret = de.dwThreadId;
err_w32_dbg_attach:
	if (!h_proc_) {
		if (h_proc) {
			CloseHandle (h_proc);
		}
	} else {
		*h_proc_ = h_proc;		
	}
	if (ret == -1 && attached) {
		w32_DebugActiveProcessStop (pid);
	}
	return ret;
}

bool w32_terminate_process (RDebug *dbg, int pid) {
	HANDLE h_proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE , FALSE, pid);
	bool ret = false;
	if (!h_proc) {
		r_sys_perror ("w32_terminate_process/OpenProcess");
		goto err_w32_terminate_process;
	}
	/* stop debugging if we are still attached */
	w32_DebugActiveProcessStop (pid); //DebugActiveProcessStop (pid);
	if (TerminateProcess (h_proc, 1) == 0) {
		r_sys_perror ("e32_terminate_process/TerminateProcess");
		goto err_w32_terminate_process;

	}
	/* wait up to one second to give the process some time to exit */
	DWORD ret_wait = WaitForSingleObject (h_proc, 1000);
	if (ret_wait == WAIT_FAILED) {
		r_sys_perror ("w32_terminate_process/WaitForSingleObject");
		goto err_w32_terminate_process;
	}
	if (ret_wait == WAIT_TIMEOUT) {
		eprintf ("(%d) Waiting for process to terminate timed out.\n", pid);
		goto err_w32_terminate_process;
	}
	ret = true;
err_w32_terminate_process:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

void w32_break_process (void *d) {
	RDebug *dbg = (RDebug *)d;
	HANDLE h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (!h_proc) {
		r_sys_perror ("w32_break_process/OpenProcess");
		goto err_w32_break_process;
	}
	if (!w32_DebugBreakProcess (h_proc)) {
		r_sys_perror ("w32_break_process/w32_DebugBreakProcess");
		goto err_w32_break_process;
	}
err_w32_break_process:
	if (h_proc) {
		CloseHandle (h_proc);
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
	if ((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
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
		Ymm = (ut128 *)w32_LocateXStateFeature(Context, XSTATE_AVX, NULL);
		for (Index = 0; Index < nRegs; Index++) {
			ymm[Index].High = Ymm[Index].High;
			ymm[Index].Low = Ymm[Index].Low;
		}
	}
err_get_avx:
	free(buffer);
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
	int tid = dbg->tid;
	int ret_size = 0;
	HANDLE h_th;

	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	h_th = OpenThread (THREAD_ALL_ACCESS, FALSE, tid);
	if (!h_th) {
		r_sys_perror ("w32_reg_read/OpenThread");
		goto err_w32_reg_read;
	}
	memset(&ctx, 0, sizeof (CONTEXT));
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
	if (h_th) {
		CloseHandle (h_th);
	}
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
	h_th = OpenThread (THREAD_ALL_ACCESS, FALSE, dbg->tid);
	if (!h_th) {
		r_sys_perror ("w32_reg_write/OpenThread");
		goto err_w32_reg_write;
	}
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
	if (h_th) {
		CloseHandle (h_th);
	}
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
	HANDLE h_proc = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, dbg->pid);

	if (!h_proc) {
		r_sys_perror ("w32_info_user/OpenProcess");
		goto err_w32_info_user;
	}
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
    if (h_proc) {
	CloseHandle (h_proc);
    }
    if (h_tok) {
	CloseHandle (h_tok);
    }
    free (usr);
    free (usr_dom);
    free (tok_usr);
}

void w32_info_exe(RDebug *dbg, RDebugInfo *rdi) {
	LPTSTR path = NULL;
	HANDLE h_proc;
	DWORD len;

	if (!w32_QueryFullProcessImageName) {
		return;
	}
	h_proc = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, dbg->pid);
	if (!h_proc) {
		r_sys_perror ("w32_info_exe/OpenProcess");
		goto err_w32_info_exe;
	}
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
	if (h_proc) {
		CloseHandle (h_proc);
	}
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

RList *w32_desc_list (int pid) {
	RDebugDesc *desc;
	RList *ret = r_list_new();
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
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	#define SystemHandleInformation 16
	while ((status = w32_NtQuerySystemInformation(SystemHandleInformation,handleInfo,handleInfoSize,NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (status) {
		eprintf("win_desc_list: NtQuerySystemInformation failed!\n");
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
		if (w32_NtDuplicateObject (processHandle, &handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0))
			continue;
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (w32_NtQueryObject(dupHandle,2,objectTypeInfo,0x1000,NULL)) {
			CloseHandle(dupHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);
		if (w32_NtQueryObject(dupHandle,1,objectNameInfo,0x1000,&returnLength)) {
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (w32_NtQueryObject(dupHandle, 1, objectNameInfo, returnLength, NULL)) {
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length) {
			//objectTypeInfo->Name.Length ,objectTypeInfo->Name.Buffer,objectName.Length / 2,objectName.Buffer
			buff=malloc((objectName.Length/2)+1);
			wcstombs(buff,objectName.Buffer,objectName.Length/2);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free(buff);
		} else {
			buff=malloc((objectTypeInfo->Name.Length / 2)+1);
			wcstombs(buff,objectTypeInfo->Name.Buffer,objectTypeInfo->Name.Length);
			desc = r_debug_desc_new (handle.Handle,
					buff, 0, '?', 0);
			if (!desc) break;
			r_list_append (ret, desc);
			free(buff);
		}
		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}
	free(handleInfo);
	CloseHandle(processHandle);
	return ret;
}
