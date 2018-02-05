#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include "profile.h"

extern NTSTATUS (WINAPI *w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
extern BOOL (WINAPI *w32_QueryThreadCycleTime)(HANDLE, PULONG64);
extern BOOL (WINAPI *w32_QueryProcessCycleTime)(HANDLE, PULONG64);

static RDebugW32ProcProfile* update_ths_profile_info(RDebugW32Profile *profile, RDebugW32ProcProfile *proc);

static int th_profile_list_sort(const void *_a, const void *_b) {
	RDebugW32ThreadProfile *th1 = (RDebugW32ThreadProfile *)_a;
       	RDebugW32ThreadProfile *th2 = (RDebugW32ThreadProfile *)_b;

	if (th1->cpu_usage < th2->cpu_usage) {
		return 1;
	}
	if (th1->cpu_usage > th2->cpu_usage) {
		return -1;
	}
	return 0;
}

static void proc_profile_free(RDebugW32ProcProfile *proc) {
	r_list_free (proc->th_list);
	free (proc);
}

static void update_cpu_profile_info(RDebugW32Profile *profile)
{
	_PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION idle_cycles = NULL;
	_PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION intr_cycles = NULL;
	_PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION dpc_cycles = NULL;
	int n, n_cpus;
	ut64 cycles;

	if (!w32_NtQuerySystemInformation) {
		return;
	}
	if (profile->n_cpus <= 0) {
		SYSTEM_INFO si;

		GetSystemInfo (&si);
		profile->n_cpus = si.dwNumberOfProcessors;
	} 
	n_cpus = profile->n_cpus;
	if (n_cpus <= 0) {
		eprintf ("can not get number of processors\n");
		goto err_update_cpu_profile_info;
	}
	// cycle time for Idle
	idle_cycles = (_PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION)calloc (1, sizeof (*idle_cycles) * profile->n_cpus);
	if (!idle_cycles) {
		r_sys_perror ("update_cpu_profile_info/calloc idle_cycles");
		goto err_update_cpu_profile_info;
	}
	if (!NT_SUCCESS (w32_NtQuerySystemInformation (SystemProcessorIdleCycleTimeInformation,
			idle_cycles,
			sizeof (_SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION) * n_cpus, NULL))) {
		r_sys_perror ("update_cpu_profile_info/NtQuerySystemInformation SystemProcessorIdleCycleInformation");
		goto err_update_cpu_profile_info;
	}
	cycles = 0;
	for (n = 0; n < n_cpus; n++) {
		cycles += idle_cycles[n].CycleTime.QuadPart;
	}
	profile->idle_cycles_delta = cycles - profile->idle_cycles_value;
	profile->idle_cycles_value = cycles;
	// cycle time for Interrupt
	intr_cycles = (_PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION)calloc (1, sizeof (*intr_cycles) * n_cpus);
	if (!intr_cycles) {
		r_sys_perror ("update_cpu_profile_info/calloc intr_cycles");
		goto err_update_cpu_profile_info;
	}
	if (!NT_SUCCESS (w32_NtQuerySystemInformation (SystemProcessorCycleTimeInformation,
			intr_cycles,
			sizeof (_SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION) * n_cpus, NULL))) {
		r_sys_perror ("update_cpu_profile_info/NtQuerySystemInformation SystemProcessorCycleInformation");
		goto err_update_cpu_profile_info;
	}
	cycles = 0;
	for (n = 0; n < n_cpus; n++) {
		cycles += intr_cycles[n].CycleTime.QuadPart;
	}
	profile->intr_cycles_delta = cycles - profile->intr_cycles_value;
	profile->intr_cycles_value = cycles;
	// cycle time for Dpc
	dpc_cycles = (_PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)calloc (1, sizeof (*dpc_cycles) * n_cpus);
	if (!dpc_cycles) {
		r_sys_perror ("update_cpu_profile_info/calloc dpc_cycles");
		goto err_update_cpu_profile_info;
	}
	if (!NT_SUCCESS (w32_NtQuerySystemInformation (SystemProcessorPerformanceInformation,
			dpc_cycles,
			sizeof (_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * n_cpus, NULL))) {
		r_sys_perror ("update_cpu_profile_info/NtQuerySystemInformation SystemProcessorPerformanceInformation");
		goto err_update_cpu_profile_info;
	}
	cycles = 0;
	for (n = 0; n < n_cpus; n++) {
		cycles += dpc_cycles[n].DpcTime.QuadPart;
	}
	profile->dpc_cycles_delta = cycles - profile->dpc_cycles_value;
	profile->dpc_cycles_value = cycles;
err_update_cpu_profile_info:
	free (idle_cycles);
	free (intr_cycles);
	free (dpc_cycles);
}

static ut64 update_proc_profile_info(RDebugW32ProcProfile *proc) {
	HANDLE h_proc = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc->pid);
	ULONG64 cycles = 0;

	if (!h_proc) {
		r_sys_perror ("update_proc_profile_info/OpenProcess");
		goto err_update_proc_profile_info;
	}
	if (w32_QueryProcessCycleTime (h_proc, &cycles)) {
		FILETIME ctime, etime, ktime, utime;

		if (GetProcessTimes (h_proc, &ctime, &etime, &ktime, &utime)) {
			if (proc->ctime.dwLowDateTime != 0 || proc->ctime.dwHighDateTime != 0) {
				if (!CompareFileTime (&proc->ctime, &ctime)) {
					proc->cycles_delta = (ut64)cycles - proc->cycles_value;
				} else {
					proc->cycles_delta = (ut64)cycles;
				}
			} else {
				proc->ctime = ctime;
				proc->cycles_delta = (ut64)cycles;
			}
			proc->cycles_value = (ut64)cycles;
			cycles = proc->cycles_delta;
		}
	}
err_update_proc_profile_info:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return cycles;
}

static ut64 update_th_profile_info(RDebugW32Profile *profile, RDebugW32ThreadProfile *th) {
	HANDLE h_th = OpenThread (THREAD_QUERY_LIMITED_INFORMATION, FALSE, th->tid);
	ULONG64 cycles = 0;

	if (!h_th) {
		r_sys_perror ("update_th_profile_info/OpenProcess");
		goto err_update_th_profile_info;
	}
	if (w32_QueryThreadCycleTime (h_th, &cycles)) {
		FILETIME ctime, etime, ktime, utime;

		if (GetThreadTimes (h_th, &ctime, &etime, &ktime, &utime)) {
			if (th->ctime.dwLowDateTime != 0 || th->ctime.dwHighDateTime != 0) {
				if (!CompareFileTime (&th->ctime, &ctime)) {
					th->cycles_delta = (ut64)cycles - th->cycles_value;
				} else {
					th->cycles_delta = (ut64)cycles;
				}
			} else {
				th->ctime = ctime;
				th->cycles_delta = (ut64)cycles;
			}
			th->cycles_value = (ut64)cycles;
			cycles = th->cycles_delta;
		}
	}
err_update_th_profile_info:
	if (h_th) {
		CloseHandle (h_th);
	}
	return cycles;
}

static RDebugW32ProcProfile* update_procs_profile_info(RDebugW32Profile *profile, int pid) {
	HANDLE h_proc_snap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 proc32;
	HANDLE h_proc = NULL;
	RList *proc_list = profile->proc_list;
	RDebugW32ProcProfile *proc, *ret_proc = NULL;
	RListIter *iter, *iter2;
	DWORD tstamp;
	ut64 total_cycles = profile->idle_cycles_delta +
			profile->intr_cycles_delta +
			profile->dpc_cycles_delta;

	if (!w32_QueryProcessCycleTime) {
		return NULL;
	}
	h_proc_snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	if (h_proc_snap == INVALID_HANDLE_VALUE) {
		r_sys_perror ("update_procs_profile_info/CreateToolhelp32Snapshot");
		goto err_update_procs_profile_info;
	}
	proc32.dwSize = sizeof (PROCESSENTRY32);
	if (!Process32First (h_proc_snap, &proc32)) {
		r_sys_perror ("update_procs_profile_info/Process32First");
		goto err_update_procs_profile_info;
	}
	tstamp = GetTickCount ();
	do {
		bool proc_exists = false;
		if ((int)proc32.th32ProcessID == IDLE_PROCESS_ID) {
			continue;
		}
		r_list_foreach (proc_list, iter, proc) {
			if (proc->pid == proc32.th32ProcessID) {
				proc_exists = true;
				break;
			}
		}
		if (!proc_exists) {
			proc = R_NEW0 (RDebugW32ProcProfile);
			
			if (!proc) {
				perror ("update_procs_profile_info/alloc RDebugW32ProcProfile");
				continue;
			}
			proc->pid = (int)proc32.th32ProcessID;
			r_list_append (proc_list, proc);
		}
		proc->tstamp = tstamp;
		total_cycles += update_proc_profile_info (proc);
		if (proc->pid == pid) {
			update_ths_profile_info (profile, proc);
		}
	} while (Process32Next (h_proc_snap, &proc32));
	/* remove dead process */
	r_list_foreach_safe (proc_list, iter, iter2, proc) {
		if (proc->tstamp != tstamp) {
			r_list_delete (proc_list, iter);
		} else if (proc->pid == pid) {
			RList *th_list = proc->th_list;
			RDebugW32ThreadProfile *th;

			/* calculate cpu usage for process and threads */
			proc->cpu_usage = ((double)proc->cycles_delta / (double)profile->total_cycles) * 100;
			if (proc->cpu_usage >= 100.0f) {
				proc->cpu_usage = 0.0f;
			}
			r_list_foreach (th_list, iter, th) {
				th->cpu_usage = ((double)th->cycles_delta / (double)profile->total_cycles) * 100;
				if (th->cpu_usage >= 100.0f) {
					th->cpu_usage = 0.0f;
				}
			}
			ret_proc = proc;
		}
	}
	profile->total_cycles = total_cycles;
err_update_procs_profile_info:
	if (h_proc_snap != INVALID_HANDLE_VALUE) {
		CloseHandle (h_proc_snap);
	}
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return ret_proc;
}

static RDebugW32ProcProfile* update_ths_profile_info(RDebugW32Profile *profile, RDebugW32ProcProfile *proc) {
	RListIter *iter, *iter2;
	DWORD tstamp;
	PSYSTEM_PROCESS_INFORMATION sys_proc = NULL, sys_proc_it = NULL;
	PSYSTEM_THREAD_INFORMATION th_proc = NULL, th_proc_it = NULL;
	RDebugW32ThreadProfile *th;
	RList *th_list;
	ULONG ret_len = 0;
	int i, th_proc_n;

	if (!w32_QueryThreadCycleTime || !w32_NtQuerySystemInformation) {
		return NULL;
	}
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	if (w32_NtQuerySystemInformation (SystemProcessInformation, NULL,
				0, &ret_len) != STATUS_INFO_LENGTH_MISMATCH) {
		r_sys_perror ("update_ths_profile_info/NtQuerySystemInformation");
		goto err_update_ths_profile_info;
	}
	sys_proc = (PSYSTEM_PROCESS_INFORMATION)calloc(1, ret_len);
	if (!sys_proc) {
		perror ("update_ths_profile_info/alloc SYSTEM_PROCESS_INFORMATION");
		goto err_update_ths_profile_info;
	}
	if (!NT_SUCCESS (w32_NtQuerySystemInformation (SystemProcessInformation, sys_proc,
		ret_len, NULL))) {
		r_sys_perror ("update_ths_profile_info/NtQuerySystemInformation");
		goto err_update_ths_profile_info;
	}
	for (sys_proc_it = sys_proc; sys_proc_it->NextEntryOffset && (DWORD)(DWORD_PTR)sys_proc_it->UniqueProcessId != proc->pid;) {
		sys_proc_it = (PSYSTEM_PROCESS_INFORMATION)(((UCHAR *)sys_proc_it) + sys_proc_it->NextEntryOffset);
	}
	if((DWORD)(DWORD_PTR)sys_proc_it->UniqueProcessId != proc->pid) {
		goto err_update_ths_profile_info;
	}
	th_proc = (PSYSTEM_THREAD_INFORMATION)(((UCHAR *)sys_proc_it) + sizeof (SYSTEM_PROCESS_INFORMATION));
	th_proc_n = sys_proc_it->NumberOfThreads;
	tstamp = GetTickCount ();
	if (!proc->th_list) {
		proc->th_list = r_list_newf ((RListFree)free);
	}
	th_list = proc->th_list;
	for (i = 0, th_proc_it = th_proc; i < th_proc_n; i++, th_proc_it++) {
		int tid = (int)(DWORD_PTR)th_proc_it->ClientId.UniqueThread;
		bool th_exists = false;

		r_list_foreach (th_list, iter, th) {
			if (th->tid == tid) {
				th_exists = true;
				break;
			}
		}
		if (!th_exists) {
			th = R_NEW0 (RDebugW32ThreadProfile);
			
			if (!th) {
				perror ("update_ths_profile_info/alloc RDebugW32ThreadProfile");
				continue;
			}
			th->tid = tid;
			r_list_append (th_list, th);
		} else {

		}
		th->tstamp = tstamp;
		update_th_profile_info (profile, th);
	}
	/* remove terminated threads */
	r_list_foreach_safe (th_list, iter, iter2, th) {
		if (th->tstamp != tstamp) {
			r_list_delete (th_list, iter);
		}
	}
err_update_ths_profile_info:
	free (sys_proc);
	return proc;
}

bool w32_dbg_profiling(RDebug *dbg) {
	RDebugW32ProcProfile *proc;
	RDebugW32Profile *profile;
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	DWORD win_ver, major_ver;
	bool ret = false;

	/* supported only Windows 7, Vista, Server 2008 or greatest */
	win_ver = GetVersion();
	major_ver = (DWORD)(LOBYTE (LOWORD (win_ver)));
	if (major_ver < 6) {
		return false;
	}
	/* initialize profile? */
	if (!dbg_w32->profile) {
		profile = R_NEW0 (RDebugW32Profile);
		if (!profile) {
			perror ("w32_dbg_profiling/alloc RDebugW32Profile");
			goto err_w32_dbg_profiling;
		}
		profile->proc_list =  r_list_newf ((RListFree)proc_profile_free);
		dbg_w32->profile = profile;
	} else {
		profile = dbg_w32->profile;
	}
	update_cpu_profile_info (profile);
	proc = update_procs_profile_info (profile, dbg->pid);
	if (proc && proc->cpu_usage > 0.0f) {
		RListIter *iter;
		RDebugW32ThreadProfile *th;
		RList *th_list;

		th_list = proc->th_list;
		th_list->sorted = false;
		r_list_sort (th_list, th_profile_list_sort);
		dbg->cb_printf ("\npid (%d)\t%.2f%%\n", proc->pid, proc->cpu_usage);
		r_list_foreach (th_list, iter, th) {
			if (th->cpu_usage >= 0.01f) {
				dbg->cb_printf (" tid (%d)\t%.2f%%\n", th->tid, th->cpu_usage);
			}
		}
		dbg->cb_flush ();	
	}
	ret = true;
err_w32_dbg_profiling:
	return ret;
}

void w32_dbg_profiling_free(RDebug *dbg) {
	RDebugW32 *dbg_w32 = (RDebugW32 *)dbg->native_ptr;
	RDebugW32Profile *profile = (RDebugW32Profile *)dbg_w32->profile;

	if (profile) {
		r_list_free (profile->proc_list);
		free (profile);
	}
}
