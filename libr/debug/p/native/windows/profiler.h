#ifndef WINDOWS_DBG_PROFILER_H
#define WINDOWS_DBG_PROFILER_H
#include "dbg.h"

typedef struct {
	int tid;
	ut64 cycles_delta;
	ut64 cycles_value;
	FILETIME ctime;
	DWORD tstamp;
	float cpu_usage;
} RDebugW32ThreadProfiler;

typedef struct {
	int pid;
	ut64 cycles_delta;
	ut64 cycles_value;
	FILETIME ctime;
	DWORD tstamp;
	RList *th_list;
	float cpu_usage;
} RDebugW32ProcProfiler;

typedef struct {
	ut64 idle_cycles_delta;
	ut64 idle_cycles_value;
	ut64 dpc_cycles_delta;
	ut64 dpc_cycles_value;
	ut64 intr_cycles_delta;
	ut64 intr_cycles_value;
	RList *proc_list;
	ut64 total_cycles;
	int n_cpus;
} RDebugW32Profiler;

bool w32_dbg_profiling(RDebug *dbg, bool enable);
void w32_dbg_profiling_free(RDebug *dbg);
#endif
