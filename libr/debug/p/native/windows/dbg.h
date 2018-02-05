#ifndef WINDOWS_DBG_H
#define WINDOWS_DBG_H
#include <windows.h>
#include <r_debug.h>
#include <r_flag.h>

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif
#ifndef WINAPI
#define WINAPI
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

enum RDebugW32ProcState {
	PROC_STATE_DETACHED,	/* process only is detached */
	PROC_STATE_ATTACHED,	/* process only is attached */
	PROC_STATE_STARTING,	/* registering process and libraries */
	PROC_STATE_STARTED,	/* end of previous state */
	PROC_STATE_READY	/* process ready for debugging */
};

enum RDebugW32ThreadState {
	THREAD_STATE_CREATED,
	THREAD_STATE_FINISHED
};

enum RDebugW32LibState {
	LIB_STATE_LOADED,
	LIB_STATE_UNLOADED
};

typedef struct {
	ut64 base_addr;
	char *path;
	char *name;
	int state;
} RDebugW32Lib;

typedef struct {
	ut64 entry_addr;
	int exit_code;
	int tid;
	int state;
	ut64 cycles_value;
	ut64 cycles_delta;
	HANDLE h_th;
} RDebugW32Thread;

typedef struct {
	RList *lib_list;
	RList *th_list;
	ut64 base_addr;
	int pid;
	int tid;
	bool cont, intr;
	int state;
	bool wow64;
	char *name, *path;
	HANDLE h_proc;
	RFlag *flags;
} RDebugW32Proc;

typedef struct {
	RList *proc_list;
	RFlag *core_flags;
	int n_cpus;
	bool init;
	void *profile;
} RDebugW32;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

#define SystemProcessInformation	0x05
#define SystemProcessorPerformanceInformation	0x02
#define SystemProcessorCycleTimeInformation	0x6c
#define SystemProcessorIdleCycleTimeInformation	0x53

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWait
} KTHREAD_STATE;

enum KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
};

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG	KPRIORITY;


/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx */
typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER Reserved1[3];
	ULONG Reserved2;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG Reserved3;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct __attribute__ ((aligned (16))) _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct __SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION {
	LARGE_INTEGER CycleTime;
} _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, *_PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION;

typedef struct __SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION {
	LARGE_INTEGER CycleTime;
} _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, *_PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *_PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

#define IDLE_PROCESS_ID 0
#define DPCS_PROCESS_ID -2
#define INTERRUPTS_PROCESS_ID -3


int w32_dbg_wait(RDebug *dbg, RDebugW32Proc **proc);
int w32_dbg_detach(RDebug *dbg, int pid);
RDebugInfo* w32_info(RDebug *dbg, const char *arg);
RList *w32_pids(int pid, RList *list);
RDebugW32 *w32_dbg_get(RDebug *dbg);
void w32_dbg_free(RDebug *dbg);
int w32_dbg_init(RDebug *dbg);
RList *w32_thread_list(RDebug *dbg, int pid);
int w32_thread_first(int pid);
int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
int w32_reg_write(RDebug *dbg, int type, const ut8* buf, int size);
bool w32_dbg_proc_kill(RDebug *dbg, int pid);
RList *w32_desc_list(int pid);
int w32_dbg_continue(RDebug *dbg, int pid, int sig);
int w32_dbg_attach(RDebug *dbg, int pid, RDebugW32Proc **ret_proc);
int w32_dbg_new_proc(RDebug *dbg, const char *cmd, char *args, RDebugW32Proc **ret_proc);
bool w32_enable_dbg_priv();
ut64 w32_get_proc_baddr(int pid);
RDebugW32Proc *find_dbg_proc(RDebug *dbg, int pid);
char *w32_reg_profile(RDebug *dbg);
int w32_dbg_select(RDebug *dbg, int pid, int tid);

#endif
