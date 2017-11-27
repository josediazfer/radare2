#ifndef WINDOWS_DBG_H
#define WINDOWS_DBG_H
#include <windows.h>
#include <r_debug.h>

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif
#ifndef WINAPI
#define WINAPI
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
	HANDLE h_th;
} RDebugW32Thread;

typedef struct {
	RList *lib_list;
	RList *th_list;
	ut64 base_addr;
	int pid;
	int tid;
	bool cont;
	int state;
	HANDLE h_proc;
} RDebugW32Proc;

typedef struct {
	RList *proc_list;
	bool init;
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

int w32_dbg_wait(RDebug *dbg, RDebugW32Proc **proc);
int w32_dbg_detach(RDebug *dbg, int pid);
RDebugInfo* w32_info(RDebug *dbg, const char *arg);
RList *w32_pids(int pid, RList *list);
RDebugW32 *w32_dbg_get(RDebug *dbg);
void w32_dbg_free(RDebug *dbg);
int w32_dbg_init(RDebug *dbg);
RList *w32_thread_list(int pid);
int w32_thread_first(int pid);
int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
int w32_reg_write(RDebug *dbg, int type, const ut8* buf, int size);
bool w32_terminate_process(RDebug *dbg, int pid);
RList *w32_desc_list(int pid);
int w32_dbg_continue(RDebug *dbg, int pid);
int w32_dbg_attach(RDebug *dbg, int pid, RDebugW32Proc **ret_proc);
int w32_dbg_new_proc(RDebug *dbg, const char *cmd, RDebugW32Proc **ret_proc);
bool w32_enable_dbg_priv();
ut64 w32_get_proc_baddr(int pid);
RDebugW32Proc *find_dbg_proc(RDebug *dbg, int pid);

#endif
