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

typedef struct {
	ut64 base_addr;
	char *path;
	char *name;
	bool loaded;
} RDebugW32LibInfo;

typedef struct {
	ut64 entry_addr;
	int exit_code;
} RDebugW32ThreadInfo;

typedef struct {
	RList *libs_loaded_list;
	RDebugW32ThreadInfo th_info;
	RDebugW32LibInfo *lib_info;
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

int w32_dbg_wait(RDebug *dbg, int pid);
int w32_dbg_detach(int pid);
RDebugInfo* w32_info(RDebug *dbg, const char *arg);
RList *w32_pids(int pid, RList *list);
RDebugW32 *w32_dbg_get(RDebug *dbg);
void w32_dbg_free(RDebug *dbg);
int w32_dbg_init();
RList *w32_thread_list(int pid, RList *list);
int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
int w32_reg_write(RDebug *dbg, int type, const ut8* buf, int size);
bool w32_terminate_process(RDebug *dbg, int pid);
RList *w32_desc_list(int pid);
int w32_dbg_continue(RDebug *dbg, int pid, int tid);
int w32_first_thread(int pid);
int w32_dbg_attach(int pid, PHANDLE h_proc_, ut64 *base_addr);
bool w32_enable_dbg_priv();

#endif
