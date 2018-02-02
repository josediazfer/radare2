#include "map.h"

extern DWORD (WINAPI *w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD);

typedef struct {
	RDebugMap *map;
	IMAGE_SECTION_HEADER *sect_hdr;
	int sect_count;
} RDebugW32Mod;

typedef struct {
	MEMORY_BASIC_INFORMATION mbi;
	char *sect_name;
} RDebugW32Map;

static const char *get_map_type(MEMORY_BASIC_INFORMATION *mbi) {
	char *type;
	switch (mbi->Type) {
	case MEM_IMAGE:
		type = "IMAGE";
		break;
	case MEM_MAPPED:
		type = "MAPPED";
		break;
	case MEM_PRIVATE:
		type = "PRIVATE";
		break;
	default:
		type = "UNKNOWN";
	}
	return type;
}

static void w32_map_free (void *native_ptr) {
	RDebugW32Map *map_w32;

	if (!native_ptr) {
		return;
	}
	map_w32 = (RDebugW32Map *)native_ptr;
	free (map_w32->sect_name);
	free (map_w32);
}

static RDebugMap *add_map(RList *list, const char *name, ut64 addr, ut64 len, MEMORY_BASIC_INFORMATION *mbi) {
	RDebugMap *map;
	int perm;

	switch (mbi->Protect) {
	case PAGE_EXECUTE:
		perm = R_IO_EXEC;
		break;
	case PAGE_EXECUTE_READ:
		perm = R_IO_READ | R_IO_EXEC;
		break;
	case PAGE_EXECUTE_READWRITE:
		perm = R_IO_READ | R_IO_WRITE | R_IO_EXEC;
		break;
	case PAGE_READONLY:
		perm = R_IO_READ;
		break;
	case PAGE_READWRITE:
		perm = R_IO_READ | R_IO_WRITE;
		break;
	case PAGE_WRITECOPY:
		perm = R_IO_WRITE;
		break;
	case PAGE_EXECUTE_WRITECOPY:
		perm = R_IO_EXEC;
		break;
	default:
		perm = 0;
	}
	map = r_debug_map_new ((char *)name, addr, addr + len, perm, mbi->Type == MEM_PRIVATE);
	if (map) {
		RDebugW32Map *map_w32;

		map_w32 = R_NEW0 (RDebugW32Map);
		if (map_w32) {
			map_w32->mbi = *mbi;	
			map->native_ptr = map_w32;
			map->native_free = w32_map_free;
		}
		if (list) {
			r_list_append (list, map);
		}
	}
	return map;
}

static inline RDebugMap *add_map_reg(RList *list, const char *name, MEMORY_BASIC_INFORMATION *mbi) {
	return add_map (list, name, (ut64)(size_t)mbi->BaseAddress, (ut64)mbi->RegionSize, mbi);
}

static inline int is_pe_hdr(unsigned char *pe_hdr) {
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

RList *w32_dbg_modules(int pid) {
	MODULEENTRY32 me32;
	RDebugMap *map;
	RList *list = r_list_newf ((RListFree)r_debug_map_free);
	DWORD flags = TH32CS_SNAPMODULE;
	HANDLE h_mod_snap;
#if __MINGW64__ || _WIN64
	flags |= TH32CS_SNAPMODULE32;
#endif
	if (pid == -1) {
		return list;
	}
	h_mod_snap = CreateToolhelp32Snapshot (flags, pid);
	if (!h_mod_snap) {
		r_sys_perror ("w32_dbg_modules/CreateToolhelp32Snapshot");
		goto err_w32_dbg_modules;
	}
	me32.dwSize = sizeof (MODULEENTRY32);
	if (!Module32First (h_mod_snap, &me32)) {
		goto err_w32_dbg_modules;
	}
	do {
		char *mod_name;
		ut64 baddr = (ut64)(size_t)me32.modBaseAddr;

		mod_name = r_sys_conv_utf16_to_utf8 (me32.szModule);
		map = r_debug_map_new (mod_name, baddr, baddr + me32.modBaseSize, 0, 0);
		free (mod_name);
		if (map) {
			map->file = r_sys_conv_utf16_to_utf8 (me32.szExePath);
			r_list_append (list, map);
		}
	} while (Module32Next (h_mod_snap, &me32));
err_w32_dbg_modules:
	if (h_mod_snap) {
		CloseHandle (h_mod_snap);
	}
	return list;
}

static int set_mod_inf(HANDLE h_proc, RDebugMap *map, RDebugW32Mod *mod) {
	IMAGE_DOS_HEADER *dos_hdr;
	IMAGE_NT_HEADERS *nt_hdrs;
	IMAGE_NT_HEADERS32 *nt_hdrs32;
	IMAGE_SECTION_HEADER *sect_hdr;
	ut8 pe_hdr[0x1000];
	SIZE_T len;
	int mod_inf_fill;

	len = 0;
	sect_hdr = NULL;
	mod_inf_fill = -1;
	ReadProcessMemory (h_proc, (LPCVOID)(size_t)map->addr, (LPVOID)pe_hdr, sizeof (pe_hdr), &len);
	if (len == (SIZE_T)sizeof (pe_hdr) && is_pe_hdr (pe_hdr)) {
		dos_hdr = (IMAGE_DOS_HEADER *)pe_hdr;
		if (!dos_hdr) {
			goto err_set_mod_info;
		}
		nt_hdrs = (IMAGE_NT_HEADERS *)((char *)dos_hdr + dos_hdr->e_lfanew);
		if (!nt_hdrs) {
			goto err_set_mod_info;
		}
		if (nt_hdrs->FileHeader.Machine == 0x014c) { // check for x32 pefile
			nt_hdrs32 = (IMAGE_NT_HEADERS32 *)((char *)dos_hdr + dos_hdr->e_lfanew);
			mod->sect_count = nt_hdrs32->FileHeader.NumberOfSections;
			sect_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_hdrs32 + sizeof (IMAGE_NT_HEADERS32));
		} else {
			mod->sect_count = nt_hdrs->FileHeader.NumberOfSections;
			sect_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_hdrs + sizeof (IMAGE_NT_HEADERS));
		}
		mod->sect_hdr = (IMAGE_SECTION_HEADER *)malloc (sizeof (IMAGE_SECTION_HEADER) * mod->sect_count);
		if (!mod->sect_hdr) {
			perror ("malloc set_mod_inf()");
			goto err_set_mod_info;
		}
		memcpy (mod->sect_hdr, sect_hdr, sizeof (IMAGE_SECTION_HEADER) * mod->sect_count);
		mod_inf_fill = 0;
	}
err_set_mod_info:
	if (mod_inf_fill == -1) {
		R_FREE (mod->sect_hdr);
	}
	return mod_inf_fill;
}

static void proc_mem_img(HANDLE h_proc, RList *map_list, RList *mod_list, RDebugW32Mod *mod, SYSTEM_INFO *si, MEMORY_BASIC_INFORMATION *mbi) {
	ut64 addr = (ut64)(size_t)mbi->BaseAddress;
	ut64 len = (ut64)mbi->RegionSize;
	if (!mod->map || addr < mod->map->addr || (addr + len) > mod->map->addr_end) {
		RListIter *iter;
		RDebugMap *map;

		free (mod->sect_hdr);
		memset (mod, 0, sizeof (RDebugW32Mod));
		r_list_foreach (mod_list, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				mod->map = map;
				set_mod_inf (h_proc, map, mod);
				break;
			}	
		}
	}
	if (mod->map && mod->sect_hdr && mod->sect_count > 0) {
		int sect_count;
		int i, p_mask;

		sect_count = 0;
		p_mask = si->dwPageSize - 1;
		for (i = 0; i < mod->sect_count; i++) {
			IMAGE_SECTION_HEADER *sect_hdr = &mod->sect_hdr[i];
			ut64 sect_addr = mod->map->addr + (ut64)sect_hdr->VirtualAddress;
			ut64 sect_len = (((ut64)sect_hdr->Misc.VirtualSize) + p_mask) & ~p_mask;
			int sect_found = 0;

			/* section in memory region? */
			if (sect_addr >= addr && (sect_addr + sect_len) <= (addr + len)) {
				sect_found = 1;
			/* memory region in section? */
			} else if (addr >= sect_addr && (addr + len) <= (sect_addr + sect_len)) {
				sect_found = 2;
			}
			if (sect_found) {
				RDebugMap *map;

				if (sect_found == 1) {
					map = add_map (map_list, mod->map->name, sect_addr, sect_len, mbi);
				} else {
					map = add_map_reg (map_list, mod->map->name, mbi);
				}
				if (map) {
					RDebugW32Map *map_w32;
					map_w32 = (RDebugW32Map *)map->native_ptr;
					if (map_w32) {
						map_w32->sect_name = r_str_new ((char *)sect_hdr->Name);
					}
				}
				sect_count++;
			}
		}
		if (sect_count == 0) {
			add_map_reg (map_list, mod->map->name, mbi);
		}
	} else {
		if (!mod->map) {
			add_map_reg (map_list, "", mbi);
		} else {
			add_map_reg (map_list, mod->map->name, mbi);
		}
	}
}

static void proc_mem_map(HANDLE h_proc, RList *map_list, MEMORY_BASIC_INFORMATION *mbi) {
	TCHAR f_name[MAX_PATH + 1];

	DWORD len = w32_GetMappedFileName (h_proc, mbi->BaseAddress, f_name, MAX_PATH);
	if (len > 0) {
		RDebugMap *map;

		char *f_name_ = r_sys_conv_utf16_to_utf8 (f_name);
		map = add_map_reg (map_list, "", mbi);
		if (map) {
			map->file = f_name_;
		} else {
			free (f_name_);
		}
	} else {
		add_map_reg (map_list, "", mbi);
	}
}

ut64 w32_dbg_map_addr_len(int pid, ut64 addr) {
	HANDLE h_proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	MEMORY_BASIC_INFORMATION mbi;
	ut64 len;
	ut64 map_len = 0;

	if (!h_proc) {
		r_sys_perror ("w32_dbg_map_addr_get/OpenProcess");
		goto err_w32_dbg_map_addr_get;
	}
	if (VirtualQueryEx (h_proc, (PVOID)(SIZE_T)addr, &mbi, sizeof (mbi)) == 0) {
		goto err_w32_dbg_map_addr_get;
	}
	len = addr - (ut64)mbi.BaseAddress;
	if (len >= (ut64)mbi.RegionSize) {
		map_len = 0;
	} else {
		map_len = (ut64)mbi.RegionSize - len;
	}
err_w32_dbg_map_addr_get:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return map_len;
}

RList *w32_dbg_maps(int pid) {
	SYSTEM_INFO si = {0};
	LPVOID cur_addr;
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE h_proc;
	RDebugW32Mod mod_inf = {0};
	RList *map_list = r_list_newf((RListFree)r_debug_map_free), *mod_list = NULL;

	if (pid == -1) {
		return map_list;
	}
	GetSystemInfo (&si);
	h_proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h_proc) {
		r_sys_perror ("w32_dbg_maps/OpenProcess");
		goto err_w32_dbg_maps;
	}
	cur_addr = si.lpMinimumApplicationAddress;
	/* get process modules list */
	mod_list = w32_dbg_modules (pid);
	/* process memory map */
	while (cur_addr < si.lpMaximumApplicationAddress && 
		VirtualQueryEx (h_proc, cur_addr, &mbi, sizeof (mbi)) != 0) {
		if (mbi.State != MEM_FREE) {
			switch (mbi.Type) {
			case MEM_IMAGE:
				proc_mem_img (h_proc, map_list, mod_list, &mod_inf, &si, &mbi);
				break;
			case MEM_MAPPED:
				proc_mem_map (h_proc, map_list, &mbi);
				break;
			default:
				add_map_reg (map_list, "", &mbi);
			}
		}
		cur_addr = (LPVOID)(size_t)((ut64)(size_t)mbi.BaseAddress + mbi.RegionSize);
	}
err_w32_dbg_maps:
	free (mod_inf.sect_hdr);
	r_list_free (mod_list);		
	return map_list;
}

static void maps_print (RDebug *dbg, ut64 addr) {
	RList *map_list = w32_dbg_maps (dbg->pid);
	RListIter *iter;
	RDebugMap *map;
	char buf[128];

	r_list_foreach (map_list, iter, map) {
		const char *type = map->shared? "sys": "usr";
		RDebugW32Map *map_w32 = (RDebugW32Map *)map->native_ptr;

		r_num_units (buf, map->size);
		dbg->cb_printf (dbg->bits & R_SYS_BITS_64
				? "0x%016"PFMT64x" # 0x%016"PFMT64x" %c %s %6s %c %s%8s"
				: "0x%08"PFMT64x" # 0x%08"PFMT64x" %c %s %6s %c %s%8s",
				map->addr,
				map->addr_end, 
				(addr >= map->addr && addr < map->addr_end)?'*':'-',
				type, buf,
				map->user?'u':'s',
				r_str_rwx_i (map->perm),
				get_map_type (&map_w32->mbi));switch (map_w32->mbi.Type) {
		case MEM_IMAGE:
			dbg->cb_printf (" %s %s\n", map->name, map_w32->sect_name? map_w32->sect_name : "");
			break;
		case MEM_MAPPED:
			dbg->cb_printf (" %s\n", map->file? map->file : "");
			break;
		default:
			dbg->cb_printf (" %s\n", map->name);
		}
	}
	r_list_free (map_list);
}

static void flags_maps_print(RDebug *dbg, ut64 addr) {
	RList *map_list = w32_dbg_maps (dbg->pid);
	RListIter *iter;
	RDebugMap *map;
	int n_map = 0;
	char *name_prev = NULL;

	if (r_list_length (map_list) <= 0) {
		return;
	}
	r_list_foreach (map_list, iter, map) {
		RDebugW32Map *map_w32 = (RDebugW32Map *)map->native_ptr;
		char *name = r_str_newf ("%s_%s%s", map->name,
					map_w32->sect_name ? map_w32->sect_name : "",
					r_str_rwx_i (map->perm));
		r_name_filter (name, 0);
		if (name_prev && !strcmp (name, name_prev)) {
			free (name);
			name = name_prev;
			dbg->cb_printf ("f map.%s#%d 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
					name, n_map, map->addr_end - map->addr, map->addr);
			n_map++;
		} else {
			dbg->cb_printf ("f map.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
					name, map->addr_end - map->addr, map->addr);
			free (name_prev);
			name_prev = name;
			n_map = 0;
		}
	}
	free (name_prev);
}

bool w32_dbg_maps_print (RDebug *dbg, ut64 addr, int type) {
	bool ret = true;

	switch (type) {
	case 'j':
	case 'q':
		ret = false;
		break;
	case '*':
		flags_maps_print (dbg, addr);
		break;
	default:
		maps_print (dbg, addr);
	}
	return ret;
}
