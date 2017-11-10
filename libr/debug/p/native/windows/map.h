#ifndef WINDOWS_MAP_H
#define WINDOWS_MAP_H
#include <windows.h>
#include <tlhelp32.h>
#include <r_debug.h>

RList *w32_dbg_modules(int pid);
RList *w32_dbg_maps(int pid);

#endif
