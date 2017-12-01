#include <r_util/r_str.h>
#include "common.h"

char *w32_dbg_fs_get(int pid) {
	if (pid == -1) {
		return NULL;
	}
	return NULL;
	//return r_str_newf ("debug%d", pid);
}
