#ifndef R2_ERROR_H
#define R2_ERROR_H

#include "r_types.h"

#define R_CORE_ERR_TYPE	0x10000000
#define R_NUM_ERR_TYPE	0x11000000

typedef struct r_error_t {
	ut32 code;
	char *msg;
} RError;

R_API void r_error_free(RError *err);
R_API RError* r_error_new();
R_API bool r_error_is(RError *err);
R_API void r_error_set(RError *err, ut32 code, char *msg);

#endif
