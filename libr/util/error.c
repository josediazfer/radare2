#include "r_util/r_error.h"

R_API void r_error_free(RError *err) {
	if (err) {
		free(err->msg);
	}
	free (err);
}

R_API RError* r_error_new() {
	return R_NEW0 (RError);
}

inline R_API bool r_error_is(RError *err) {
	return err && err->code;
}

inline R_API void r_error_set(RError *err, ut32 code, char *msg) {
	err->code = code;
	free (err->msg);
	err->msg = msg;
}
