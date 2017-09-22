#include <r_debug.h>
/* radare - LGPL - Copyright 2017 - josediazfer */
/* Very simple memory cache (indexing with a key values array) */

static void r_debug_cache_item_free (RDebugCacheBuf *cache_buf) {
	r_buf_free (cache_buf->buf);
	free (cache_buf->user);
	free (cache_buf->key);
	free (cache_buf);
}

R_API RDebugCacheBuf* r_debug_cache_find(RList *cache_list, ut64 *key, int values, RListIter **ret_it) {
	RListIter *it;
	RDebugCacheBuf *cache_buf;

	r_list_foreach (cache_list, it, cache_buf) {
		if (cache_buf->values == values) {
			int i;
			for (i = 0; i < values; i++) {
				if (cache_buf->key[i] != key[i]) {
					break;
				}
			}
			if (i == values) {
				if (ret_it) {
					*ret_it = it;
				}
				return cache_buf;
			}
		}
	}
	return NULL;
}

R_API void r_debug_cache_delete(RList *cache_list, ut64 *key, int values) {
	RListIter *it;

	it = NULL;
	r_debug_cache_find (cache_list, key, values, &it);
	if (it) {
		r_list_delete(cache_list, it);
	}
}

R_API void r_debug_cache_init(RList **cache_list) {
	*cache_list = r_list_newf((RListFree)r_debug_cache_item_free);
}

R_API RDebugCacheBuf* r_debug_cache_add(RList *cache_list, ut64 *key, int values, const char *buf, int len) {
	ut64 *key_;
	RDebugCacheBuf *cache_buf;

	key_ = (ut64 *)malloc(values * sizeof(ut64));
	if (!key_) {
		perror("malloc r_debug_native_add_egg_code");
		goto err_r_debug_cache_add;
	}
	memcpy(key_, key, sizeof(ut64) * values);	
	cache_buf = R_NEW0 (RDebugCacheBuf);
	if (!cache_buf) {
		perror("new0 RDebugCacheBuf");
		goto err_r_debug_cache_add;
	}
	cache_buf->buf = r_buf_new_with_bytes (buf, len);
	cache_buf->key = key_;
	cache_buf->values = values;
	r_list_append (cache_list, cache_buf);
err_r_debug_cache_add:
	if (!cache_buf) {
		free (key);
	}
	return cache_buf;
}
