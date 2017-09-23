/* radare - LGPL - Copyright 2017 - josediazfer */
/* This is a tiny process memory manager, it´s used to write some code/data in the debugged process memory.
*/
#include <r_debug.h>

static RDebugMemChunk* r_debug_mem_chunk_new(ut64 addr, int sz);
static RListIter* r_debug_mem_find_chunk(RDebugMemArena *proc_arena, ut64 addr, int sz, bool need_alloc);

#define DEBUG_MEM_PROC_VERBOSE 0
#define DEFAULT_DEBUG_MEM_ARENA_SIZE 8192

static int mem_addr_cmp(RDebugMemChunk *a, RDebugMemChunk *b) {
	if (a->addr == b->addr) return 0;
	if (a->addr < b->addr) return -1;
	return 1; /* a->addr > b->addr */
}

static RDebugMemChunk* r_debug_mem_chunk_new(ut64 addr, int sz) {
        RDebugMemChunk *chunk;

        if (sz <= 0) {
                eprintf ("r_debug_mem_chunk_new: error ("
                       "0x%08"PFMT64x " %d)\n", addr, sz);
                return NULL;
        }
        chunk = R_NEW0 (RDebugMemChunk);
        if (!chunk) {
                return NULL;
        }
        chunk->addr = addr;
        chunk->sz = sz;
        return chunk;
}

static void r_debug_mem_unify_chunks(RDebug *dbg) {
	RListIter *chunk_it;
	RDebugMemChunk *chunk, *prev_chunk = NULL;
	RDebugMemArena *proc_arena = dbg->proc_arena;
	RList *unify_list = r_list_new ();
	bool unifying = false;
	ut64 chunk_unify_addr = 0, chunk_unify_sz = 0;

#if DEBUG_MEM_PROC_VERBOSE
		eprintf("unifying chunks...\n");
#endif
	/* make unifyied list and mark purgable chunks */	
	r_list_foreach (proc_arena->chunk_free_list, chunk_it, chunk) {
		if (prev_chunk != NULL && (prev_chunk->addr + prev_chunk->sz) == chunk->addr) {
			if (!unifying) {
				chunk_unify_addr = prev_chunk->addr;
				chunk_unify_sz = prev_chunk->sz;
				prev_chunk->purge = 1;
				unifying = true;
			}
			chunk->purge = 1;
			chunk_unify_sz += chunk->sz;
		} else if (unifying == true) {
			RDebugMemChunk *chunk_unify =
					r_debug_mem_chunk_new (chunk_unify_addr,
								chunk_unify_sz);

			r_list_append (unify_list, chunk_unify);
			unifying = false;
		}
		prev_chunk = chunk;	
	}
	if (unifying) {
		RDebugMemChunk *chunk_unify =
				r_debug_mem_chunk_new (chunk_unify_addr,
							chunk_unify_sz);

		r_list_append (unify_list, chunk_unify);
	}
	/* free purgeable chunks */
	r_list_foreach (proc_arena->chunk_free_list, chunk_it, chunk) {
		if (chunk->purge) {
			r_list_delete (proc_arena->chunk_free_list, chunk_it);
		}
	}
	/* add unified chunks */
	r_list_foreach (unify_list, chunk_it, chunk) {
		r_list_add_sorted (proc_arena->chunk_free_list, chunk, ((RListComparator)mem_addr_cmp));
	}
	R_FREE (unify_list);
}

static RListIter* r_debug_mem_find_chunk(RDebugMemArena *proc_arena, ut64 addr, int sz, bool need_alloc) {
        RListIter *ret_chunk_it = NULL;

        if (proc_arena->free_sz < sz) {
                return NULL;
        }
        if (need_alloc) {
                RListIter *chunk_it;
                RDebugMemChunk *chunk;

                r_list_foreach (proc_arena->chunk_free_list, chunk_it, chunk) {
                        if(chunk->sz == sz) {
                                ret_chunk_it = chunk_it;
                                break;
                        }
                        if (chunk->sz > sz) {
                                if (ret_chunk_it != NULL) {
                			RDebugMemChunk *ret_chunk;

					ret_chunk = ret_chunk_it->data;	
                                        if (chunk->sz < ret_chunk->sz) {
                                                ret_chunk_it = chunk_it;
                                        }
                                } else {
                                        ret_chunk_it = chunk_it;
                                }
                        }
                }
        } else {
                RListIter *chunk_it;
                RDebugMemChunk *chunk;

                r_list_foreach (proc_arena->chunk_alloc_list, chunk_it, chunk) {
                        if (chunk->addr == addr) {
                                ret_chunk_it = chunk_it;
                                break;
                        }
                }
        }
        return ret_chunk_it;
}

R_API void r_debug_mem_proc_info(RDebug *dbg) {
	RListIter *it;
	RDebugMemChunk *chunk;
	RDebugMemArena *proc_arena = dbg->proc_arena;

	if (!proc_arena) {
		eprintf ("uninitialized process memory aren!a\n");
		return;
	}
	eprintf ("==============================================\n");
	eprintf (">> process memory managment info\n");
	eprintf ("==============================================\n");
	eprintf ("\tarena map 0x%08"PFMT64x"-0x%08"PFMT64x"\n", proc_arena->map.addr, proc_arena->map.addr_end);
	eprintf ("\tarena size: %d bytes\n", proc_arena->sz);
	eprintf ("\tallocated size: %d bytes\n", proc_arena->sz - proc_arena->free_sz);
	eprintf ("\tfree size: %d bytes\n", proc_arena->free_sz);
	eprintf ("==============================================\n");
	eprintf (">> allocated %d chunks:\n", proc_arena->chunk_alloc_list->length);
	eprintf ("==============================================\n");
	r_list_foreach (proc_arena->chunk_alloc_list, it, chunk) {
		eprintf ("addr: 0x%08"PFMT64x " size: %d\n", chunk->addr, chunk->sz);
	}
	eprintf ("==============================================\n");
	eprintf (">> freed %d chunks:\n", proc_arena->chunk_free_list->length);
	eprintf ("==============================================\n");
	r_list_foreach (proc_arena->chunk_free_list, it, chunk) {
		eprintf ("addr: 0x%08"PFMT64x " size: %d\n", chunk->addr, chunk->sz);
	}
	eprintf ("\n");
}

R_API ut64 r_debug_mem_proc_alloc(RDebug *dbg, int sz) {
	RDebugMemChunk *chunk = NULL;
	RDebugMemChunk *chunk1 = NULL, *chunk2 = NULL;
	RListIter *chunk_it;
	RDebugMemArena *proc_arena = dbg->proc_arena;
	bool fail;

        if (sz > DEFAULT_DEBUG_MEM_ARENA_SIZE || (proc_arena && sz > proc_arena->free_sz)) {
                return 0;
        }
        /* init arena for the process debugged */
	fail = true;
        if (!proc_arena) {
                RDebugMap *map;

		proc_arena = calloc(1, sizeof(RDebugMemArena));
                if (!proc_arena) {
			goto err_r_debug_proc_alloc;
		}
                map = dbg->h->map_alloc (dbg, 0, DEFAULT_DEBUG_MEM_ARENA_SIZE);
                if (!map) {
			goto err_r_debug_proc_alloc;
		}
		proc_arena->map = *map;
		chunk = r_debug_mem_chunk_new (proc_arena->map.addr, proc_arena->map.size);
		if (!chunk) {
			goto err_r_debug_proc_alloc;
		}
		proc_arena->sz = map->size;
		proc_arena->free_sz = proc_arena->sz;
		proc_arena->chunk_free_list = r_list_newf ((RListFree)free);
		proc_arena->chunk_alloc_list = r_list_newf ((RListFree)free);
		r_list_append (proc_arena->chunk_free_list, chunk);
		dbg->proc_arena = proc_arena;
        }
        if (sz > proc_arena->free_sz) {
                goto err_r_debug_proc_alloc;
        }
	chunk_it = r_debug_mem_find_chunk (proc_arena, 0, sz, true);
	if (!chunk_it) {
		r_debug_mem_unify_chunks(dbg);
		chunk_it = r_debug_mem_find_chunk (proc_arena, 0, sz, true);
	}
	if (chunk_it) {
		chunk = chunk_it->data;
		if (chunk->sz > sz) {
                        chunk1 = r_debug_mem_chunk_new (chunk->addr, sz);
			if (!chunk1) {
				goto err_r_debug_proc_alloc;
			}
                        chunk2 = r_debug_mem_chunk_new (chunk->addr + sz, chunk->sz - sz);
			if (!chunk2) {
				goto err_r_debug_proc_alloc;
			}
#if DEBUG_MEM_PROC_VERBOSE
		eprintf("chunk allocated 0x%08"PFMT64x ":%d, chunk freed 0x%08"PFMT64x ":%d\n", chunk1->addr, chunk1->sz, chunk2->addr, chunk2->sz);
#endif
			r_list_delete (proc_arena->chunk_free_list, chunk_it);
                        r_list_add_sorted (proc_arena->chunk_alloc_list, chunk1, ((RListComparator)mem_addr_cmp));
			r_list_add_sorted (proc_arena->chunk_free_list, chunk2, ((RListComparator)mem_addr_cmp));
			chunk = chunk1;
		} else if (chunk->sz == sz) {
			RDebugMemChunk *aux;

			aux = r_debug_mem_chunk_new (chunk->addr, chunk->sz);
			if (!aux) {
				goto err_r_debug_proc_alloc;
			}
			r_list_delete (proc_arena->chunk_free_list, chunk_it);
			r_list_add_sorted (proc_arena->chunk_alloc_list, aux, ((RListComparator)mem_addr_cmp));
			chunk = aux;
#if DEBUG_MEM_PROC_VERBOSE
			eprintf("chunk allocated 0x%08"PFMT64x ":%d\n", aux->addr, aux->sz);
#endif
		} 
                proc_arena->free_sz -= sz;
		fail = false;
	}
err_r_debug_proc_alloc:
	if (fail) {
		free (chunk1);
		free (chunk2);
		chunk = NULL;

		if (proc_arena && proc_arena->sz == 0) {
			if (proc_arena->map.addr != 0) {
                		dbg->h->map_dealloc (dbg, proc_arena->map.addr, proc_arena->map.size);
			}
			R_FREE (dbg->proc_arena);
		} 
	}
#if DEBUG_MEM_PROC_VERBOSE
	r_debug_mem_proc_info (dbg);
	if (!chunk) {
		eprintf ("can not alloc %d bytes\n", sz);
	}
#endif
        return chunk? chunk->addr : 0;
}

R_API bool r_debug_mem_proc_free(RDebug *dbg, ut64 addr) {
	RListIter *chunk_it = NULL;
	RDebugMemArena *proc_arena = dbg->proc_arena;
	bool freed = false;

	if (!proc_arena || addr == 0) {
		return false;
	}
	chunk_it = r_debug_mem_find_chunk (proc_arena, addr, 0, false);
	if (chunk_it) {
		RDebugMemChunk *chunk, *aux;

		chunk = chunk_it->data; 
		aux = r_debug_mem_chunk_new (chunk->addr, chunk->sz);
		if (!aux) {
			goto err_r_debug_mem_proc_free;
		}
		r_list_delete (proc_arena->chunk_alloc_list, chunk_it);
		r_list_add_sorted (proc_arena->chunk_free_list, aux, ((RListComparator)mem_addr_cmp));
		proc_arena->free_sz += chunk->sz;
		freed = true;
#if DEBUG_MEM_PROC_VERBOSE
		eprintf("chunk freed 0x%08"PFMT64x ":%d\n", aux->addr, aux->sz);
#endif
	}
err_r_debug_mem_proc_free:
#if DEBUG_MEM_PROC_VERBOSE
	r_debug_mem_proc_info (dbg);
	if (!freed) {
		eprintf ("can not free 0x%08"PFMT64x "\n", addr);
	}
#endif
	return freed;
}

R_API void r_debug_mem_test (RDebug *dbg) {
	int addr_sz [] = {6, 8, 100, 400, 500, 4096, 3000};
	ut64 addr[sizeof (addr_sz) / sizeof(int)];
	int i;

	for (i = 0; i < sizeof (addr_sz) / sizeof(int); i++) {
		addr[i] = r_debug_mem_proc_alloc (dbg, addr_sz[i]);
		eprintf ("alloc %d bytes at 0x%08"PFMT64x "\n", addr_sz[i], addr[i]);
	}

	for (i = 0; i < sizeof (addr_sz) / sizeof(int); i++) {
		r_debug_mem_proc_free (dbg, addr[i]);
		eprintf ("free %d bytes at 0x%08"PFMT64x "\n", addr_sz[i], addr[i]);
	}

	for (i = 0; i < 2; i++) {
		addr[i] = r_debug_mem_proc_alloc (dbg, addr_sz[i]);
		eprintf ("alloc %d bytes at 0x%08"PFMT64x "\n", addr_sz[i], addr[i]);
	}
}

R_API void r_debug_mem_proc_destroy (RDebug *dbg)
{
	RDebugMemArena *proc_arena = dbg->proc_arena;
        if (proc_arena) {
		if (proc_arena->sz > 0 && !r_debug_is_dead (dbg)) {
                	dbg->h->map_dealloc (dbg, proc_arena->map.addr, proc_arena->map.size);
		}
		r_list_free (proc_arena->chunk_alloc_list);
		r_list_free (proc_arena->chunk_free_list);
	}
	R_FREE (dbg->proc_arena);
}
