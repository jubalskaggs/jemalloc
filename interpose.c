#include "jemalloc/internal/private_namespace.h"
#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/assert.h"

#import "jemalloc/jemalloc.h"

#define DYLD_INTERPOSE(_replacment,_replacee) \
   __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

void *mje_malloc(size_t size) __result_use_check __alloc_size(1) {
    return je_malloc(size);
}

void *mje_calloc(size_t count, size_t size) __result_use_check __alloc_size(1,2) {
    return je_calloc(count, size);
}

void mje_free(void *ptr) {
    if (ivsalloc(tsdn_fetch(), ptr) != 0) {
		je_free(ptr);
		return;
	}

	free(ptr);
}

void *mje_realloc(void *ptr, size_t size) __result_use_check __alloc_size(2) {
    if (ivsalloc(tsdn_fetch(), ptr) != 0) {
		return je_realloc(ptr, size);
	}

	return realloc(ptr, size);
}

void *mje_valloc(size_t size) __alloc_size(1) {
    void *ret = NULL; /* Assignment avoids useless compiler warning. */

	je_posix_memalign(&ret, PAGE, size);

	return ret;

}

int mje_posix_memalign(void **memptr, size_t alignment, size_t size) {
	return je_posix_memalign(memptr, alignment, size);
}

DYLD_INTERPOSE(mje_malloc, malloc);
DYLD_INTERPOSE(mje_realloc, realloc);
DYLD_INTERPOSE(mje_calloc, calloc);
DYLD_INTERPOSE(mje_valloc, valloc);
DYLD_INTERPOSE(mje_free, free);
DYLD_INTERPOSE(mje_posix_memalign, posix_memalign);

__used __attribute__((constructor)) void asf() {
    printf("go\n\n\n");
}

// malloc_create_zone, malloc_destroy_zone, malloc_default_zone, malloc_default_purgeable_zone, malloc_make_purgeable, malloc_make_nonpurgeable, malloc_set_zone_name, posix_memalign
//DYLD_INTERPOSE(je_batch_malloc, free);
//DYLD_INTERPOSE(je_batch_free, free);
// DYLD_INTERPOSE(je_realloc, realloc);
