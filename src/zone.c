#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/assert.h"
#include <malloc/malloc.h>
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <sys/utsname.h>
#include <string.h>
#include <stdlib.h>

#ifndef JEMALLOC_ZONE
#  error "This source file is for zones on Darwin (OS X)."
#endif

/******************************************************************************/
/* Function prototypes for non-inline static functions. */

static size_t	zone_size(malloc_zone_t *zone, const void *ptr);
static void	*zone_malloc(malloc_zone_t *zone, size_t size);
static void	*zone_calloc(malloc_zone_t *zone, size_t num, size_t size);
static void	*zone_valloc(malloc_zone_t *zone, size_t size);
static void	zone_free(malloc_zone_t *zone, void *ptr);
static void	*zone_realloc(malloc_zone_t *zone, void *ptr, size_t size);
static void	*zone_memalign(malloc_zone_t *zone, size_t alignment,
    size_t size);
static void	zone_free_definite_size(malloc_zone_t *zone, void *ptr,
    size_t size);
static void	zone_destroy(malloc_zone_t *zone);
static unsigned	zone_batch_malloc(struct _malloc_zone_t *zone, size_t size,
    void **results, unsigned num_requested);
static void	zone_batch_free(struct _malloc_zone_t *zone,
    void **to_be_freed, unsigned num_to_be_freed);
static size_t	zone_pressure_relief(struct _malloc_zone_t *zone, size_t goal);
static size_t	zone_good_size(malloc_zone_t *zone, size_t size);
static kern_return_t	zone_enumerator(task_t task, void *data, unsigned type_mask,
    vm_address_t zone_address, memory_reader_t reader,
    vm_range_recorder_t recorder);
static boolean_t	zone_check(malloc_zone_t *zone);
static void	zone_print(malloc_zone_t *zone, boolean_t verbose);
static void	zone_log(malloc_zone_t *zone, void *address);
static void	zone_force_lock(malloc_zone_t *zone);
static void	zone_force_unlock(malloc_zone_t *zone);
static void	zone_statistics(malloc_zone_t *zone,
    malloc_statistics_t *stats);
static boolean_t	zone_locked(malloc_zone_t *zone);
static void	zone_reinit_lock(malloc_zone_t *zone);

static malloc_zone_t *originalDefaultZone(void);

static pid_t zone_force_lock_pid = -1;
static bool useJemalloc();

static pthread_mutex_t replaceSystemMallocLock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic(bool) sMallocWasReplaced = false;

/******************************************************************************/
/*
 * Functions.
 */

static size_t
zone_size(malloc_zone_t *zone, const void *ptr) {
	/*
	 * There appear to be places within Darwin (such as setenv(3)) that
	 * cause calls to this function with pointers that *no* zone owns.  If
	 * we knew that all pointers were owned by *some* zone, we could split
	 * our zone into two parts, and use one as the default allocator and
	 * the other as the default deallocator/reallocator.  Since that will
	 * not work in practice, we must check all pointers to assure that they
	 * reside within a mapped extent before determining size.
	 */
	return ivsalloc(tsdn_fetch(), ptr);
}

static void *
zone_malloc(malloc_zone_t *zone, size_t size) {
	return je_malloc(size);
}

static void *
zone_calloc(malloc_zone_t *zone, size_t num, size_t size) {
    /*if (unlikely(...)) {
        // Hack: dlsym calls calloc before REAL(calloc) is retrieved from dlsym.
        size_t alignment = 16;
        const size_t kCallocPoolSize = 65536;
        static void *calloc_memory_for_dlsym[kCallocPoolSize];
        static size_t allocated;
        size_t size_in_words = ((num * size) + alignment) / alignment;
        void *mem = (void*)&calloc_memory_for_dlsym[allocated];
        allocated += size_in_words;
        assert(allocated <= kCallocPoolSize);
        return mem;
    }*/

	return je_calloc(num, size);
}

static void *
zone_valloc(malloc_zone_t *zone, size_t size) {
	void *ret = NULL; /* Assignment avoids useless compiler warning. */

	je_posix_memalign(&ret, PAGE, size);

	return ret;
}

static void
zone_free(malloc_zone_t *zone, void *ptr) {
	if (likely(ptr && ivsalloc(tsdn_fetch(), ptr) != 0)) {
		je_free(ptr);
		return;
	}

    originalDefaultZone()->free(originalDefaultZone(), ptr);
}

static void *
zone_realloc(malloc_zone_t *zone, void *ptr, size_t size) {
	if (likely(ivsalloc(tsdn_fetch(), ptr) != 0)) {
		return je_realloc(ptr, size);
	}

    return originalDefaultZone()->realloc(originalDefaultZone(), ptr, size);
}

static void *
zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size) {
	void *ret = NULL; /* Assignment avoids useless compiler warning. */

	je_posix_memalign(&ret, alignment, size);

	return ret;
}

static void
zone_destroy(malloc_zone_t *zone) {
    // A no-op -- we will not be destroyed!
}

static unsigned
zone_batch_malloc(struct _malloc_zone_t *zone, size_t size, void **results,
    unsigned num_requested) {
	unsigned i;

	for (i = 0; i < num_requested; i++) {
		results[i] = je_malloc(size);
		if (!results[i])
			break;
	}

	return i;
}

static void
zone_batch_free(struct _malloc_zone_t *zone, void **to_be_freed,
    unsigned num_to_be_freed) {
	unsigned i;

	for (i = 0; i < num_to_be_freed; i++) {
		zone_free(zone, to_be_freed[i]);
		to_be_freed[i] = NULL;
	}
}

static size_t
zone_pressure_relief(struct _malloc_zone_t *zone, size_t goal) {
	return 0;
}

static size_t
zone_good_size(malloc_zone_t *zone, size_t size) {
	if (size == 0) {
		size = 1;
	}
	return sz_s2u(size);
}

static boolean_t
zone_check(malloc_zone_t *zone) {
	return true;
}

static void
zone_print(malloc_zone_t *zone, boolean_t verbose) {
}

static void
zone_log(malloc_zone_t *zone, void *address) {
}

static void
zone_force_lock(malloc_zone_t *zone) {
	if (isthreaded) {
		/*
		 * See the note in zone_force_unlock, below, to see why we need
		 * this.
		 */
		assert(zone_force_lock_pid == -1);
		zone_force_lock_pid = getpid();
		jemalloc_prefork();
	}
}

static void
zone_force_unlock(malloc_zone_t *zone) {
	/*
	 * zone_force_lock and zone_force_unlock are the entry points to the
	 * forking machinery on OS X.  The tricky thing is, the child is not
	 * allowed to unlock mutexes locked in the parent, even if owned by the
	 * forking thread (and the mutex type we use in OS X will fail an assert
	 * if we try).  In the child, we can get away with reinitializing all
	 * the mutexes, which has the effect of unlocking them.  In the parent,
	 * doing this would mean we wouldn't wake any waiters blocked on the
	 * mutexes we unlock.  So, we record the pid of the current thread in
	 * zone_force_lock, and use that to detect if we're in the parent or
	 * child here, to decide which unlock logic we need.
	 */
	if (isthreaded) {
		assert(zone_force_lock_pid != -1);
		if (getpid() == zone_force_lock_pid) {
			jemalloc_postfork_parent();
		} else {
			jemalloc_postfork_child();
		}
		zone_force_lock_pid = -1;
	}
}

static void
zone_statistics(malloc_zone_t *zone, malloc_statistics_t *stats) {
	/* We make no effort to actually fill the values */
	stats->blocks_in_use = 0;
	stats->size_in_use = 0;
	stats->max_size_in_use = 0;
	stats->size_allocated = 0;
}

static boolean_t
zone_locked(malloc_zone_t *zone) {
	/* Pretend no lock is being held */
	return false;
}

static void
zone_reinit_lock(malloc_zone_t *zone) {
	/* As of OSX 10.12, this function is only used when force_unlock would
	 * be used if the zone version were < 9. So just use force_unlock. */
	zone_force_unlock(zone);
}

// Just a pair of pointers.
struct interpose_substitution {
    const void *replacement;
    const void *original;
};

#define REAL(x) x

# define WRAP(x) wrap_##x

// For a function foo() create a global pair of pointers { wrap_foo, foo } in
// the __DATA,__interpose section.
// As a result all the calls to foo() will be routed to wrap_foo() at runtime.
#define INTERPOSER(func_name) __attribute__((used)) \
const struct interpose_substitution substitution_##func_name[] \
__attribute__((section("__DATA, __interpose"))) = { \
{ (const void *)(WRAP(func_name)), \
(const void *)(func_name) } \
}

#define GET_MACRO(_0, _1, _2, _3, _4, _5, _6, NAME, ...) NAME
#define ODDS0()
#define ODDS1(a)
#define ODDS2(a, b) b
#define ODDS4(a, b, c, d) b, d
#define ODDS6(a, b, c, d, e, f) b, d, f
#define ODDS(...) GET_MACRO(_0, ##__VA_ARGS__, ODDS6, _, ODDS4, _, ODDS2, ODDS1, ODDS0)(__VA_ARGS__)

#define PAIRS0()
#define PAIRS1(a)
#define PAIRS2(a, b) a b
#define PAIRS4(a, b, c, d) a b, c d
#define PAIRS6(a, b, c, d, e, f)  a b, c d, e f
#define PAIRS(...) GET_MACRO(_0, ##__VA_ARGS__, PAIRS6, _, PAIRS4, _, PAIRS2, PAIRS1, PAIRS0)(__VA_ARGS__)

#define INTERCEPTOR_VOID(ret_type, func, ...) \
ret_type WRAP(func)(PAIRS(__VA_ARGS__)); \
INTERPOSER(func); \
ret_type WRAP(func)(PAIRS(__VA_ARGS__)) { \
if (unlikely(!useJemalloc())) { \
    REAL(func)(ODDS(__VA_ARGS__)); \
    return; \
}

#define INTERCEPTOR_RETURN(ret_type, func, ...) \
ret_type WRAP(func)(PAIRS(__VA_ARGS__)); \
INTERPOSER(func); \
ret_type WRAP(func)(PAIRS(__VA_ARGS__)) { \
if (unlikely(!useJemalloc())) { \
    return REAL(func)(ODDS(__VA_ARGS__)); \
}

// Similar code is used in Google Perftools,
// https://github.com/gperftools/gperftools.

typedef enum {
    MACOS_VERSION_UNINITIALIZED = 0,
    MACOS_VERSION_UNKNOWN,
    MACOS_VERSION_LEOPARD,
    MACOS_VERSION_SNOW_LEOPARD,
    MACOS_VERSION_LION,
    MACOS_VERSION_MOUNTAIN_LION,
    MACOS_VERSION_MAVERICKS,
    MACOS_VERSION_YOSEMITE,
    MACOS_VERSION_EL_CAPITAN,
    MACOS_VERSION_SIERRA,
    MACOS_VERSION_HIGH_SIERRA,
    MACOS_VERSION_MOJAVE,
    MACOS_VERSION_UNKNOWN_NEWER
} MacosVersion;

MacosVersion GetMacosVersion(void);

MacosVersion cached_macos_version = MACOS_VERSION_UNINITIALIZED;

MacosVersion GetMacosVersionInternal() {
    int mib[2] = { CTL_KERN, KERN_OSRELEASE };
    char version[100];
    unsigned long len = 0, maxlen = sizeof(version) / sizeof(version[0]);
    for (unsigned long i = 0; i < maxlen; i++) version[i] = '\0';
    // Get the version length.
    sysctl(mib, 2, 0, &len, 0, 0);
    sysctl(mib, 2, version, &len, 0, 0);
    // assert(sysctl(mib, 2, 0, &len, 0, 0) != -1);
    // assert(len != maxlen);
    // assert(sysctl(mib, 2, version, &len, 0, 0) != -1);
    switch (version[0]) {
        case '9': return MACOS_VERSION_LEOPARD;
        case '1': {
            switch (version[1]) {
                case '0': return MACOS_VERSION_SNOW_LEOPARD;
                case '1': return MACOS_VERSION_LION;
                case '2': return MACOS_VERSION_MOUNTAIN_LION;
                case '3': return MACOS_VERSION_MAVERICKS;
                case '4': return MACOS_VERSION_YOSEMITE;
                case '5': return MACOS_VERSION_EL_CAPITAN;
                case '6': return MACOS_VERSION_SIERRA;
                case '7': return MACOS_VERSION_HIGH_SIERRA;
                case '8': return MACOS_VERSION_MOJAVE;
                default:
                    if ('0' <= version[1] && version[1] <= '9')
                        return MACOS_VERSION_UNKNOWN_NEWER;
                    else
                        return MACOS_VERSION_UNKNOWN;
            }
        }
        default: return MACOS_VERSION_UNKNOWN;
    }
}

MacosVersion GetMacosVersion() {
    if (!cached_macos_version) {
        cached_macos_version = GetMacosVersionInternal();
    }
    return cached_macos_version;
}

malloc_zone_t internal_sanitizer_zone;
malloc_zone_t *orig_default_zone;

unsigned long RoundUpTo(unsigned long size, unsigned long boundary) {
    return (size + boundary - 1) & ~(boundary - 1);
}

static void ReplaceSystemMallocIfNecessary(void);

// Mark this a constructor so that it's run early on. Asan runs this setup in a constructor as well
static malloc_zone_t *defaultZone() {
    ReplaceSystemMallocIfNecessary();
    return &internal_sanitizer_zone;
}

static long sInternalPageSize;

static long pageSize() {
    if (!sInternalPageSize) {
        sInternalPageSize = sysconf(_SC_PAGESIZE);
    }
    return sInternalPageSize;
}

typedef enum {
    LazyBooleanUninited = 0,
    LazyBooleanFalse,
    LazyBooleanTrue
} LazyBoolean;

static LazyBoolean sInternalUseJemalloc = LazyBooleanUninited;

// Gets set by dyld
extern double dyldVersionNumber;

static double maxDyldVersionNumber = 625.110000 + 0.000001; // Give it a bit extra to be safe
static const char *maxKernelVersion = "18.0.0";

// Run this in the debugger to see what it is for your iPhone
__used void printEnvironment() {
    struct utsname u = {0};
    int res = uname(&u);
    printf("%lf, %s", dyldVersionNumber, u.release);
}

static bool environmentIsWithinMax() {
    struct utsname u = {0};
    char buffer[_SYS_NAMELEN];
    int res = uname(&u);
    if (res == -1) {
        return false;
    }
    return maxDyldVersionNumber >= dyldVersionNumber && strcmp(maxKernelVersion, u.release) >= 0;
}

// jemalloc is built with a specific page size: 16kb, i.e. 2 ** 14
// This has been the page size for iPhones for years, but in the future it's possible that Apple could change it
// I think binaries can also be forced to have a certain page size
static inline bool useJemalloc() {
    if (unlikely(sInternalUseJemalloc == LazyBooleanUninited)) {
        // fix this
        bool correctPageSize = pageSize() == (1 << 14);
        sInternalUseJemalloc = (correctPageSize && environmentIsWithinMax()) ? LazyBooleanTrue : LazyBooleanFalse;
        if (sInternalUseJemalloc == LazyBooleanFalse) {
            // Don't use printf, NSLog, etc., because they may call malloc themselves
            char warning[] = "WARNING: not using the jemalloc because either the page size is wrong or the environment is too new\n";
            write(STDOUT_FILENO, warning, sizeof(warning) - 1);
        }
    }
    return sInternalUseJemalloc == LazyBooleanTrue;
}

static malloc_zone_t *originalDefaultZone() {
    if (!orig_default_zone) {
        malloc_default_zone(); // Causes originalDefaultZone to get set up
    }
    return orig_default_zone;
}

INTERCEPTOR_RETURN(malloc_zone_t *, malloc_create_zone,
            vm_size_t, start_size, unsigned, zone_flags)
    unsigned long page_size = pageSize();
    unsigned long allocated_size = RoundUpTo(sizeof(malloc_zone_t), page_size);
    void *p = NULL;
    posix_memalign(&p, page_size, allocated_size);
    malloc_zone_t *new_zone = (malloc_zone_t *)p;
    memcpy(new_zone, defaultZone(), sizeof(malloc_zone_t));
    new_zone->zone_name = NULL;  // The name will be changed anyway.
    if (GetMacosVersion() >= MACOS_VERSION_LION) {
        // Prevent the client app from overwriting the zone contents.
        // Library functions that need to modify the zone will set PROT_WRITE on it.
        // This matches the behavior of malloc_create_zone() on OSX 10.7 and higher.
        mprotect(new_zone, allocated_size, PROT_READ);
    }
    // We're explicitly *NOT* registering the zone.
    return new_zone;
}

INTERCEPTOR_VOID(void, malloc_destroy_zone, malloc_zone_t *, zone)
    // We don't need to do anything here.  We're not registering nw zones, so we
    // don't to unregister.  Just un-mprotect and free() the zone.
    if (GetMacosVersion() >= MACOS_VERSION_LION) {
        unsigned long page_size = pageSize();
        unsigned long allocated_size = RoundUpTo(sizeof(malloc_zone_t), page_size);
        mprotect(zone, allocated_size, PROT_READ | PROT_WRITE);
    }
    if (zone->zone_name) {
        free((void *)zone->zone_name);
    }
    free(zone);
}

INTERCEPTOR_RETURN(malloc_zone_t *, malloc_default_zone, void)
    if (!orig_default_zone) {
        orig_default_zone = malloc_default_zone();
    }
    return defaultZone();
}

INTERCEPTOR_RETURN(malloc_zone_t *, malloc_default_purgeable_zone, void)
    // FIXME: ASan should support purgeable allocations.
    // https://github.com/google/sanitizers/issues/139
    return defaultZone();
}

INTERCEPTOR_VOID(void, malloc_make_purgeable, void *, ptr)
    // FIXME: ASan should support purgeable allocations. Ignoring them is fine
    // for now.
}

INTERCEPTOR_RETURN(int, malloc_make_nonpurgeable, void *, ptr)
    // FIXME: ASan should support purgeable allocations. Ignoring them is fine
    // for now.
    // Must return 0 if the contents were not purged since the last call to
    // malloc_make_purgeable().
    return 0;
}

// Functions with special handling in their zone counterparts go through those
INTERCEPTOR_VOID(void, free, void *, ptr)
    zone_free(NULL, ptr);
}

INTERCEPTOR_RETURN(void *, realloc, void *, ptr, size_t, size)
    return zone_realloc(NULL, ptr, size);
}

// Other functions call directly in and don't go through a zone fn
INTERCEPTOR_RETURN(void *, malloc, size_t, size)
    abort();
    return je_malloc(size);
}

INTERCEPTOR_RETURN(void *, calloc, size_t, nmemb, size_t, size)
    if (atomic_load_explicit(&sMallocWasReplaced, memory_order_acquire)) {
    }
    return je_calloc(nmemb, size);
}

INTERCEPTOR_RETURN(void *, valloc, size_t, size)
    return je_valloc(size);
}

INTERCEPTOR_RETURN(size_t, malloc_good_size, size_t, size)
    return zone_good_size(NULL, size);
}

INTERCEPTOR_RETURN(int, posix_memalign, void **, memptr, size_t, alignment, size_t, size)
    return je_posix_memalign(memptr, alignment, size);
}

static kern_return_t zone_enumerator(task_t task, void *p,
                            unsigned type_mask, vm_address_t zone_address,
                            memory_reader_t reader,
                            vm_range_recorder_t recorder) {
    // Should enumerate all the pointers we have.  Seems like a lot of work.
    return KERN_FAILURE;
}

static inline void ReplaceSystemMallocIfNecessary() {
    if (atomic_load_explicit(&sMallocWasReplaced, memory_order_acquire)) {
        return;
    }

    pthread_mutex_lock(&replaceSystemMallocLock);
    ({
        if (atomic_load_explicit(&sMallocWasReplaced, memory_order_relaxed)) {
            return;
        }
        atomic_store_explicit(&sMallocWasReplaced, true, memory_order_release);
        static malloc_introspection_t sanitizer_zone_introspection;
        memset(&sanitizer_zone_introspection, 0,
                        sizeof(sanitizer_zone_introspection));

        sanitizer_zone_introspection.enumerator = &zone_enumerator;
        sanitizer_zone_introspection.good_size = &zone_good_size;
        sanitizer_zone_introspection.check = &zone_check;
        sanitizer_zone_introspection.print = &zone_print;
        sanitizer_zone_introspection.log = &zone_log;
        sanitizer_zone_introspection.force_lock = &zone_force_lock;
        sanitizer_zone_introspection.force_unlock = &zone_force_unlock;
        sanitizer_zone_introspection.statistics = &zone_statistics;
        sanitizer_zone_introspection.zone_locked = &zone_locked;

        memset(&internal_sanitizer_zone, 0, sizeof(malloc_zone_t));

        // Use version 6 for OSX >= 10.6.
        internal_sanitizer_zone.version = 6;
        internal_sanitizer_zone.zone_name = "jemalloc_zone";
        internal_sanitizer_zone.size = &zone_size;
        internal_sanitizer_zone.malloc = &zone_malloc;
        internal_sanitizer_zone.calloc = &zone_calloc;
        internal_sanitizer_zone.valloc = &zone_valloc;
        internal_sanitizer_zone.free = &zone_free;
        internal_sanitizer_zone.realloc = &zone_realloc;
        internal_sanitizer_zone.destroy = &zone_destroy;
        internal_sanitizer_zone.batch_malloc = 0;
        internal_sanitizer_zone.batch_free = 0;
        internal_sanitizer_zone.free_definite_size = 0;
        internal_sanitizer_zone.memalign = &zone_memalign;
        internal_sanitizer_zone.introspect = &sanitizer_zone_introspection;
        // claimed address?

        // Register the zone.
        malloc_zone_register(&internal_sanitizer_zone);
    });
    pthread_mutex_unlock(&replaceSystemMallocLock);
}
