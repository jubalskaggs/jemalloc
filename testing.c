#import <malloc/malloc.h>
#import <stdlib.h>
#import <string.h>
#import <assert.h>
#import <stdbool.h>
#import <stdio.h>

static malloc_zone_t otherZone;

extern malloc_zone_t *je_orig_default_zone;

void JERunTests() __attribute__ ((optnone))
{
    // none of this stuff should cause a crash or do anything weird
    malloc_zone_t *zone = malloc_default_zone();
    char *ptr = NULL;

    free(NULL);

    malloc_zone_t newZone = {0};
    memcpy(&newZone, zone, sizeof(malloc_zone_t));
    malloc_zone_register(&newZone);
    ptr = malloc_zone_malloc(&newZone, 20);
    malloc_zone_free(&newZone, ptr);
    malloc_zone_unregister(&newZone);



    memcpy(&otherZone, zone, sizeof(malloc_zone_t));
    malloc_zone_register(&otherZone);
    ptr = malloc_zone_malloc(&otherZone, 20);
    malloc_zone_free(&otherZone, ptr);
    // leave otherZone registered

    assert(0 == strcmp(malloc_get_zone_name(zone), "jemalloc_zone"));
    const char *newName = strdup("asdf");
    malloc_set_zone_name(zone, newName);
    assert(0 == strcmp(malloc_get_zone_name(zone), "asdf"));

    ptr = malloc_zone_memalign(zone, 128, 1);
    assert(malloc_size(ptr) >= 128);
    free(ptr);

    malloc_statistics_t stats;
    bzero(&stats, sizeof(stats)); // Use bzero to make sure alignment padding is zero-filled as well
    malloc_zone_statistics(zone, &stats);
    malloc_statistics_t zeroStats;
    bzero(&zeroStats, sizeof(zeroStats));
    assert(0 == memcmp(&stats, &zeroStats, sizeof(stats)));

    for (long long i = 0; i < 1000; i++) {
        ptr = malloc(i);
        if (i > 0) {
            ptr[0] = 'a';
        }
        free(ptr);
    }
    for (long long i = 1e5; i < 1e6; i += 1e5) {
        ptr = malloc(i);
        bzero(ptr, i);
        free(ptr);
    }
    ptr = malloc(1e8);
    bzero(ptr, 1e8);
    free(ptr);

    ptr = malloc(20);
    malloc_zone_print_ptr_info(ptr);
    free(ptr);

    ptr = malloc(20);
    malloc_zone_log(zone, ptr);
    free(ptr);

    malloc_zone_print(zone, true);
    malloc_zone_print(NULL, true);

    ptr = malloc(20);
    assert(malloc_size(ptr) == 32);
    free(ptr);

    assert(malloc_good_size(20) == 32);

    ptr = malloc(20);
    assert(zone == malloc_zone_from_ptr(ptr));
    free(ptr);

    ptr = malloc_zone_malloc(je_orig_default_zone, 20);
    ptr = realloc(ptr, 40);
    ptr[0] = 'a';
    free(ptr);

    ptr = calloc(20, 20);
    ptr[0] = 'a';
    free(ptr);

    ptr = valloc(20);
    ptr[0] = 'a';
    free(ptr);

    ptr = malloc(20);
    malloc_zone_discharge(zone, ptr);
    free(ptr);

    ptr = malloc(20);
    malloc_zone_discharge(NULL, ptr);
    free(ptr);

    assert(malloc_zone_enable_discharge_checking(zone) == false);
    malloc_zone_disable_discharge_checking(zone);

    malloc_printf("asdf");

    zone->introspect->force_lock(zone);
    zone->introspect->force_unlock(zone);

    ptr = malloc(20);
    malloc_make_purgeable(ptr);
    assert(malloc_make_nonpurgeable(ptr) == 0);

    assert(malloc_zone_pressure_relief(zone, 20) == 0);

    assert(malloc_default_purgeable_zone() == malloc_default_zone());

    ptr = malloc(20);
    ptr[0] = 'a';
    zone->free_definite_size(zone, ptr, 20);

    ptr = malloc(20);
    assert(zone->size(zone, ptr) == 32);
    free(ptr);

    ptr = realloc(NULL, 20);

    posix_memalign((void **)(&ptr), 256, 20);
    assert(malloc_size(ptr) == 256);
    free(ptr);

    void *results[30];
    malloc_zone_batch_malloc(zone, 20, results, 30);
    malloc_zone_batch_free(zone, results, 30);

    assert(je_orig_default_zone != NULL && je_orig_default_zone != zone);
    assert(malloc_zone_check(zone));

    printf("\n\n\n--------------------------\nTests have completed. There may be lots of output to the console from running test functions, but as long as none of it is specifically an error message, then the tests have passed\n--------------------------\n");
}
