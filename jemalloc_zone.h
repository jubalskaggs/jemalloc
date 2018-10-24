//Copyright (c) 2018 Michael Eisel. All rights reserved.

size_t    je_zone_size(malloc_zone_t *zone, const void *ptr);
void    *je_zone_malloc(malloc_zone_t *zone, size_t size);
void    *je_zone_calloc(malloc_zone_t *zone, size_t num, size_t size);
void    *je_zone_valloc(malloc_zone_t *zone, size_t size);
void    je_zone_free(malloc_zone_t *zone, void *ptr);
void    *je_zone_realloc(malloc_zone_t *zone, void *ptr, size_t size);
void    *je_zone_memalign(malloc_zone_t *zone, size_t alignment,
                       size_t size);
void    je_zone_free_definite_size(malloc_zone_t *zone, void *ptr,
                                size_t size);
void    je_zone_destroy(malloc_zone_t *zone);
unsigned    je_zone_batch_malloc(struct _malloc_zone_t *zone, size_t size,
                              void **results, unsigned num_requested);
void    je_zone_batch_free(struct _malloc_zone_t *zone,
                        void **to_be_freed, unsigned num_to_be_freed);
size_t    je_zone_pressure_relief(struct _malloc_zone_t *zone, size_t goal);
size_t    je_zone_good_size(malloc_zone_t *zone, size_t size);
kern_return_t    je_zone_enumerator(task_t task, void *data, unsigned type_mask,
                                 vm_address_t zone_address, memory_reader_t reader,
                                 vm_range_recorder_t recorder);
boolean_t    je_zone_check(malloc_zone_t *zone);
void    je_zone_print(malloc_zone_t *zone, boolean_t verbose);
void    je_zone_log(malloc_zone_t *zone, void *address);
void    je_zone_force_lock(malloc_zone_t *zone);
void    je_zone_force_unlock(malloc_zone_t *zone);
void    je_zone_statistics(malloc_zone_t *zone,
                        malloc_statistics_t *stats);
boolean_t    je_zone_locked(malloc_zone_t *zone);
void    je_zone_reinit_lock(malloc_zone_t *zone);
