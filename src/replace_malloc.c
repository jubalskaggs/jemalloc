// Note that much of this code is taken from https://github.com/llvm-mirror/compiler-rt, see COPYING for the license

#include <AvailabilityMacros.h>
#include <CoreFoundation/CFBase.h>
#include <dlfcn.h>
#include <malloc/malloc.h>
#include <sys/mman.h>

#include <unistd.h>
#import <stdio.h>
#import <dispatch/dispatch.h>
#import <sys/sysctl.h>
#import "jemalloc.h"
#import "jemalloc_zone.h"
#import <assert.h>

