# Jemalloc for iOS

Jemalloc is a popular allocator that is supported by Facebook. In this fork of it, we have (sketchy) support for iOS.

## Building

Run `./build.rb` and it will output a dynamic library to `lib/libjemalloc.2.dylib` and a static library to `lib/libjemalloc_pic.a`. By default it does not include bitcode, but you can add the `--bitcode` flag to `./build.rb` to support it. If you don't want it to automatically replace malloc for you, e.g. because you will be using `CFAllocatorSetDefault` instead, simply add the `--no-replace` flag.

## Usage

If you only want to call this library explicitly, e.g. calls to `je_malloc` and `je_free`, you can use the static library. However, **if you want to replace the system allocator, you need to use the dynamic library**. This is because dyld interposing only works with dylibs.

## Stability

The system allocator on iOS is not easy to replace, and requires many hacks. Stability is not guaranteed, although it will improve over time with contributions to the repo. One thing you can do to mitigate this is to only enable jemalloc on versions of iOS that you've already tested. You could leave jemalloc on all the time for internal users, and only enable it for external users on operating systems that have gotten some testing internally. So if some new version of iOS comes along that would break it, your app would be safe because it'd then use the system allocator.

This library has a mechanism specifically for that. In `src/zone.c`, the `maxDyldVersionNumber` and `maxKernelVersion` constants represent the maximum those two things, the version of dyld and version of the kernel respectively, can be. If the version on the phone is any higher, it will not work. You can get these two numbers for an iPhone by running your app on it and uncommenting and calling the `printEnvironment` function in `src/zone.c` (you can call it with `je_printEnvironment();`).

## Testing

You can add the `testing.{c,h}` files from this repo to your project and call `JERunTests()` to do unit testing.

## Tuning and other configuration

The main jemalloc repo offers additional info about [building](https://github.com/jemalloc/jemalloc/blob/dev/INSTALL.md) and [tuning](https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md).
