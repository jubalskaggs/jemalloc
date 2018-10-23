#!/usr/bin/ruby
require 'pry-byebug'

Dir.chdir(__dir__)

dev = `xcode-select --print-path`.chomp
sdk_root = `xcodebuild -version -sdk iphoneos`.split("\n").detect do |line|
  line.start_with?("Path: ")
end.match(/^Path: (.*)/)[1]

arch = "arm64"
min_version = "10.0"
triple = "aarch64-apple-ios"

ENV["CC"]= "#{dev}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
ENV["CXX"] = ENV["CC"] + "++"

ENV["EXTRA_CFLAGS"] = ENV["CXXFLAGS"] = "-isysroot #{sdk_root} -arch #{arch} -miphoneos-version-min=#{min_version}"
ENV["LDFLAGS"] += "-Wl,install_name,@rpath/libjemalloc.2.dylib -Wl,-dead_strip -miphoneos-version-min=#{min_version}"# -isysroot #{sdk_root} " # -L#{sdk_root}/usr/lib/

# NOTE: don't forget to remove the other install_name command in the linker invocation, because it comes after ours and thus takes precedence

if ARGV.include?("--compile")
  system("./configure --enable-zone-allocator --with-lg-page=14 --host=#{triple} --target=#{triple}")
  system("make")
end
path = "lib/libjemalloc.2.dylib"
`rm #{path}`
interpose_c_file = "interpose.c"
interpose_o_file = "interpose.o"
malloc_replacer_files = IO.read("/Users/michaeleisel/projects/mallocReplacer/Build/Intermediates/mallocReplacer.build/Release-iphoneos/mallocReplacer.build/Objects-normal/arm64/mallocReplacer.LinkFileList").split("\n").shelljoin
puts malloc_replacer_files
static_lib_cmd = "ar crus lib/libjemalloc.a src/jemalloc.o src/arena.o src/background_thread.o src/base.o src/bin.o src/bitmap.o src/ckh.o src/ctl.o src/div.o src/extent.o src/extent_dss.o src/extent_mmap.o src/hash.o src/hooks.o src/large.o src/log.o src/malloc_io.o src/mutex.o src/mutex_pool.o src/nstime.o src/pages.o src/prng.o src/prof.o src/rtree.o src/stats.o src/sz.o src/tcache.o src/ticker.o src/tsd.o src/witness.o src/zone.o src/jemalloc_cpp.o
ar crus lib/libjemalloc_pic.a src/jemalloc.pic.o src/arena.pic.o src/background_thread.pic.o src/base.pic.o src/bin.pic.o src/bitmap.pic.o src/ckh.pic.o src/ctl.pic.o src/div.pic.o src/extent.pic.o src/extent_dss.pic.o src/extent_mmap.pic.o src/hash.pic.o src/hooks.pic.o src/large.pic.o src/log.pic.o src/malloc_io.pic.o src/mutex.pic.o src/mutex_pool.pic.o src/nstime.pic.o src/pages.pic.o src/prng.pic.o src/prof.pic.o src/rtree.pic.o src/stats.pic.o src/sz.pic.o src/tcache.pic.o src/ticker.pic.o src/tsd.pic.o src/witness.pic.o src/zone.pic.o src/jemalloc_cpp.pic.o #{interpose_o_file} #{malloc_replacer_files}"
# lto?
link_cmd = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk -arch arm64 -shared  -o #{path} src/jemalloc.pic.o src/arena.pic.o src/background_thread.pic.o src/base.pic.o src/bin.pic.o src/bitmap.pic.o src/ckh.pic.o src/ctl.pic.o src/div.pic.o src/extent.pic.o src/extent_dss.pic.o src/extent_mmap.pic.o src/hash.pic.o src/hooks.pic.o src/large.pic.o src/log.pic.o src/malloc_io.pic.o src/mutex.pic.o src/mutex_pool.pic.o src/nstime.pic.o src/pages.pic.o src/prng.pic.o src/prof.pic.o src/rtree.pic.o src/stats.pic.o src/sz.pic.o src/tcache.pic.o src/ticker.pic.o src/tsd.pic.o src/witness.pic.o src/zone.pic.o src/jemalloc_cpp.pic.o -L/opt/local/lib -Wl,-dead_strip -miphoneos-version-min=10.0 -lstdc++ -lpthread -Xlinker -install_name -Xlinker @rpath/libjemalloc.2.dylib #{interpose_o_file} #{malloc_replacer_files}"
zone_build_cmd = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -std=gnu11 -Wall -Wshorten-64-to-32 -Wsign-compare -Wundef -Wno-format-zero-length -pipe -g3 -O3 -funroll-loops -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.0.sdk -arch arm64 -miphoneos-version-min=10.0 -fPIC -DPIC -c -D_REENTRANT -Iinclude -Iinclude -o src/zone.pic.o src/zone.c && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -std=gnu11 -Wall -Wshorten-64-to-32 -Wsign-compare -Wundef -Wno-format-zero-length -pipe -g3 -O3 -funroll-loops -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.0.sdk -arch arm64 -miphoneos-version-min=10.0 -c -D_REENTRANT -Iinclude -Iinclude -o src/zone.o src/zone.c"
xcodebuild_cmd = "cd ~/projects/mallocReplacer && xcodebuild -scheme mallocReplacer -target mallocReplacer"
raise "fail" unless system(xcodebuild_cmd)
cmd = <<-CMD
rm #{interpose_o_file} ; \
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -std=gnu11 -pipe -g3 -O3 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.0.sdk -arch arm64 -miphoneos-version-min=10.0 -fPIC -DPIC -c -D_REENTRANT -Iinclude -Iinclude -DJEMALLOC_NO_PRIVATE_NAMESPACE -o #{interpose_o_file} #{interpose_c_file} && \
#{zone_build_cmd} && \
#{link_cmd} && \
#{static_lib_cmd} && \
cp #{path} ../FastFoundation/FastFoundation && \
cp lib/libjemalloc_pic.a ../FastFoundation
CMD
puts cmd
success = system(cmd)
puts success ? "SUCCESS" : "FAIL"
