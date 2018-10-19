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
link_cmd = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk -arch arm64 -shared  -o #{path} src/jemalloc.pic.o src/arena.pic.o src/background_thread.pic.o src/base.pic.o src/bin.pic.o src/bitmap.pic.o src/ckh.pic.o src/ctl.pic.o src/div.pic.o src/extent.pic.o src/extent_dss.pic.o src/extent_mmap.pic.o src/hash.pic.o src/hooks.pic.o src/large.pic.o src/log.pic.o src/malloc_io.pic.o src/mutex.pic.o src/mutex_pool.pic.o src/nstime.pic.o src/pages.pic.o src/prng.pic.o src/prof.pic.o src/rtree.pic.o src/stats.pic.o src/sz.pic.o src/tcache.pic.o src/ticker.pic.o src/tsd.pic.o src/witness.pic.o src/zone.pic.o src/jemalloc_cpp.pic.o -L/opt/local/lib -Wl,-dead_strip -miphoneos-version-min=10.0 -lstdc++ -lpthread -Xlinker -install_name -Xlinker @rpath/libjemalloc.2.dylib #{interpose_o_file}"
cmd = <<-CMD
rm #{interpose_o_file} ; \
\
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -std=gnu11 -pipe -g3 -O3 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS12.0.sdk -arch arm64 -miphoneos-version-min=10.0 -fPIC -DPIC -c -D_REENTRANT -Iinclude -Iinclude -DJEMALLOC_NO_PRIVATE_NAMESPACE -o #{interpose_o_file} #{interpose_c_file} && \
\
#{link_cmd} && \
\
cp #{path} ../FastFoundation/FastFoundation
cp lib/libjemalloc.a ../FastFoundation
CMD
puts link_cmd
system(cmd)
