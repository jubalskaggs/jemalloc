#!/usr/bin/ruby
require 'pry-byebug'

Dir.chdir(__dir__)

dev = `xcode-select --print-path 2>/dev/null`.chomp

debug = ARGV.include?("--debug")

archs = debug ? ["arm64"] : ["x86_64", "arm64"]

min_version = "10.0"
triple = "aarch64-apple-ios"
$static_lib_path = "lib/libjemalloc_pic.a"
$dylib_path = "lib/libjemalloc.2.dylib"

def run(cmd)
  puts cmd
  system(cmd)
end

def tmp_dylib_path(arch)
  "/tmp/#{arch}-#{File.basename($dylib_path)}"
end

def tmp_static_lib_path(arch)
  "/tmp/#{arch}-#{File.basename($static_lib_path)}"
end

puts "Using #{min_version} as the minimum iOS version, feel free to change min_version in the code to something else\n\n"

ENV.delete_if { true }
archs.each do |arch|
  sdk = {"arm64" => "iphoneos", "x86_64" => "iphonesimulator"}[arch]
  sdk_root = `xcodebuild -version -sdk #{sdk} 2>/dev/null`.split("\n").detect do |line|
    line.start_with?("Path: ")
  end.match(/^Path: (.*)/)[1]
  ENV["CC"]= "#{dev}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
  ENV["CXX"] = ENV["CC"] + "++"

  ENV["EXTRA_CFLAGS"] = ENV["CXXFLAGS"] = "-isysroot #{sdk_root} -arch #{arch} -miphoneos-version-min=#{min_version}"
  ENV["LDFLAGS"] = "-isysroot #{sdk_root} -arch #{arch} -Wl,-install_name,@rpath/libjemalloc.2.dylib -Wl,-dead_strip -miphoneos-version-min=#{min_version}"

  cmd = debug ? "make -j 4" : "make clean && ./configure --disable-cxx --enable-zone-allocator --with-lg-page=14 --host=#{triple} --target=#{triple} && make -j 4"
  success = run(cmd)
  raise "Failure" unless success
  `cp #{$static_lib_path} #{tmp_static_lib_path(arch)}`
  `cp #{$dylib_path} #{tmp_dylib_path(arch)}`
end

dylibs = archs.map do |arch|
  tmp_dylib_path(arch)
end

static_libs = archs.map do |arch|
  tmp_static_lib_path(arch)
end

`rm lib/*`
`xcrun libtool #{static_libs.shelljoin} -o #{$static_lib_path}`
`xcrun lipo -create #{dylibs.shelljoin} -output #{$dylib_path}`

puts "------------------------------------------------\n" * 3
puts "Successfully wrote out a static library to #{$static_lib_path} and a dynamic library to #{$dylib_path}"
