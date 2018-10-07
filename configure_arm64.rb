#!/usr/bin/ruby
require 'pry-byebug'

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

system("./configure -arch #{arch} --with-lg-page=14 --host=#{triple} --target=#{triple}")
