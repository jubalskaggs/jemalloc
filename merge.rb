#!/usr/bin/ruby

libs = ARGV
Dir.mktmpdir do |dir|
  `cp #{libs.shelljoin} #{dir}`
  Dir.chdir(dir)
  man 
end
