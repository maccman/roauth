require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "roauth"
    gemspec.summary = "Simple Ruby OAuth library"
    gemspec.email = "info@eribium.org"
    gemspec.homepage = "http://github.com/maccman/roauth"
    gemspec.description = "Simple Ruby OAuth library"
    gemspec.authors = ["Alex MacCaw"]
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install jeweler"
end


require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

task :test => :check_dependencies
task :default => :test