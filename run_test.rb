

require 'toolrack'
require 'fileutils'

gemfile = File.join(File.dirname(__FILE__),"Gemfile.lock")
if TR::RTUtils.on_jruby?
  rtGemFile = File.join(File.dirname(__FILE__),"Gemfile.lock-java")
else
  rtGemFile = File.join(File.dirname(__FILE__),"Gemfile.lock-ruby")
end

if File.exist?(rtGemFile)
  
  FileUtils.rm_f gemfile if File.exist?(gemfile)

  FileUtils.cp rtGemFile, gemfile

  cmd = "bundle exec rspec #{ARGV.join(" ")}"

  system(cmd)

else

  STDERR.puts "No java or ruby Gemfile.lock found. Please create the environment first."

end
