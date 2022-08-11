# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in ccipher_box.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

#gem 'teLogger', git: 'teLogger', branch: "main"

#gem 'ccrypto', git: 'ccrypto', branch: 'main'

require 'toolrack'
if TR::RTUtils.on_java?
  #gem 'ccrypto-java', git: 'ccrypto-java', branch: 'main'
  gem 'ccrypto-java'
else
  #gem 'ccrypto-ruby', git: 'ccrypto-ruby', branch: 'main'
  gem 'ccrypto-ruby'
end

#gem 'ccipher_factory', git: 'ccipher_factory', branch: 'master'

#gem 'binenc', git: 'binenc', branch: 'master'
if TR::RTUtils.on_java?
  #gem 'binenc-java', git: 'binenc-java', branch: 'master'
  gem 'binenc-java'
else
  #gem 'binenc-ruby', git: 'binenc-ruby', branch: 'master'
  gem 'binenc-ruby'
end

