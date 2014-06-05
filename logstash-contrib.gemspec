# -*- encoding: utf-8 -*-
require File.expand_path('../lib/logstash/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Jason Kendall"]
  gem.email         = ["jason.kendall@ostlabs.com"]
  gem.description   = %q{Query CIF servers for information}
  gem.summary       = %q{logstash-cif}
  gem.homepage      = "http://logstash.net/"
  gem.license       = "Apache License (2.0)"

  gem.files         = `git ls-files`.split($\)
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "logstash-cif"
  gem.require_paths = ["lib"]
  gem.version       = LOGSTASH_VERSION

  gem.add_runtime_dependency "net-http-persistent" 
end
