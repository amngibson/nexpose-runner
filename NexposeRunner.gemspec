# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'NexposeRunner/version'

Gem::Specification.new do |spec|
  spec.name          = 'NexposeRunner'
  spec.version       = NexposeRunner::VERSION
  spec.authors       = ['Nathan Gibson']
  spec.email         = ['amngibson@gmail.com']
  spec.summary       = 'This is a gem that provides the ability to create a new site, add an IP to the site, and perform a scan against the site using a defined/passed scan template, and finally produce a reports for vulnerabilities, installed software, and policy compliance.'
  spec.description   = ''
  spec.homepage      = ''
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = %w(scan)
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'nexpose', '0.8.3'

  spec.add_development_dependency 'bundler', '~> 1.6'
  spec.add_development_dependency 'rake', '< 11.0'
  spec.add_development_dependency 'rspec', '3.0.0'
end
