# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
#require 'fluent/plugin/encryption/filter/version'

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-encryption-filter"
  spec.version	     = "0.0.1"
  spec.authors       = ["Akifumi Niida"]
  spec.email         = ["nidstyle3@gmail.com"]

  spec.summary       = %q{Filter plugin to encrypt.}
  spec.description   = %q{Filter plugin to encrypt.}
  spec.homepage      = "https://github.com/nidcode/fluent-plugin-encryption-filter"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "fluentd", ">= 0.12"
  spec.add_development_dependency "encryptor", "~> 3.0"
  spec.add_runtime_dependency "fluentd", ">= 0.12"
end
