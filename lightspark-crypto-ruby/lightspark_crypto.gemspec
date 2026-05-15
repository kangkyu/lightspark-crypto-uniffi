# frozen_string_literal: true

require_relative "lib/lightspark_crypto/version"

Gem::Specification.new do |spec|
  spec.name    = "lightspark_crypto"
  spec.version = LightsparkCrypto::VERSION
  spec.authors = ["Lightspark Group, Inc."]
  spec.email   = ["info@lightspark.com"]

  spec.summary     = "Ruby bindings for the Lightspark crypto library"
  spec.description = "A shared library for crypto operations in the Lightspark Wallet SDK. " \
                     "Provides key derivation, signing, ECIES encryption, invoice signing, " \
                     "and funds recovery operations over Bitcoin/Lightning."
  spec.homepage    = "https://github.com/lightsparkdev/lightspark-crypto-uniffi"
  spec.license     = "Apache-2.0"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata = {
    "homepage_uri"    => spec.homepage,
    "source_code_uri" => "#{spec.homepage}/tree/main/lightspark-crypto-ruby",
    "changelog_uri"   => "#{spec.homepage}/blob/main/RELEASE.md"
  }

  spec.extensions = ["ext/lightspark_crypto/extconf.rb"]

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{rb,rs,toml}",
    "LICENSE",
    "README.md"
  ]

  spec.require_paths = ["lib"]

  spec.add_dependency "rb_sys", "~> 0.9"

  spec.add_development_dependency "base64",        "~> 0.2"
  spec.add_development_dependency "rake",          "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rspec",         "~> 3.0"
end
