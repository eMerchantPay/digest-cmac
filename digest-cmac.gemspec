lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'digest/cmac/version'

Gem::Specification.new do |spec|
  spec.name          = 'digest-cmac'
  spec.version       = Digest::CMAC::VERSION
  spec.authors       = ['eMerchantPay']
  spec.email         = ['rnd@emerchantpay.com']

  spec.summary       = 'CMAC algorithm'
  spec.description   = 'CMAC algorithm'
  spec.homepage      = 'https://emp-sof-github01.emp.internal.com/eMerchantPay/digest-cmac'

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.15'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.7'
end
