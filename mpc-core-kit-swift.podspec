Pod::Spec.new do |spec|
  spec.name         = "mpc-core-kit-swift"
  spec.version      = "1.0.1"
  spec.platform = :ios, "14.0"
  spec.summary      = "Core Kit SDK"
  spec.homepage     = "https://web3auth.io/"
  spec.license      = { :type => 'BSD', :file  => 'License.md' }
  spec.swift_version   = "5.9"
  spec.author       = { "Torus Labs" => "hello@tor.us" }
  spec.module_name = "tkey"
  spec.source       = { :git => "https://github.com/Web3Auth/mpc-core-kit", :tag => spec.version }
  spec.dependency 'tkey-mpc-swift', '~> 4.0.2'
  spec.dependency 'tss-client-swift', '~> 5.0.1'
  spec.dependency 'CustomAuth', '~> 11.0.1'
end
