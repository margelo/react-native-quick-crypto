require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-quick-crypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["authors"]

  s.platforms    = { :ios => "12.4", :tvos => "12.0", :osx => "10.14" }
  s.source       = { :git => "https://github.com/mrousavy/react-native-quick-crypto.git", :tag => "#{s.version}" }

  s.source_files = [
    "ios/**/*.{h,m,mm}",
    "cpp/**/*.{h,c,cpp}",
  ]

  s.dependency "OpenSSL-Universal"

  install_modules_dependencies(s)
  s.dependency "React" # remove after migrating breaking changes to remove explicit dep on React
  s.dependency "ReactCommon/turbomodule/core"
end
