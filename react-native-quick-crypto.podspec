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

  # All source files that should be publicly visible
  # Note how this does not include headers, since those can nameclash.
  s.source_files = [
    "ios/**/*.{h,m,mm}",
    "cpp/**/*.{h,c,cpp}",
    "ios/QuickCryptoModule.h",
    "node_modules/react-native-quick-base64/cpp/base64.h"
  ]
  # Any private headers that are not globally unique should be mentioned here.
  # Otherwise there will be a nameclash, since CocoaPods flattens out any header directories
  # See https://github.com/firebase/firebase-ios-sdk/issues/4035 for more details.
  # s.preserve_paths = [
  #   'ios/**/*.h',
  #   'cpp/**/*.h'
  # ]

  s.pod_target_xcconfig    = {
    "USE_HEADERMAP" => "YES",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/ReactCommon\" \"$(PODS_TARGET_SRCROOT)\"  \"$(PODS_ROOT)/boost\" \"$(PODS_ROOT)/boost-for-react-native\" \"$(PODS_ROOT)/DoubleConversion\" \"$(PODS_ROOT)/Headers/Private/React-Core\" "
  }
  s.xcconfig               = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/boost\" \"$(PODS_ROOT)/boost-for-react-native\" \"$(PODS_ROOT)/glog\"  \"${PODS_ROOT}/Headers/Public/React-hermes\" \"${PODS_ROOT}/Headers/Public/hermes-engine\""
  }

  s.dependency "OpenSSL-Universal", "~> 1.1.2200"
  s.dependency "React-Core"
  s.dependency "React"
  s.dependency "React-callinvoker"
  s.dependency "ReactCommon"
end
