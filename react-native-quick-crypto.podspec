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

  #https://github.com/duckduckgo/OpenSSL-XCFramework
  s.vendored_frameworks = 'ios/OpenSSL.xcframework'

  # Use install_modules_dependencies helper to install the dependencies if React Native version >=0.71.0.
  # See https://github.com/facebook/react-native/blob/febf6b7f33fdb4904669f99d795eba4c0f95d7bf/scripts/cocoapods/new_architecture.rb#L79
  if defined?(install_modules_dependencies()) != nil
    install_modules_dependencies(s)
    s.dependency "React" # remove after migrating breaking changes to remove explicit dep on React
  else
    # Old React Native versions
    s.pod_target_xcconfig    = {
      "USE_HEADERMAP" => "YES",
      "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
      "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/ReactCommon\" \"$(PODS_TARGET_SRCROOT)\"  \"$(PODS_ROOT)/boost\" \"$(PODS_ROOT)/boost-for-react-native\" \"$(PODS_ROOT)/DoubleConversion\" \"$(PODS_ROOT)/Headers/Private/React-Core\" "
    }
    s.dependency "React"
    s.dependency "React-Core"
    s.dependency "React-callinvoker"
    s.dependency "ReactCommon"
  end
end
