Pod::Spec.new do |s|
  s.name             = 'Shield'
  s.version          = '2.2.0'
  s.summary          = 'EXPTIME-secure symmetric encryption for iOS/macOS'
  s.description      = <<-DESC
    Shield provides symmetric cryptography with proven exponential-time security.
    Breaking requires 2^256 operations - no shortcut exists.

    Features:
    - Password-based encryption (PBKDF2-SHA256)
    - SHA256-based stream cipher (AES-256-CTR equivalent)
    - HMAC-SHA256 authentication
    - Secure Keychain integration
    - Cross-platform compatible (encrypt on iOS, decrypt on Android/Web/Server)
  DESC

  s.homepage         = 'https://github.com/Dikestra-ai/Shield'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Eliran Sabag' => 'admin@gibraltarcloud.dev' }
  s.source           = { :git => 'https://github.com/Dikestra-ai/Shield.git', :tag => "v#{s.version}" }
  s.social_media_url = 'https://twitter.com/dikestraai'

  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '11.0'
  s.tvos.deployment_target = '14.0'
  s.watchos.deployment_target = '7.0'

  s.swift_versions = ['5.7', '5.8', '5.9']

  s.source_files = 'ios/Sources/Shield/**/*'
  s.exclude_files = 'ios/Sources/Shield/PqHybrid.swift'

  s.frameworks = 'Foundation', 'Security', 'CryptoKit'
end
