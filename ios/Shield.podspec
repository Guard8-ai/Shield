Pod::Spec.new do |s|
  s.name             = 'Shield'
  s.version          = '1.0.0'
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

  s.homepage         = 'https://github.com/Guard8-ai/Shield'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Guard8.ai' => 'security@guard8.ai' }
  s.source           = { :git => 'https://github.com/Guard8-ai/Shield.git', :tag => "v#{s.version}" }
  s.social_media_url = 'https://twitter.com/guard8ai'

  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.15'
  s.tvos.deployment_target = '13.0'
  s.watchos.deployment_target = '6.0'

  s.swift_versions = ['5.7', '5.8', '5.9']

  s.source_files = 'ios/Sources/Shield/**/*'

  s.frameworks = 'Foundation', 'Security'
end
