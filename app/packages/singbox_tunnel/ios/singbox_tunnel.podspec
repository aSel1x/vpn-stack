#
# The pod is the APP half only.
#
# `Classes/` is the FlutterPlugin that runs in the app process and `Shared/` is
# what both processes need; `Extension/` is deliberately NOT here. A CocoaPods
# pod is linked into the targets the Podfile names, and the Podfile Flutter
# generates names Runner and nothing else -- so putting the
# NEPacketTunnelProvider subclass in source_files would compile it into the app
# and leave the extension, which is the only target that can run it, without it.
# The extension target in Runner.xcodeproj references Extension/ and Shared/
# directly. packages/singbox_tunnel/ios/README.md is the spec for that project.
#
# Nothing here vendors Libbox.xcframework either, for the same reason: only the
# extension links it. That is also why declaring `ios:` in pubspec.yaml does not
# make `flutter build ios` need an 800 MB Go artifact -- this pod compiles
# against NetworkExtension and Flutter alone, which is what makes CI's macOS
# runner a cheap check on the Swift in Classes/ and Shared/.
#
Pod::Spec.new do |s|
  s.name             = 'singbox_tunnel'
  s.version          = '0.1.0'
  s.summary          = 'sing-box on iOS behind the vpn-stack client tunnel interface.'
  s.description      = <<-DESC
The app-process half of the iOS tunnel: a FlutterPlugin that installs and drives
a NETunnelProviderManager. The tunnel itself is an app extension target in the
host project, not a pod.
                       DESC
  s.homepage         = 'https://github.com/aSel1x/vpn-stack'
  s.license          = { :type => 'AGPL-3.0' }
  s.author           = { 'vpn-stack' => 'https://github.com/aSel1x/vpn-stack' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*.swift', 'Shared/**/*.swift'
  s.dependency 'Flutter'

  # 15.0, and it is not the CocoaPods default talking. `build_libbox -target
  # apple` passes -iosversion=15.0 (cmd/internal/build_libbox/main.go:206), so
  # that is the floor of every slice in Libbox.xcframework, and Flutter 3.47.4's
  # own iOS template already writes IPHONEOS_DEPLOYMENT_TARGET = 15.0 -- so the
  # two agree today and this line is what makes a drift in either one visible
  # here rather than as a link error in the extension.
  s.platform = :ios, '15.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
