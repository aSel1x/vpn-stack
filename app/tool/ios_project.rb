#!/usr/bin/env ruby
# frozen_string_literal: true

# Adds the packet-tunnel EXTENSION TARGET to app/ios/Runner.xcodeproj.
#
# Without it nothing compiles Extension/PacketTunnelProvider.swift or
# Extension/LibboxPlatform.swift -- 827 lines that have never been through a
# compiler. An NEPacketTunnelProvider runs in its own app-extension process, and
# a CocoaPods pod is linked into the targets the Podfile names, which is Runner
# and nothing else; singbox_tunnel.podspec:32 therefore ships Classes/ and
# Shared/ and deliberately not Extension/. The only thing that can own that
# directory is a second target in the host project, and `flutter create` writes
# one target, no entitlements, no App Group and no extension.
#
# This script is the reproducible half of the decision to COMMIT app/ios/: an
# extension target, its bundle identifiers, its entitlements and an App Group
# cannot survive regeneration, and a hand-written .pbxproj is a file nobody can
# review. Generate the stock project, run this over it, commit the result. The
# `ios_project` job in .github/workflows/app.yml is the only caller.
#
# packages/singbox_tunnel/ios/README.md is the spec and every identifier below
# is quoted from it rather than invented here. The two disagreeing is an App
# Group the extension cannot open, diagnosed at runtime from a sandbox denial.
#
# Idempotence is deliberately NOT attempted: a second run over a project that
# already carries the target refuses. Merging a new `flutter create` template
# into an edited project is the thing that cannot be reviewed, so regeneration
# means deleting app/ios/ and starting from the template.

begin
  require 'xcodeproj'
rescue LoadError
  abort(<<~MSG)
    ios_project.rb: no `xcodeproj` on this Ruby's load path.
    It is a runtime dependency of CocoaPods (cocoapods 1.17.0 requires
    xcodeproj >= 1.28.1, < 2.0), which GitHub's macOS runner images install, so
    on a runner this should never fire. Elsewhere: gem install xcodeproj
  MSG
end

require 'fileutils'

def die(message)
  abort("ios_project.rb: #{message}")
end

APP_DIR = File.expand_path('..', __dir__)
IOS_DIR = File.join(APP_DIR, 'ios')
PROJECT_PATH = File.join(IOS_DIR, 'Runner.xcodeproj')
PACKAGE_IOS = File.join(APP_DIR, 'packages', 'singbox_tunnel', 'ios')

APP_TARGET = 'Runner'
# The target name, not the directory name. The sources live in Extension/ but
# the target is SingboxTunnel because two things read that string: the bundle
# identifier below, and NSExtensionPrincipalClass, which is resolved through
# $(PRODUCT_MODULE_NAME) -- the target name with non-identifier characters
# replaced. Renaming the target renames the Swift module and breaks the
# principal-class lookup with no build error, only a provider iOS cannot
# instantiate. packages/singbox_tunnel/ios/README.md:58 names it, and
# Shared/SharedContainer.swift:60 tells the operator the same string.
EXT_TARGET = 'SingboxTunnel'
APP_BUNDLE_ID = 'io.github.asel1x.vpnStackApp'
# Nested under the app's, because iOS refuses to install an extension whose
# identifier is not a prefix-extension of its container app's, at install time,
# with no useful text (README.md:64).
EXT_BUNDLE_ID = "#{APP_BUNDLE_ID}.#{EXT_TARGET}"
APP_GROUP = "group.#{APP_BUNDLE_ID}"

# 15.0 is libbox's floor, not a preference: build_libbox passes -iosversion=15.0
# (cmd/internal/build_libbox/main.go:206), so that is the minimum of every slice
# in Libbox.xcframework. Set on the target explicitly so a drift in the
# project-level setting cannot silently drop the extension below it.
DEPLOYMENT_TARGET = '15.0'
SWIFT_VERSION = '5.0'

NE_ENTITLEMENT = 'com.apple.developer.networking.networkextension'
GROUPS_ENTITLEMENT = 'com.apple.security.application-groups'
APP_GROUP_INFO_KEY = 'SingboxTunnelAppGroup'
PROVIDER_INFO_KEY = 'SingboxTunnelProviderBundleIdentifier'

# Relative to app/ios/, which is where Runner.xcodeproj sits and what $(SRCROOT)
# expands to for every target in it.
PACKAGE_REL = '../packages/singbox_tunnel/ios'
XCFRAMEWORK_REL = "#{PACKAGE_REL}/Frameworks/Libbox.xcframework"

EXT_SOURCES = [
  'Extension/PacketTunnelProvider.swift',
  'Extension/LibboxPlatform.swift',
].freeze

# Compiled into the extension here and into the app through the pod
# (singbox_tunnel.podspec:32). Two modules that never meet; what they share is
# the on-disk format and the four stage strings, so a second spelling of either
# shows up as a status the other side cannot read.
SHARED_SOURCES = [
  'Shared/SharedContainer.swift',
  'Shared/SharedState.swift',
  'Shared/TunnelWire.swift',
].freeze

# --- preflight: every failure below names the file it wanted ----------------

unless File.directory?(PROJECT_PATH)
  die(<<~MSG)
    no #{PROJECT_PATH}.
    This edits the stock project, it does not write one. Run, in #{APP_DIR}:
      flutter create --platforms=ios --project-name vpn_stack_app --org io.github.asel1x .
  MSG
end

missing = (EXT_SOURCES + SHARED_SOURCES).reject { |rel| File.file?(File.join(PACKAGE_IOS, rel)) }
unless missing.empty?
  die(<<~MSG)
    missing under #{PACKAGE_IOS}:
      #{missing.join("\n      ")}
    The extension target is a list of these files. A target that compiles a
    subset is a build that succeeds and a tunnel that cannot start.
  MSG
end

project = Xcodeproj::Project.open(PROJECT_PATH)

runner = project.targets.find { |t| t.name == APP_TARGET }
die("Runner.xcodeproj has no target named #{APP_TARGET}; targets are: #{project.targets.map(&:name).join(', ')}") if runner.nil?

if project.targets.any? { |t| t.name == EXT_TARGET }
  die(<<~MSG)
    Runner.xcodeproj already has a target named #{EXT_TARGET}.
    This script does not merge into an edited project. To regenerate: delete
    app/ios/ entirely, re-run `flutter create --platforms=ios`, then this.
  MSG
end

# Read rather than assumed. The App Group and the extension's identifier are
# both derived from the app's, and the App Group is a real artefact registered
# against a signing team -- so an app identifier that is not the one the docs
# name means the group in the entitlements below is one nobody registered.
# `flutter create` builds it from --org and --project-name via
# createUTIIdentifier (create_base.dart:595); leave --org off and it is
# com.example forever.
app_ids = runner.build_configurations.map { |c| c.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] }.compact.uniq
unless app_ids == [APP_BUNDLE_ID]
  die(<<~MSG)
    #{APP_TARGET}'s PRODUCT_BUNDLE_IDENTIFIER is #{app_ids.inspect}, expected [#{APP_BUNDLE_ID.inspect}].
    Either `flutter create` was run without
    `--project-name vpn_stack_app --org io.github.asel1x`, or Flutter's
    identifier derivation moved. Both matter: #{APP_GROUP} and
    #{EXT_BUNDLE_ID} are built from that string, and
    packages/singbox_tunnel/ios/README.md:60 and app/docs/ios-release.md name
    it as the value to register with Apple.
  MSG
end

flutter_group = project.main_group.find_subpath('Flutter')
generated_xcconfig = flutter_group&.children&.find { |c| c.display_name == 'Generated.xcconfig' }
if generated_xcconfig.nil?
  die(<<~MSG)
    no Flutter/Generated.xcconfig file reference in Runner.xcodeproj.
    The extension's CFBundleShortVersionString and CFBundleVersion are
    $(FLUTTER_BUILD_NAME) and $(FLUTTER_BUILD_NUMBER), the same two Runner's
    Info.plist uses, and that file is where Flutter defines them. Without it
    the extension's version differs from its container app's, which App Store
    validation rejects as ITMS-90473 -- at upload, which is the last place
    anybody wants to learn it.
  MSG
end

# --- the extension's own files ---------------------------------------------

runner_dir = File.join(IOS_DIR, APP_TARGET)
runner_info_path = File.join(runner_dir, 'Info.plist')
die("no #{runner_info_path} -- `flutter create` writes it, so the iOS template layout moved") unless File.file?(runner_info_path)

ext_dir = File.join(IOS_DIR, EXT_TARGET)
FileUtils.mkdir_p(ext_dir)

entitlements = {
  NE_ENTITLEMENT => ['packet-tunnel-provider'],
  GROUPS_ENTITLEMENT => [APP_GROUP],
}

Xcodeproj::Plist.write_to_path(entitlements, File.join(ext_dir, "#{EXT_TARGET}.entitlements"))

# The app needs the SAME two keys, and that is not symmetry for its own sake:
# com.apple.developer.networking.networkextension is what lets
# NETunnelProviderManager save a configuration naming a custom provider, and
# without the App Group the app cannot read the only account the extension
# leaves of why it stopped (README.md:87).
Xcodeproj::Plist.write_to_path(entitlements, File.join(runner_dir, "#{APP_TARGET}.entitlements"))

Xcodeproj::Plist.write_to_path(
  {
    'CFBundleDevelopmentRegion' => 'en',
    'CFBundleDisplayName' => 'vpn-stack tunnel',
    'CFBundleExecutable' => '$(EXECUTABLE_NAME)',
    'CFBundleIdentifier' => '$(PRODUCT_BUNDLE_IDENTIFIER)',
    'CFBundleInfoDictionaryVersion' => '6.0',
    'CFBundleName' => '$(PRODUCT_NAME)',
    'CFBundlePackageType' => 'XPC!',
    'CFBundleShortVersionString' => '$(FLUTTER_BUILD_NAME)',
    'CFBundleVersion' => '$(FLUTTER_BUILD_NUMBER)',
    'NSExtension' => {
      'NSExtensionPointIdentifier' => 'com.apple.networkextension.packet-tunnel',
      # Resolved by the Objective-C runtime as <module>.<class>, which is why
      # PacketTunnelProvider keeps that exact name and why the target does.
      'NSExtensionPrincipalClass' => '$(PRODUCT_MODULE_NAME).PacketTunnelProvider',
    },
    # Read by Shared/SharedContainer.swift:32 in both processes. The extension
    # does not look itself up, so PROVIDER_INFO_KEY is the app's only.
    APP_GROUP_INFO_KEY => APP_GROUP,
  },
  File.join(ext_dir, 'Info.plist'),
)

runner_info = Xcodeproj::Plist.read_from_path(runner_info_path)
runner_info[APP_GROUP_INFO_KEY] = APP_GROUP
runner_info[PROVIDER_INFO_KEY] = EXT_BUNDLE_ID
Xcodeproj::Plist.write_to_path(runner_info, runner_info_path)

# --- the target -------------------------------------------------------------

ext = project.new_target(:app_extension, EXT_TARGET, :ios, DEPLOYMENT_TARGET, nil, :swift)

# new_target writes Debug and Release. A Flutter project has three, and
# `flutter run --profile` passes -configuration Profile: a target missing it
# fails the build with "does not contain configuration Profile", naming the
# extension rather than this omission.
project_configs = project.build_configuration_list.build_configurations.map(&:name)
existing = ext.build_configurations.map(&:name)
(project_configs - existing).each do |name|
  ext.add_build_configuration(name, name == 'Debug' ? :debug : :release)
end
missing_configs = project_configs - ext.build_configurations.map(&:name)
die("could not give #{EXT_TARGET} these build configurations: #{missing_configs.join(', ')}") unless missing_configs.empty?

ext.build_configurations.each do |config|
  # Flutter defines FLUTTER_BUILD_NAME and FLUTTER_BUILD_NUMBER here. Pointed at
  # Generated.xcconfig directly and NOT at Flutter/Debug.xcconfig, which
  # #include?s the Pods-Runner xcconfig -- that would hand the extension
  # OTHER_LDFLAGS for every pod in the app, including Flutter itself, which the
  # extension must not link.
  config.base_configuration_reference = generated_xcconfig

  settings = config.build_settings
  settings['PRODUCT_NAME'] = '$(TARGET_NAME)'
  settings['PRODUCT_BUNDLE_IDENTIFIER'] = EXT_BUNDLE_ID
  settings['INFOPLIST_FILE'] = "#{EXT_TARGET}/Info.plist"
  # Xcode 13+ will synthesise an Info.plist and merge it over this one unless
  # told not to, which is how a hand-written NSExtension dictionary quietly
  # stops being the one in the built bundle.
  settings['GENERATE_INFOPLIST_FILE'] = 'NO'
  settings['CODE_SIGN_ENTITLEMENTS'] = "#{EXT_TARGET}/#{EXT_TARGET}.entitlements"
  settings['CODE_SIGN_STYLE'] = 'Automatic'
  settings['IPHONEOS_DEPLOYMENT_TARGET'] = DEPLOYMENT_TARGET
  settings['SWIFT_VERSION'] = SWIFT_VERSION
  settings['TARGETED_DEVICE_FAMILY'] = '1,2'
  settings['SKIP_INSTALL'] = 'NO'
  # The app embeds the Swift runtime; a second copy inside the .appex is
  # rejected at validation.
  settings['ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES'] = 'NO'
  settings['LD_RUNPATH_SEARCH_PATHS'] = [
    '$(inherited)', '@executable_path/Frameworks', '@executable_path/../../Frameworks'
  ]

  # libbox's Apple binding references UIApplication and UIBackgroundTaskInvalid,
  # and an app extension does not link UIKit by default -- the first link of this
  # target failed on exactly those two symbols. `-lresolv` for the same reason
  # one step later: the Go resolver pulls res_9_* out of libresolv.
  settings['OTHER_LDFLAGS'] = ['$(inherited)', '-framework', 'UIKit', '-lresolv']
  settings['FRAMEWORK_SEARCH_PATHS'] = ['$(inherited)', "$(SRCROOT)/#{PACKAGE_REL}/Frameworks"]
  # The build-phase check below reads a path outside app/ios/. With script
  # sandboxing on, that read is denied and the phase fails with a sandbox error
  # instead of the message it exists to print.
  settings['ENABLE_USER_SCRIPT_SANDBOXING'] = 'NO'
end

# --- sources ----------------------------------------------------------------

# Referenced where they live. Copying them into app/ios/ would give the
# extension a second copy of Shared/ to drift from the pod's.
pkg_group = project.main_group.new_group('singbox_tunnel', PACKAGE_REL)

[[EXT_SOURCES, 'Extension'], [SHARED_SOURCES, 'Shared']].each do |paths, dir|
  group = pkg_group.new_group(dir, dir)
  paths.each do |rel|
    ref = group.new_reference(File.basename(rel))
    ext.source_build_phase.add_file_reference(ref, true)
  end
end

ext_group = project.main_group.new_group(EXT_TARGET, EXT_TARGET)
ext_group.new_reference('Info.plist')
ext_group.new_reference("#{EXT_TARGET}.entitlements")

runner_group = project.main_group.find_subpath(APP_TARGET)
die("no #{APP_TARGET} group in Runner.xcodeproj -- the iOS template layout moved") if runner_group.nil?
runner_group.new_reference("#{APP_TARGET}.entitlements")
runner.build_configurations.each do |config|
  config.build_settings['CODE_SIGN_ENTITLEMENTS'] = "#{APP_TARGET}/#{APP_TARGET}.entitlements"
end

# --- Libbox.xcframework, linked into the EXTENSION and nothing else ---------

# The app half talks to NetworkExtension and never to libbox. That is what
# keeps `flutter build ios` from needing an 800 MB Go artefact to compile the
# pod, and it is why singbox_tunnel.podspec vendors no framework.
xcframework = project.frameworks_group.new_reference(XCFRAMEWORK_REL)
xcframework.last_known_file_type = 'wrapper.xcframework'
ext.frameworks_build_phase.add_file_reference(xcframework, true)

# Not embedded. gomobile builds the slices -buildmode=c-archive
# (bind_iosapp.go:335), so every one is a static archive, and embedding a static
# framework produces a bundle the loader rejects.

check_phase = ext.new_shell_script_build_phase('Check Libbox.xcframework')
check_phase.shell_path = '/bin/sh'
check_phase.show_env_vars_in_log = '0'
# Without the framework the extension still has source to compile and the
# project still produces an .ipa, which then dies at the first connect with a
# missing symbol thrown from inside a Go callback -- the least legible possible
# place to learn that a build step was skipped. Same reason
# packages/singbox_tunnel/android/build.gradle refuses to configure without the
# .aar. An .xcframework IS its root Info.plist: that file is what lists the
# available libraries, so a directory without one is not one.
check_phase.shell_script = <<~SH
  xcframework="$SRCROOT/#{XCFRAMEWORK_REL}"
  if [ ! -f "$xcframework/Info.plist" ]; then
    echo "error: missing $xcframework -- it is built by the libbox_apple job in .github/workflows/app.yml and unpacked there by the ios job" >&2
    exit 1
  fi
SH
# Before Compile Sources, or the check reports a missing framework after the
# compile that needed it has already failed on `import Libbox`.
ext.build_phases.move(check_phase, 0)

# --- embed it in the app ----------------------------------------------------

# The dependency is what makes `flutter build ios`, which builds the Runner
# scheme, build the extension at all. Without it the .appex is never produced
# and the copy phase below silently copies nothing.
runner.add_dependency(ext)

embed = runner.new_copy_files_build_phase('Embed App Extensions')
# 13 is PlugIns. An .appex anywhere else in the bundle is not loaded and iOS
# says nothing about it.
embed.dst_subfolder_spec = '13'
embed.dst_path = ''
embed_file = embed.add_file_reference(ext.product_reference, true)
embed_file.settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }

project.save

puts "target        #{EXT_TARGET} (com.apple.product-type.app-extension)"
puts "app bundle    #{APP_BUNDLE_ID}"
puts "ext bundle    #{EXT_BUNDLE_ID}"
puts "app group     #{APP_GROUP}"
puts "deployment    iOS #{DEPLOYMENT_TARGET}, Swift #{SWIFT_VERSION}"
puts "configs       #{ext.build_configurations.map(&:name).join(', ')}"
puts "sources       #{(EXT_SOURCES + SHARED_SOURCES).join(', ')}"
puts "links         #{XCFRAMEWORK_REL} (extension only, not embedded)"
puts "wrote         ios/#{EXT_TARGET}/Info.plist, ios/#{EXT_TARGET}/#{EXT_TARGET}.entitlements,"
puts "              ios/#{APP_TARGET}/#{APP_TARGET}.entitlements, and two keys into ios/#{APP_TARGET}/Info.plist"
