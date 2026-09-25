#!/usr/bin/env ruby
# frozen_string_literal: true

# Adds the packet-tunnel EXTENSION TARGET to app/ios/Runner.xcodeproj, and with
# --check verifies that the committed project is still the one it would write.
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
# review. Generate the stock project, run this over it, commit the result.
#
# --- what --check is for ----------------------------------------------------
#
# A committed generated artefact drifts from its generator silently. Nothing in
# this tree tied the two together, so a hand edit to app/ios/ -- or a change here
# that nobody re-ran -- would be discovered on somebody's Mac 45 minutes into a
# build, or not at all: every setting below is read by Xcode or by iOS at a point
# where the only symptom is a build that succeeds and a tunnel that does not
# start. --check opens the committed project and asserts every value this script
# writes, reporting all differences rather than the first, and exits 1 on any.
#
# It does NOT re-run `flutter create` and diff two project files, which is the
# obvious shape and the wrong one. Xcodeproj mints a fresh random 24-hex UUID for
# every object it creates, so two generated projects differ textually in every
# object even when they are identical in meaning; and a regenerated template
# would be the template of whatever Flutter is installed at that moment, so a
# Flutter release would fail this check for a reason that is not drift. The
# settings are the contract, so the settings are what is compared -- against the
# same tables the generate path writes from, which is what keeps the two halves
# from disagreeing.
#
# Idempotence is deliberately NOT attempted: a second generate over a project
# that already carries the target refuses. Merging a new `flutter create`
# template into an edited project is the thing that cannot be reviewed, so
# regeneration means deleting app/ios/ and starting from the template.
#
# The `ios_project` job in .github/workflows/app.yml is the generate caller;
# --check can run in any job on a macOS runner, which is the only place the
# xcodeproj gem exists. `ruby -c` in the cheap `check` job is the only thing
# elsewhere that judges this file at all, which is why tool/check_extension.sh
# asserts the identifiers with plain text tools instead.

require 'fileutils'

def die(message)
  abort("ios_project.rb: #{message}")
end

MODE =
  case ARGV
  when [] then :generate
  when ['--check'] then :check
  else
    die(<<~MSG)
      usage: ios_project.rb [--check]
        (no argument)  add the extension target to app/ios/Runner.xcodeproj
        --check        assert the committed project is the one this would write
    MSG
  end

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

APP_DIR = File.expand_path('..', __dir__)
IOS_DIR = File.join(APP_DIR, 'ios')
PROJECT_PATH = File.join(IOS_DIR, 'Runner.xcodeproj')

# --- the identifiers, from the one file tool/check_extension.sh also reads ---

# Every identifier here is compared at runtime by iOS and by nothing at build
# time, so the checker that asserts them has to run without Xcode and without
# this gem -- on ubuntu, in the cheap job. That means the values cannot live in
# Ruby. They live in tool/ios_identifiers.sh, shell syntax so bash can source
# it, and this is the reader. Two literals drift; one does not.
IDENTIFIERS_PATH = File.join(__dir__, 'ios_identifiers.sh')

# `NAME=value` lines and comments, nothing else -- no command substitution, no
# quoting, no arrays. `$NAME` and `${NAME}` expand against names already defined
# ABOVE the line, which is how the derived identifiers (the extension's bundle
# id, the App Group) stay one derivation rule instead of two literals that can
# disagree. Anything the grammar does not cover is refused by name rather than
# silently half-read, because a half-read identifier is an App Group nobody
# registered.
def read_identifiers(path)
  die("no #{path} -- it is the single definition of every iOS identifier, read by this script and by tool/check_extension.sh") unless File.file?(path)

  values = {}
  File.foreach(path).with_index(1) do |line, number|
    text = line.strip
    next if text.empty? || text.start_with?('#')

    name, separator, raw = text.partition('=')
    unless separator == '=' && name.match?(/\A[A-Z][A-Z0-9_]*\z/)
      die("#{path}:#{number}: not a NAME=value line: #{text}")
    end

    value = raw.gsub(/\$\{?([A-Z][A-Z0-9_]*)\}?/) do
      referenced = Regexp.last_match(1)
      values[referenced] || die("#{path}:#{number}: $#{referenced} is used before it is defined")
    end

    if value.empty? || value.match?(/[\s'"`$()]/)
      die("#{path}:#{number}: #{name} is #{value.inspect}; this reader handles plain unquoted values only")
    end

    values[name] = value
  end
  values
end

IDENTIFIERS = read_identifiers(IDENTIFIERS_PATH)

def identifier(name)
  IDENTIFIERS[name] || die("#{IDENTIFIERS_PATH} defines no #{name}, which this script cannot invent: it is registered against an Apple team or read out of a bundle at runtime")
end

APP_TARGET = identifier('APP_TARGET')
# The target name, not the directory name. The sources live in Extension/ but
# the target is SingboxTunnel because two things read that string: the bundle
# identifier below, and NSExtensionPrincipalClass, which is resolved through
# $(PRODUCT_MODULE_NAME) -- the target name with non-identifier characters
# replaced. Renaming the target renames the Swift module and breaks the
# principal-class lookup with no build error, only a provider iOS cannot
# instantiate. packages/singbox_tunnel/ios/README.md:58 names it, and
# Shared/SharedContainer.swift tells the operator the same string.
EXT_TARGET = identifier('EXT_TARGET')
APP_BUNDLE_ID = identifier('APP_BUNDLE_ID')
EXT_BUNDLE_ID = identifier('EXT_BUNDLE_ID')
APP_GROUP = identifier('APP_GROUP')

DEPLOYMENT_TARGET = identifier('DEPLOYMENT_TARGET')
SWIFT_VERSION = identifier('SWIFT_VERSION')

NE_ENTITLEMENT = identifier('NE_ENTITLEMENT')
NE_ENTITLEMENT_VALUE = identifier('NE_ENTITLEMENT_VALUE')
GROUPS_ENTITLEMENT = identifier('GROUPS_ENTITLEMENT')
APP_GROUP_INFO_KEY = identifier('APP_GROUP_INFO_KEY')
PROVIDER_INFO_KEY = identifier('PROVIDER_INFO_KEY')
EXTENSION_POINT = identifier('EXTENSION_POINT')
PROVIDER_CLASS = identifier('PROVIDER_CLASS')

# Nested under the app's, because iOS refuses to install an extension whose
# identifier is not a prefix-extension of its container app's, at install time,
# with no useful text (README.md:64). Asserted here as well as in
# tool/check_extension.sh, because this is the half that writes it.
unless EXT_BUNDLE_ID == "#{APP_BUNDLE_ID}.#{EXT_TARGET}" && APP_GROUP == "group.#{APP_BUNDLE_ID}"
  die(<<~MSG)
    #{IDENTIFIERS_PATH} has drifted from the shapes iOS and this script require:
      EXT_BUNDLE_ID is #{EXT_BUNDLE_ID.inspect}, expected #{"#{APP_BUNDLE_ID}.#{EXT_TARGET}".inspect}
      APP_GROUP     is #{APP_GROUP.inspect}, expected #{"group.#{APP_BUNDLE_ID}".inspect}
    The extension's identifier must be the app's plus exactly the target name,
    or iOS refuses to install it; the App Group is registered against a real
    Apple team under that spelling.
  MSG
end

# Relative to app/ios/, which is where Runner.xcodeproj sits and what $(SRCROOT)
# expands to for every target in it.
PACKAGE_REL = "../#{identifier('PACKAGE_SUBDIR')}"
PACKAGE_IOS = File.join(APP_DIR, identifier('PACKAGE_SUBDIR'))
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

ENTITLEMENTS = {
  NE_ENTITLEMENT => [NE_ENTITLEMENT_VALUE],
  GROUPS_ENTITLEMENT => [APP_GROUP],
}.freeze

EXT_INFO_PLIST = {
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
    'NSExtensionPointIdentifier' => EXTENSION_POINT,
    # Resolved by the Objective-C runtime as <module>.<class>, which is why
    # PacketTunnelProvider keeps that exact name and why the target does.
    'NSExtensionPrincipalClass' => "$(PRODUCT_MODULE_NAME).#{PROVIDER_CLASS}",
  },
  # Read by Shared/SharedContainer.swift in both processes. The extension does
  # not look itself up, so PROVIDER_INFO_KEY is the app's only.
  APP_GROUP_INFO_KEY => APP_GROUP,
}.freeze

# The two keys merged into the app's Info.plist, which `flutter create` owns the
# rest of.
RUNNER_INFO_ADDITIONS = {
  APP_GROUP_INFO_KEY => APP_GROUP,
  PROVIDER_INFO_KEY => EXT_BUNDLE_ID,
}.freeze

EMBED_PHASE_NAME = 'Embed App Extensions'
CHECK_PHASE_NAME = 'Check Libbox.xcframework'

# 13 is PlugIns. An .appex anywhere else in the bundle is not loaded and iOS
# says nothing about it.
PLUGINS_SUBFOLDER_SPEC = '13'

# Without the framework the extension still has source to compile and the
# project still produces an .ipa, which then dies at the first connect with a
# missing symbol thrown from inside a Go callback -- the least legible possible
# place to learn that a build step was skipped. Same reason
# packages/singbox_tunnel/android/build.gradle refuses to configure without the
# .aar. An .xcframework IS its root Info.plist: that file is what lists the
# available libraries, so a directory without one is not one.
CHECK_PHASE_SCRIPT = <<~SH
  xcframework="$SRCROOT/#{XCFRAMEWORK_REL}"
  if [ ! -f "$xcframework/Info.plist" ]; then
    echo "error: missing $xcframework -- it is built by the libbox_apple job in .github/workflows/app.yml and unpacked there by the ios job" >&2
    exit 1
  fi
SH

# Every one of these is read by Xcode or by iOS at a point where getting it
# wrong produces a build that succeeds, which is why they are a table both modes
# read rather than a sequence of assignments only one of them runs.
EXT_BUILD_SETTINGS = {
  'PRODUCT_NAME' => '$(TARGET_NAME)',
  'PRODUCT_BUNDLE_IDENTIFIER' => EXT_BUNDLE_ID,
  'INFOPLIST_FILE' => "#{EXT_TARGET}/Info.plist",
  # Xcode 13+ will synthesise an Info.plist and merge it over this one unless
  # told not to, which is how a hand-written NSExtension dictionary quietly
  # stops being the one in the built bundle.
  'GENERATE_INFOPLIST_FILE' => 'NO',
  'CODE_SIGN_ENTITLEMENTS' => "#{EXT_TARGET}/#{EXT_TARGET}.entitlements",
  'CODE_SIGN_STYLE' => 'Automatic',
  # 15.0 is libbox's floor, not a preference: build_libbox passes
  # -iosversion=15.0 (cmd/internal/build_libbox/main.go:206), so that is the
  # minimum of every slice in Libbox.xcframework. Set on the target explicitly
  # so a drift in the project-level setting cannot silently drop the extension
  # below it.
  'IPHONEOS_DEPLOYMENT_TARGET' => DEPLOYMENT_TARGET,
  'SWIFT_VERSION' => SWIFT_VERSION,
  'TARGETED_DEVICE_FAMILY' => '1,2',
  'SKIP_INSTALL' => 'NO',
  # The app embeds the Swift runtime; a second copy inside the .appex is
  # rejected at validation.
  'ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES' => 'NO',
  'LD_RUNPATH_SEARCH_PATHS' => [
    '$(inherited)', '@executable_path/Frameworks', '@executable_path/../../Frameworks'
  ],
  # libbox's Apple binding references UIApplication and UIBackgroundTaskInvalid,
  # and an app extension does not link UIKit by default -- the first link of this
  # target failed on exactly those two symbols. `-lresolv` for the same reason
  # one step later: the Go resolver pulls res_9_* out of libresolv.
  'OTHER_LDFLAGS' => ['$(inherited)', '-framework', 'UIKit', '-lresolv'],
  'FRAMEWORK_SEARCH_PATHS' => ['$(inherited)', "$(SRCROOT)/#{PACKAGE_REL}/Frameworks"],
  # The build-phase check below reads a path outside app/ios/. With script
  # sandboxing on, that read is denied and the phase fails with a sandbox error
  # instead of the message it exists to print.
  'ENABLE_USER_SCRIPT_SANDBOXING' => 'NO',
}.freeze

RUNNER_BUILD_SETTINGS = {
  'PRODUCT_BUNDLE_IDENTIFIER' => APP_BUNDLE_ID,
  'CODE_SIGN_ENTITLEMENTS' => "#{APP_TARGET}/#{APP_TARGET}.entitlements",
}.freeze

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

runner_dir = File.join(IOS_DIR, APP_TARGET)
runner_info_path = File.join(runner_dir, 'Info.plist')
die("no #{runner_info_path} -- `flutter create` writes it, so the iOS template layout moved") unless File.file?(runner_info_path)

ext_dir = File.join(IOS_DIR, EXT_TARGET)
project_configs = project.build_configuration_list.build_configurations.map(&:name)

# ============================================================================
# --check
# ============================================================================

if MODE == :check
  problems = []
  note = ->(message) { problems << message }

  ext = project.targets.find { |t| t.name == EXT_TARGET }
  if ext.nil?
    note.call("no target named #{EXT_TARGET}; targets are #{project.targets.map(&:name).join(', ')}")
  else
    unless ext.product_type == 'com.apple.product-type.app-extension'
      note.call("#{EXT_TARGET}'s product type is #{ext.product_type.inspect}, not com.apple.product-type.app-extension -- iOS decides what to do with the product from that")
    end

    # A Flutter project has three configurations and `flutter run --profile`
    # passes -configuration Profile: a target missing it fails the build with
    # "does not contain configuration Profile", naming the extension rather than
    # the omission.
    absent_configs = project_configs - ext.build_configurations.map(&:name)
    note.call("#{EXT_TARGET} has no #{absent_configs.join(', ')} build configuration") unless absent_configs.empty?

    ext.build_configurations.each do |config|
      base = config.base_configuration_reference&.display_name
      unless base == 'Generated.xcconfig'
        # Flutter defines FLUTTER_BUILD_NAME and FLUTTER_BUILD_NUMBER there, and
        # the extension's version keys expand from them. Without it the
        # extension's version differs from its container app's, which App Store
        # validation rejects as ITMS-90473 -- at upload.
        note.call("#{EXT_TARGET}/#{config.name} has base configuration #{base.inspect}, not Generated.xcconfig")
      end

      EXT_BUILD_SETTINGS.each do |key, want|
        got = config.build_settings[key]
        note.call("#{EXT_TARGET}/#{config.name} #{key} is #{got.inspect}, expected #{want.inspect}") unless got == want
      end
    end

    # Basenames, because the references are relative to the singbox_tunnel group
    # and it is the SET of compiled files that decides whether the extension can
    # start -- a target that compiles a subset builds clean.
    want_sources = (EXT_SOURCES + SHARED_SOURCES).map { |rel| File.basename(rel) }.sort
    got_sources = ext.source_build_phase.files.filter_map { |f| f.file_ref&.display_name }.sort
    note.call("#{EXT_TARGET} compiles #{got_sources.inspect}, expected #{want_sources.inspect}") unless got_sources == want_sources

    linked = ext.frameworks_build_phase.files.filter_map { |f| f.file_ref&.display_name }
    note.call("#{EXT_TARGET} links #{linked.inspect}, which does not include Libbox.xcframework") unless linked.include?('Libbox.xcframework')

    # gomobile builds the slices -buildmode=c-archive (bind_iosapp.go:335), so
    # every one is a static archive, and embedding a static framework produces a
    # bundle the loader rejects.
    embedded_framework = ext.copy_files_build_phases.flat_map do |phase|
      phase.files.filter_map { |f| f.file_ref&.display_name }
    end
    if embedded_framework.include?('Libbox.xcframework')
      note.call("#{EXT_TARGET} EMBEDS Libbox.xcframework in a copy-files phase; its slices are static archives and the loader rejects the resulting bundle")
    end

    check_phase = ext.shell_script_build_phases.find { |p| p.name == CHECK_PHASE_NAME }
    if check_phase.nil?
      note.call("#{EXT_TARGET} has no \"#{CHECK_PHASE_NAME}\" shell script phase")
    else
      # Before Compile Sources, or the check reports a missing framework after
      # the compile that needed it has already failed on `import Libbox`.
      index = ext.build_phases.index(check_phase)
      note.call("\"#{CHECK_PHASE_NAME}\" is build phase #{index} of #{EXT_TARGET}, not the first") unless index.zero?
      unless check_phase.shell_script.to_s.include?(XCFRAMEWORK_REL)
        note.call("\"#{CHECK_PHASE_NAME}\" does not mention #{XCFRAMEWORK_REL}, so it is checking some other path")
      end
    end

    # The dependency is what makes `flutter build ios`, which builds the Runner
    # scheme, build the extension at all. Without it the .appex is never
    # produced and the copy phase silently copies nothing.
    unless runner.dependencies.map { |d| d.target&.name }.include?(EXT_TARGET)
      note.call("#{APP_TARGET} does not depend on #{EXT_TARGET}, so building the Runner scheme never builds the extension")
    end

    embed = runner.copy_files_build_phases.find { |p| p.name == EMBED_PHASE_NAME }
    if embed.nil?
      note.call("#{APP_TARGET} has no \"#{EMBED_PHASE_NAME}\" phase, so the .appex is never copied into the app")
    else
      unless embed.dst_subfolder_spec == PLUGINS_SUBFOLDER_SPEC
        note.call("\"#{EMBED_PHASE_NAME}\" copies into subfolder spec #{embed.dst_subfolder_spec.inspect}, not #{PLUGINS_SUBFOLDER_SPEC} (PlugIns) -- an .appex elsewhere in the bundle is not loaded and iOS says nothing about it")
      end
      note.call("\"#{EMBED_PHASE_NAME}\" has a destination path of #{embed.dst_path.inspect}, expected the PlugIns root") unless embed.dst_path.to_s.empty?
      copied = embed.files.filter_map { |f| f.file_ref&.display_name }
      note.call("\"#{EMBED_PHASE_NAME}\" copies #{copied.inspect}, not #{EXT_TARGET}.appex") unless copied.include?("#{EXT_TARGET}.appex")

      # Appended last -- which is where new_copy_files_build_phase puts it --
      # the build failed with "Cycle inside Runner": the copy of the .appex
      # depended on Thin Binary, which reached ExtractAppIntentsMetadata, which
      # reached the [CP] Embed Pods Frameworks phase CocoaPods appends after
      # ours, which reached back to the copy. Ordering the embed ahead of Thin
      # Binary breaks the loop.
      thin = runner.build_phases.find { |p| p.respond_to?(:name) && p.name == 'Thin Binary' }
      if thin && runner.build_phases.index(embed) > runner.build_phases.index(thin)
        note.call("\"#{EMBED_PHASE_NAME}\" runs after \"Thin Binary\"; that ordering is the \"Cycle inside Runner\" build failure")
      end
    end
  end

  # Read rather than assumed. The App Group and the extension's identifier are
  # both derived from the app's, and the App Group is a real artefact registered
  # against a signing team -- so an app identifier that is not the one the docs
  # name means the group in the entitlements is one nobody registered.
  runner.build_configurations.each do |config|
    RUNNER_BUILD_SETTINGS.each do |key, want|
      got = config.build_settings[key]
      note.call("#{APP_TARGET}/#{config.name} #{key} is #{got.inspect}, expected #{want.inspect}") unless got == want
    end
  end

  # The three generated files, compared as parsed plists and not as bytes:
  # whitespace is not a runtime fact, and a value is. Key by key, and including
  # keys that should not be there -- a second App Group appended beside the right
  # one is a file iOS reads differently from this script, and dumping two whole
  # dictionaries to say so buries it.
  {
    File.join(ext_dir, "#{EXT_TARGET}.entitlements") => ENTITLEMENTS,
    File.join(runner_dir, "#{APP_TARGET}.entitlements") => ENTITLEMENTS,
    File.join(ext_dir, 'Info.plist') => EXT_INFO_PLIST,
  }.each do |path, want|
    unless File.file?(path)
      note.call("no #{path}")
      next
    end
    name = path.delete_prefix("#{IOS_DIR}/")
    got = Xcodeproj::Plist.read_from_path(path)
    want.each do |key, value|
      note.call("#{name} #{key} is #{got[key].inspect}, expected #{value.inspect}") unless got[key] == value
    end
    (got.keys - want.keys).each do |key|
      note.call("#{name} carries #{key} => #{got[key].inspect}, which this script does not write")
    end
  end

  runner_info = Xcodeproj::Plist.read_from_path(runner_info_path)
  RUNNER_INFO_ADDITIONS.each do |key, want|
    got = runner_info[key]
    next if got == want

    note.call("#{runner_info_path.delete_prefix("#{IOS_DIR}/")} #{key} is #{got.inspect}, expected #{want.inspect}")
  end

  unless problems.empty?
    warn "ios_project.rb --check: #{problems.length} difference(s) between app/ios/ and what this script writes"
    problems.each { |message| warn "  #{message}" }
    warn ''
    warn 'app/ios/ is a committed generated artefact. Either the edit belongs in this'
    warn 'script, or app/ios/ was hand-edited: regenerate it with the ios_project job'
    warn 'in .github/workflows/app.yml and commit the result.'
    exit 1
  end

  puts "app/ios/Runner.xcodeproj matches tool/ios_project.rb (#{EXT_TARGET}, #{project_configs.length} configurations)"
  puts "app bundle    #{APP_BUNDLE_ID}"
  puts "ext bundle    #{EXT_BUNDLE_ID}"
  puts "app group     #{APP_GROUP}"
  exit 0
end

# ============================================================================
# generate
# ============================================================================

if project.targets.any? { |t| t.name == EXT_TARGET }
  die(<<~MSG)
    Runner.xcodeproj already has a target named #{EXT_TARGET}.
    This script does not merge into an edited project. To regenerate: delete
    app/ios/ entirely, re-run `flutter create --platforms=ios`, then this.
    To check the committed project against this script instead: --check
  MSG
end

# `flutter create` builds the app identifier from --org and --project-name via
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

FileUtils.mkdir_p(ext_dir)

Xcodeproj::Plist.write_to_path(ENTITLEMENTS, File.join(ext_dir, "#{EXT_TARGET}.entitlements"))

# The app needs the SAME two keys, and that is not symmetry for its own sake:
# com.apple.developer.networking.networkextension is what lets
# NETunnelProviderManager save a configuration naming a custom provider, and
# without the App Group the app cannot read the only account the extension
# leaves of why it stopped (README.md:87).
Xcodeproj::Plist.write_to_path(ENTITLEMENTS, File.join(runner_dir, "#{APP_TARGET}.entitlements"))

Xcodeproj::Plist.write_to_path(EXT_INFO_PLIST, File.join(ext_dir, 'Info.plist'))

runner_info = Xcodeproj::Plist.read_from_path(runner_info_path)
Xcodeproj::Plist.write_to_path(runner_info.merge(RUNNER_INFO_ADDITIONS), runner_info_path)

# --- the target -------------------------------------------------------------

ext = project.new_target(:app_extension, EXT_TARGET, :ios, DEPLOYMENT_TARGET, nil, :swift)

# new_target writes Debug and Release. A Flutter project has three, and
# `flutter run --profile` passes -configuration Profile: a target missing it
# fails the build with "does not contain configuration Profile", naming the
# extension rather than this omission.
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
  config.build_settings.merge!(EXT_BUILD_SETTINGS)
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
  config.build_settings.merge!(RUNNER_BUILD_SETTINGS)
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

check_phase = ext.new_shell_script_build_phase(CHECK_PHASE_NAME)
check_phase.shell_path = '/bin/sh'
check_phase.show_env_vars_in_log = '0'
check_phase.shell_script = CHECK_PHASE_SCRIPT
# Before Compile Sources, or the check reports a missing framework after the
# compile that needed it has already failed on `import Libbox`.
ext.build_phases.move(check_phase, 0)

# --- embed it in the app ----------------------------------------------------

# The dependency is what makes `flutter build ios`, which builds the Runner
# scheme, build the extension at all. Without it the .appex is never produced
# and the copy phase below silently copies nothing.
runner.add_dependency(ext)

embed = runner.new_copy_files_build_phase(EMBED_PHASE_NAME)
embed.dst_subfolder_spec = PLUGINS_SUBFOLDER_SPEC
embed.dst_path = ''
embed_file = embed.add_file_reference(ext.product_reference, true)
embed_file.settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }

# Before Flutter's "Thin Binary", not after it. Appended last -- which is where
# new_copy_files_build_phase puts it -- the build failed with "Cycle inside
# Runner": the copy of SingboxTunnel.appex depended on Thin Binary, which
# reached ExtractAppIntentsMetadata, which reached the [CP] Embed Pods
# Frameworks phase CocoaPods appends after ours, which reached back to the copy.
# Ordering the embed ahead of Thin Binary breaks the loop.
thin = runner.build_phases.find do |phase|
  phase.respond_to?(:name) && phase.name == 'Thin Binary'
end
if thin
  runner.build_phases.delete(embed)
  runner.build_phases.insert(runner.build_phases.index(thin), embed)
else
  warn 'note: no "Thin Binary" phase; leaving Embed App Extensions last'
end

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
puts "verify        ruby tool/ios_project.rb --check"
