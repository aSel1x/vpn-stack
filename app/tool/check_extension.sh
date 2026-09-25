#!/usr/bin/env bash
#
# Assert the four places that must agree about the packet-tunnel extension do,
# and that `flutter build ios` actually produced it.
#
# The second half is the check the iOS job did not have, and its absence is why
# packages/singbox_tunnel/ios/Extension/ had never been through a compiler: a
# stock one-target Flutter project builds clean, links no libbox, contains no
# NEPacketTunnelProvider, and wraps into a perfectly valid .ipa. A .app with no
# PlugIns/ is a UI with no tunnel, and nothing in the build log says so. Same
# shape of failure as an APK with no libbox.aar, caught at the same seam.
#
# The first half exists because app/ios/Runner.xcodeproj is a COMMITTED
# generated artefact and every identifier in it is compared at RUNTIME by iOS
# and by nothing at build time. An App Group that appears in an entitlement and
# not in an Info.plist, or a provider bundle identifier that names an extension
# the .appex is not, compiles, links, signs and ships; the symptom is a sandbox
# denial or a provider iOS declines to instantiate, on the first connect, on a
# target nobody here can sign or run. Reading the strings is the cheapest
# available substitute for a device, so it is done on every push in the cheap
# `check` job rather than only behind a 45-minute macOS build.
#
# Two modes, because those two halves need different machines:
#
#   sources   the committed app/ios/ only. No build, no Xcode, plain text
#             tools; runs on ubuntu-latest.
#   bundle    build/ios/iphoneos/Runner.app, which only a macOS runner has.
#             Asserts the EXPANDED values, which is the whole reason to read
#             the built bundle rather than the source Info.plist.
#
# With no argument it runs both, which is what the `ios` and `ios_project` jobs
# in .github/workflows/app.yml want after a build.
#
# Every identifier below comes from tool/ios_identifiers.sh, the one file
# tool/ios_project.rb also reads, so the generator and this checker cannot
# disagree about what was supposed to be written -- the same reason
# scripts/check.sh reads the sing-box tag out of compose.yml instead of
# restating it.
#
# It reports EVERY mismatch rather than exiting on the first. These values are
# derived from one another, so one wrong bundle identifier usually breaks three
# assertions, and a person fixing it wants the whole set in one run.
set -euo pipefail

app="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tool/ios_identifiers.sh
. "$app/tool/ios_identifiers.sh"

ios="$app/ios"
bundle="$app/build/ios/iphoneos/$APP_TARGET.app"
appex="$bundle/PlugIns/$EXT_TARGET.appex"
pbxproj="$ios/$APP_TARGET.xcodeproj/project.pbxproj"

mode="${1:-all}"
case "$mode" in
  sources | bundle | all) ;;
  *)
    echo "usage: ${BASH_SOURCE[0]##*/} [sources|bundle]" >&2
    exit 2
    ;;
esac

failures=0

fail() {
  echo "error: $1" >&2
  shift
  for line in "$@"; do echo "  $line" >&2; done
  failures=$((failures + 1))
}

# Reports rather than aborts, so the caller can keep checking the other three
# files. An empty `got` is what a missing key looks like.
same() {
  local what=$1 got=$2 want=$3
  if [ "$got" = "$want" ]; then
    printf '  ok  %-56s %s\n' "$what" "$want"
  elif [ -z "$got" ]; then
    fail "$what is absent, expected \"$want\""
  else
    fail "$what is \"$got\", expected \"$want\""
  fi
}

# The first <string> after <key>NAME</key> in an XML plist -- which is the value
# for a string and the first element for an array, and that is deliberate: every
# array read here (both entitlements) carries exactly one entry, and asserting
# the first entry is what catches a second App Group appended beside the right
# one. Nested keys are found by name because each one read here is unique in its
# file.
#
# awk and not PlistBuddy or plutil: this half of the script runs on
# ubuntu-latest, where neither exists. The generated plists are written by
# Xcodeproj::Plist, which puts one element per line, so a line-oriented read is
# sound for these files and for no others.
xml_plist_string() {
  local file=$1 key=$2
  [ -f "$file" ] || return 0
  awk -v key="$key" '
    index($0, "<key>" key "</key>") { seen = 1; next }
    seen && match($0, /<string>.*<\/string>/) {
      print substr($0, RSTART + 8, RLENGTH - 17)
      exit
    }
    # A sibling <key> before any <string> means the value was not a string and
    # not an array of them. Say nothing and let `same` report it as absent.
    seen && /<key>/ { exit }
  ' "$file"
}

# grep -c exits 1 on zero matches, which under `set -e` would end the run at the
# assertion instead of reporting it.
count_in_pbxproj() {
  grep -cF "$1" "$pbxproj" || true
}

# --- the identifier relationship, before anything reads a file --------------

# iOS refuses to install an extension whose identifier is not its container
# app's plus exactly one component. Asserted against the constants as well as
# against the built bundle, because getting it wrong here would write a project
# that builds and an .ipa that installs nowhere -- diagnosed, if at all, on
# somebody's Mac.
suffix=""
case "$EXT_BUNDLE_ID" in
  "$APP_BUNDLE_ID".*) suffix=${EXT_BUNDLE_ID#"$APP_BUNDLE_ID".} ;;
esac
if [ -z "$suffix" ] || [ "$suffix" != "${suffix%%.*}" ]; then
  fail "EXT_BUNDLE_ID \"$EXT_BUNDLE_ID\" is not \"$APP_BUNDLE_ID\" plus exactly one component" \
    "iOS refuses to install an extension whose identifier is not a prefix-extension of" \
    "its container app's, at install time, with no useful text."
else
  printf '  ok  %-56s %s\n' "ext bundle id = app bundle id + one component" ".$suffix"
fi

# --- sources: the committed app/ios/ ----------------------------------------

check_sources() {
  echo "== committed $ios"

  local runner_info="$ios/$APP_TARGET/Info.plist"
  local ext_info="$ios/$EXT_TARGET/Info.plist"
  local runner_ent="$ios/$APP_TARGET/$APP_TARGET.entitlements"
  local ext_ent="$ios/$EXT_TARGET/$EXT_TARGET.entitlements"

  local missing=0 f
  for f in "$runner_info" "$ext_info" "$runner_ent" "$ext_ent" "$pbxproj"; do
    [ -f "$f" ] || {
      fail "no $f" "It is written by tool/ios_project.rb and committed. Regenerate app/ios/ with the ios_project job."
      missing=1
    }
  done
  [ "$missing" = 0 ] || return 0

  # The app's only way to say which extension to run. A value naming an
  # extension that is not in PlugIns/ leaves NETunnelProviderManager saving a
  # configuration iOS never starts.
  same "$APP_TARGET/Info.plist:$PROVIDER_INFO_KEY" \
    "$(xml_plist_string "$runner_info" "$PROVIDER_INFO_KEY")" "$EXT_BUNDLE_ID"

  # Both processes read this key out of their OWN bundle, so the two spellings
  # have to match each other and the entitlements below. One container written
  # and another read is a tunnel that starts and reports nothing.
  same "$APP_TARGET/Info.plist:$APP_GROUP_INFO_KEY" \
    "$(xml_plist_string "$runner_info" "$APP_GROUP_INFO_KEY")" "$APP_GROUP"
  same "$EXT_TARGET/Info.plist:$APP_GROUP_INFO_KEY" \
    "$(xml_plist_string "$ext_info" "$APP_GROUP_INFO_KEY")" "$APP_GROUP"

  same "$EXT_TARGET/Info.plist:NSExtension:NSExtensionPointIdentifier" \
    "$(xml_plist_string "$ext_info" NSExtensionPointIdentifier)" "$EXTENSION_POINT"
  # Unexpanded here on purpose: $(PRODUCT_MODULE_NAME) is what makes the
  # principal class follow a target rename, and the expansion is asserted
  # against the built bundle in the other mode.
  same "$EXT_TARGET/Info.plist:NSExtension:NSExtensionPrincipalClass" \
    "$(xml_plist_string "$ext_info" NSExtensionPrincipalClass)" \
    "\$(PRODUCT_MODULE_NAME).$PROVIDER_CLASS"

  # Entitlements are read from the SOURCE files and nowhere else: the .ipa this
  # workflow produces is built --no-codesign, so nothing embeds them and the
  # built bundle cannot be asked. The app needs the same two keys as the
  # extension, and that is not symmetry for its own sake -- the Network
  # Extension entitlement is what lets NETunnelProviderManager save a
  # configuration naming a custom provider, and without the App Group the app
  # cannot read the only account the extension leaves of why it stopped.
  local target
  for target in "$APP_TARGET" "$EXT_TARGET"; do
    local ent="$ios/$target/$target.entitlements"
    same "$target.entitlements:$GROUPS_ENTITLEMENT" \
      "$(xml_plist_string "$ent" "$GROUPS_ENTITLEMENT")" "$APP_GROUP"
    same "$target.entitlements:$NE_ENTITLEMENT" \
      "$(xml_plist_string "$ent" "$NE_ENTITLEMENT")" "$NE_ENTITLEMENT_VALUE"
  done

  # The project file, by text. Not by the xcodeproj gem: nothing outside a macOS
  # runner has it, and tool/ios_project.rb --check is what reads the project
  # properly, on the one runner that can.
  local configs n key
  configs=$(count_in_pbxproj "INFOPLIST_FILE = $EXT_TARGET/Info.plist;")
  if [ "$configs" -lt 3 ]; then
    fail "$pbxproj points only $configs build configuration(s) at $EXT_TARGET/Info.plist" \
      "A Flutter project has three -- Debug, Profile, Release -- and \`flutter run --profile\`" \
      "passes -configuration Profile, which fails naming the extension rather than the omission."
  else
    printf '  ok  %-56s %s\n' "$EXT_TARGET build configurations" "$configs"
    # Per configuration, not once: a single drifted one ships an extension
    # carrying the app's own identifier, which Xcode builds and iOS refuses to
    # install, or an Info.plist Xcode synthesises and merges over the
    # hand-written NSExtension dictionary.
    for key in "PRODUCT_BUNDLE_IDENTIFIER = $EXT_BUNDLE_ID;" \
      "CODE_SIGN_ENTITLEMENTS = $EXT_TARGET/$EXT_TARGET.entitlements;" \
      "GENERATE_INFOPLIST_FILE = NO;"; do
      n=$(count_in_pbxproj "$key")
      [ "$n" -ge "$configs" ] || fail "$pbxproj has \"$key\" in $n configuration(s), not all $configs"
    done
  fi

  # Counted against the total rather than against the extension's three, because
  # every target in this project shares one floor: 15.0 is the minimum of every
  # slice in Libbox.xcframework, and a target below it links a framework that
  # does not cover it.
  local floors all_floors
  floors=$(count_in_pbxproj "IPHONEOS_DEPLOYMENT_TARGET = $DEPLOYMENT_TARGET;")
  all_floors=$(count_in_pbxproj 'IPHONEOS_DEPLOYMENT_TARGET = ')
  if [ "$floors" != "$all_floors" ]; then
    fail "$pbxproj sets IPHONEOS_DEPLOYMENT_TARGET $all_floors times and only $floors of them are $DEPLOYMENT_TARGET" \
      "build_libbox passes -iosversion=$DEPLOYMENT_TARGET, so that is the floor of every slice in" \
      "Libbox.xcframework and a target below it has no slice to link."
  else
    printf '  ok  %-56s %s\n' "IPHONEOS_DEPLOYMENT_TARGET, all $all_floors" "$DEPLOYMENT_TARGET"
  fi

  n=$(count_in_pbxproj "PRODUCT_BUNDLE_IDENTIFIER = $APP_BUNDLE_ID;")
  [ "$n" -ge 3 ] || fail "$pbxproj gives $APP_TARGET the identifier $APP_BUNDLE_ID in $n configuration(s), expected 3"

  n=$(count_in_pbxproj "CODE_SIGN_ENTITLEMENTS = $APP_TARGET/$APP_TARGET.entitlements;")
  [ "$n" -ge 3 ] || fail "$pbxproj points $APP_TARGET at $APP_TARGET/$APP_TARGET.entitlements in $n configuration(s), expected 3" \
    "Without it the app is signed with no App Group and no Network Extension entitlement," \
    "and every call into NETunnelProviderManager fails at runtime."

  # Three strings that cannot be in a stock `flutter create` project by
  # accident, so their presence is what separates a project carrying the
  # extension from one that predates it. dstSubfolderSpec 13 is PlugIns; an
  # .appex copied anywhere else in the bundle is not loaded and iOS says nothing
  # about it.
  local needle
  for needle in \
    'com.apple.product-type.app-extension' \
    'Libbox.xcframework' \
    'dstSubfolderSpec = 13;'; do
    grep -qF "$needle" "$pbxproj" || fail "$pbxproj does not mention $needle -- this project predates the extension target"
  done
}

# --- bundle: what the build actually produced -------------------------------

check_bundle() {
  echo "== built $bundle"

  [ -d "$bundle" ] || {
    fail "no $bundle -- the iOS output layout moved"
    return 0
  }

  [ -d "$appex" ] || {
    fail "no $appex" \
      "The app built without its extension. Either Runner.xcodeproj carries no dependency" \
      "from $APP_TARGET on the $EXT_TARGET target, or its Embed App Extensions copy phase did" \
      "not copy the product. Both are written by tool/ios_project.rb."
    return 0
  }

  if [ -f "$appex/$EXT_TARGET" ]; then
    file "$appex/$EXT_TARGET"
  else
    fail "$appex has no executable -- the target exists and compiled nothing into it"
  fi

  # PlistBuddy, because Xcode writes the built Info.plists as BINARY plists --
  # the awk reader above sees no markup in them at all. That is also why this
  # half cannot run on ubuntu.
  plist_string() {
    /usr/libexec/PlistBuddy -c "Print $2" "$1" 2>/dev/null || true
  }

  local app_plist="$bundle/Info.plist"
  local ext_plist="$appex/Info.plist"

  # Every value below is the EXPANDED one, which is the whole reason to read the
  # built bundle: the sources say $(PRODUCT_BUNDLE_IDENTIFIER) and
  # $(PRODUCT_MODULE_NAME), and a setting that fails to expand ships a bundle
  # identifier of literally "$(PRODUCT_BUNDLE_IDENTIFIER)" or a principal class
  # the Objective-C runtime cannot look up -- and the app is then handed a bare
  # "disconnected" with no reason, the exact summarised-into-nothing that the
  # shared status file exists to prevent.
  same "$APP_TARGET.app/Info.plist:CFBundleIdentifier" \
    "$(plist_string "$app_plist" :CFBundleIdentifier)" "$APP_BUNDLE_ID"
  same "$EXT_TARGET.appex/Info.plist:CFBundleIdentifier" \
    "$(plist_string "$ext_plist" :CFBundleIdentifier)" "$EXT_BUNDLE_ID"

  same "$APP_TARGET.app/Info.plist:$APP_GROUP_INFO_KEY" \
    "$(plist_string "$app_plist" ":$APP_GROUP_INFO_KEY")" "$APP_GROUP"
  same "$APP_TARGET.app/Info.plist:$PROVIDER_INFO_KEY" \
    "$(plist_string "$app_plist" ":$PROVIDER_INFO_KEY")" "$EXT_BUNDLE_ID"
  same "$EXT_TARGET.appex/Info.plist:$APP_GROUP_INFO_KEY" \
    "$(plist_string "$ext_plist" ":$APP_GROUP_INFO_KEY")" "$APP_GROUP"

  same "$EXT_TARGET.appex NSExtensionPointIdentifier" \
    "$(plist_string "$ext_plist" :NSExtension:NSExtensionPointIdentifier)" "$EXTENSION_POINT"
  same "$EXT_TARGET.appex NSExtensionPrincipalClass" \
    "$(plist_string "$ext_plist" :NSExtension:NSExtensionPrincipalClass)" "$EXT_TARGET.$PROVIDER_CLASS"

  # ITMS-90473, which App Store validation raises at UPLOAD -- the last place
  # anybody wants to learn it. Both come from $(FLUTTER_BUILD_NAME) and
  # $(FLUTTER_BUILD_NUMBER), so they agree only for as long as the extension's
  # build configurations keep Flutter/Generated.xcconfig as their base
  # configuration reference.
  local key
  for key in CFBundleShortVersionString CFBundleVersion; do
    local app_value ext_value
    app_value=$(plist_string "$app_plist" ":$key")
    ext_value=$(plist_string "$ext_plist" ":$key")
    if [ -z "$app_value" ] || [ "$app_value" != "$ext_value" ]; then
      fail "$key is \"$app_value\" in the app and \"$ext_value\" in the extension" \
        "App Store validation rejects that as ITMS-90473. The extension's copy comes from" \
        "Flutter/Generated.xcconfig; a build configuration without that base configuration" \
        "reference has no FLUTTER_BUILD_NAME to expand."
    else
      printf '  ok  %-56s %s\n' "$key, app and extension" "$app_value"
    fi
  done
}

case "$mode" in
  sources) check_sources ;;
  bundle) check_bundle ;;
  all)
    check_sources
    check_bundle
    ;;
esac

if [ "$failures" -ne 0 ]; then
  echo "$failures assertion(s) failed" >&2
  exit 1
fi

echo "iOS extension identifiers agree ($mode)"
