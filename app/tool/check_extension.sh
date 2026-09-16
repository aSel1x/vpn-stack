#!/usr/bin/env bash
#
# Assert `flutter build ios` actually produced the packet-tunnel extension.
#
# This is the check the iOS job did not have, and its absence is why
# packages/singbox_tunnel/ios/Extension/ had never been through a compiler: a
# stock one-target Flutter project builds clean, links no libbox, contains no
# NEPacketTunnelProvider, and wraps into a perfectly valid .ipa. A .app with no
# PlugIns/ is a UI with no tunnel, and nothing in the build log says so. Same
# shape of failure as an APK with no libbox.aar, caught at the same seam.
#
# One definition, two callers: the `ios` and `ios_project` jobs in
# .github/workflows/app.yml.
set -euo pipefail

app="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle="$app/build/ios/iphoneos/Runner.app"
appex="$bundle/PlugIns/SingboxTunnel.appex"

[ -d "$bundle" ] || {
  echo "error: no $bundle -- the iOS output layout moved" >&2
  exit 1
}

[ -d "$appex" ] || {
  echo "error: no $appex" >&2
  echo "The app built without its extension. Either Runner.xcodeproj carries no dependency" >&2
  echo "from Runner on the SingboxTunnel target, or its Embed App Extensions copy phase did" >&2
  echo "not copy the product. Both are written by tool/ios_project.rb." >&2
  exit 1
}

[ -f "$appex/SingboxTunnel" ] || {
  echo "error: $appex has no executable -- the target exists and compiled nothing into it" >&2
  exit 1
}
file "$appex/SingboxTunnel"

plist="$appex/Info.plist"
point=$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionPointIdentifier' "$plist")
principal=$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionPrincipalClass' "$plist")

[ "$point" = "com.apple.networkextension.packet-tunnel" ] || {
  echo "error: NSExtensionPointIdentifier is \"$point\", not com.apple.networkextension.packet-tunnel" >&2
  echo "iOS decides what kind of extension this is from that string alone." >&2
  exit 1
}

# Asserted against the EXPANDED value, which is the whole reason to read the
# built bundle rather than the source Info.plist. The source says
# $(PRODUCT_MODULE_NAME).PacketTunnelProvider; if that setting ever fails to
# expand, the bundle ships a principal class the Objective-C runtime cannot
# look up, iOS refuses to instantiate the provider, and the app is handed a bare
# "disconnected" with no reason -- the exact summarised-into-nothing that the
# shared status file exists to prevent.
[ "$principal" = "SingboxTunnel.PacketTunnelProvider" ] || {
  echo "error: NSExtensionPrincipalClass is \"$principal\", not SingboxTunnel.PacketTunnelProvider" >&2
  exit 1
}

echo "extension built: SingboxTunnel.appex, $point, $principal"
