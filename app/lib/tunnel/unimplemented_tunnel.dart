import 'package:flutter/foundation.dart';

import 'tunnel.dart';

/// The [TunnelController] for a platform that has no engine, and it does
/// nothing.
///
/// It reports [TunnelStage.failed] with the text below and throws an
/// [UnimplementedError] naming the platform and what that platform would need.
/// It never reports [TunnelStage.connected].
///
/// That restraint is the whole point. A stub that shows "Connected" is
/// indistinguishable from a working app: somebody believes it, routes their
/// traffic through nothing, and finds out later. A build that says exactly what
/// is missing costs an afternoon; one that lies costs trust in the whole thing.
///
/// `SingboxTunnel` in `packages/singbox_tunnel/` is the engine, and `main.dart`
/// wires it on Android and iOS. What is left here is the three desktop targets,
/// where the tunnel needs a privileged process to open a TUN device rather than
/// a plugin -- so the sibling that replaces this one is a client of a helper
/// service, not another method channel.
class UnimplementedTunnel extends BaseTunnelController {
  UnimplementedTunnel({TargetPlatform? platform})
      : platform = platform ?? defaultTargetPlatform;

  /// Injectable so a test can assert the message for a platform it is not
  /// running on; `dart:io` would pin this to the host.
  final TargetPlatform platform;

  /// Why this platform has no tunnel, in prose, because it is read by a person
  /// staring at a Connect button that failed.
  ///
  /// Every branch names its own platform, and [_refusal] leads with this rather
  /// than with a sentence of its own. A wrapper such as "no tunnel engine on
  /// `<platform>`" would be a flat contradiction on the two platforms where an
  /// engine does exist and this controller is merely unwired -- and a message
  /// that contradicts itself is one nobody reads to the end of.
  String get requirement {
    switch (platform) {
      // The two platforms that DO have an engine. Reaching either means the
      // composition root handed the screens the stub, because `main.dart` puts
      // both on `SingboxTunnel` -- so the requirement is not an artifact, it is
      // one line of wiring, and saying anything about libbox here would send
      // somebody looking for a file that is present.
      case TargetPlatform.android:
        return 'Android has an engine -- libbox behind a VpnService, in '
            'packages/singbox_tunnel -- and this is not it. Whatever built this '
            'app did not wire it; lib/main.dart is the only file that chooses.';
      case TargetPlatform.iOS:
        return 'iOS has an engine -- a NEPacketTunnelProvider extension started '
            'through NETunnelProviderManager, with the target committed in '
            'app/ios/ -- and this is not it. What an iOS BUILD needs beyond '
            'that is a signature: the Network Extension entitlement requires a '
            'paid Apple membership, and App Store Review Guideline 5.4 admits '
            'VPN apps only from a developer enrolled as an organization, so CI '
            'can only produce an unsigned .ipa. Connecting here would not '
            'change either; see app/README.md.';
      case TargetPlatform.macOS:
        return 'macOS needs a privileged helper to open the TUN device: '
            'sing-box cannot create one from a sandboxed app. The helper is not '
            'in this repository yet.';
      case TargetPlatform.windows:
        return 'Windows needs wintun.dll and an elevated helper service to '
            'create the TUN adapter. Neither is in this repository yet.';
      case TargetPlatform.linux:
        return 'Linux needs a privileged helper (CAP_NET_ADMIN, or a root '
            'systemd unit) to create the TUN device. It is not in this '
            'repository yet.';
      case TargetPlatform.fuchsia:
        return 'There is no tunnel engine for Fuchsia, and none is planned.';
    }
  }

  String _refusal(TunnelProfile profile) =>
      '$requirement\n'
      'Nothing was connected: ${profile.label} (${profile.host}) is configured '
      'and its ${profile.importUris.length} share URI(s) were not used.';

  @override
  Future<void> connect(TunnelProfile profile) async {
    final String message = _refusal(profile);
    // Goes through connecting on the way to failed so the UI's connecting state
    // is exercised by the real path rather than by a flag somebody set by hand.
    // There is no artificial delay: pretending to take time would be the first
    // step towards pretending to succeed.
    emit(TunnelStatus(TunnelStage.connecting, profileId: profile.id));
    emit(TunnelStatus(
      TunnelStage.failed,
      profileId: profile.id,
      message: message,
    ));
    throw UnimplementedError(message);
  }

  @override
  Future<void> disconnect() async {
    // Honest: nothing is up, so asking for it down is already true. Throwing
    // here would make a UI that tries to clean up look broken.
    emit(TunnelStatus.idle);
  }
}
