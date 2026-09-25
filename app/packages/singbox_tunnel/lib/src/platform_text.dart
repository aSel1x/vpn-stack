// The half of a failure message that is not the same on both platforms.
//
// One Dart controller drives Android and iOS, because the channel contract is
// identical and everything that differs lives below it. What leaked through that
// symmetry was the prose: every user-visible string this package composed named
// Android unconditionally, so an iPhone whose tunnel would not come up told the
// person to read `adb logcat` for a service that had never existed on their
// device, and to look for a VPN key in a status bar that shows a badge. A
// diagnosis naming the wrong operating system is worse than a terse one -- it
// sends somebody after an artifact that cannot be there.
//
// So the words that differ are data, chosen once at construction. Each field is
// a FRAGMENT a message is composed from and not a finished message: a
// message-per-platform table lets one platform's copy drift out of the shape the
// other keeps, which is how the Android-only wording survived unnoticed in the
// first place. The shared sentences stay at the failure site in
// singbox_tunnel.dart, where the reasoning about why that path fails is.

import 'package:flutter/foundation.dart';

/// The platform-specific fragments of this package's failure messages.
///
/// [TunnelStatus.message] is shown verbatim -- a tunnel that will not come up is
/// diagnosed from exactly that string -- so every fragment here is written for
/// somebody staring at a Connect button that failed, not for a log parser.
class TunnelPlatformText {
  const TunnelPlatformText({
    required this.osName,
    required this.language,
    required this.startedProcess,
    required this.engineClass,
    required this.consentDenied,
    required this.consentDetail,
    required this.logHint,
    required this.groundTruth,
    required this.unregistered,
  });

  /// How the operating system calls itself, as a person would read it.
  final String osName;

  /// The language on the other end of the channel. Named only where the message
  /// is about a disagreement over the channel contract, because that is a skew
  /// between two files somebody has to open, and saying which two saves the
  /// search.
  final String language;

  /// The thing `start` started, as the subject of a sentence: the two are not
  /// the same kind of object. Android runs the engine in a foreground service
  /// inside the app's own process; iOS runs it in a separate packet-tunnel
  /// extension the system launches.
  final String startedProcess;

  /// The class required to name what broke when it reports failure. A status of
  /// `failed` with no message is a bug in exactly this file on exactly that
  /// side, so the message says which.
  final String engineClass;

  /// What the system withheld, as a verb phrase after [osName]. Android grants
  /// or refuses a VPN permission from a dialog; iOS approves or refuses the
  /// installation of a VPN configuration. The two are the same consent and not
  /// the same noun.
  final String consentDenied;

  /// What declining leaves behind, and therefore what has to be done about it.
  final String consentDetail;

  /// Where the engine's own words are. Both are exact commands rather than
  /// "check the logs": the engine logs under a tag on one platform and an
  /// os_log subsystem on the other, and neither is guessable.
  final String logHint;

  /// What to trust when this layer cannot say whether the tunnel is down. The
  /// system's own VPN indicator is the only authority, and it is in a different
  /// place with a different icon on each platform.
  final String groundTruth;

  /// Why a channel might not be registered here. Not merely "this is not
  /// Android": on a platform this package declares no implementation for, the
  /// answer is that the composition root wired the wrong controller, which is a
  /// different repair from a missing rebuild.
  final String unregistered;

  static const TunnelPlatformText android = TunnelPlatformText(
    osName: 'Android',
    language: 'Kotlin',
    startedProcess: 'The Android foreground service',
    engineClass: 'SingboxVpnService',
    consentDenied: 'did not grant VPN permission',
    consentDetail: 'Android asks once per app, from a system dialog; declining '
        'it leaves this app unable to open a TUN interface at all.',
    logHint: '`adb logcat -s SingboxTunnel`',
    groundTruth: 'The VPN key in the status bar, and Settings > Network & '
        'internet > VPN, are the ground truth.',
    unregistered: 'Either this is not Android, or the plugin was added to '
        'pubspec.yaml without a rebuild -- a hot restart does not register a '
        'new plugin.',
  );

  static const TunnelPlatformText ios = TunnelPlatformText(
    osName: 'iOS',
    language: 'Swift',
    startedProcess: 'The iOS packet-tunnel extension',
    engineClass: 'PacketTunnelProvider',
    consentDenied: 'did not approve the VPN configuration',
    consentDetail: 'iOS asks by raising its own approval sheet when the '
        'configuration is saved, and there is no separate permission API; '
        'declining it installs no configuration, so there is nothing for the '
        'packet-tunnel extension to be started from. Settings > General > VPN & '
        'Device Management lists what is installed.',
    logHint: "`log stream --predicate 'subsystem == "
        "\"io.github.asel1x.singbox_tunnel\"'` on a Mac with the device "
        'attached, or the same predicate in Console.app',
    groundTruth: 'The VPN badge in the status bar, and Settings > General > VPN '
        '& Device Management, are the ground truth.',
    unregistered: 'Either this is not iOS, or the plugin was added to '
        'pubspec.yaml without a rebuild -- a hot restart does not register a '
        'new plugin, and on iOS neither does it install an app extension.',
  );

  /// For a platform this package registers nothing on.
  ///
  /// Reaching it is a composition-root mistake and the text says so rather than
  /// blaming an operating system that is not involved: `main.dart` wires
  /// `UnimplementedTunnel` everywhere but Android and iOS, and a
  /// [SingboxTunnel] built here fails at startup when its status channel turns
  /// out not to exist.
  factory TunnelPlatformText.unsupported(String osName) => TunnelPlatformText(
        osName: osName,
        language: 'platform code',
        startedProcess: 'The $osName side',
        engineClass: 'the platform implementation',
        consentDenied: 'did not grant VPN permission',
        consentDetail: 'singbox_tunnel registers a plugin on Android and iOS '
            'only, so there was nothing on $osName to ask.',
        // Not a device log: there is no engine on this platform to have
        // logged anything. What a person can actually read is the app's
        // own console, where a plugin that registered nothing shows up.
        logHint: '`flutter logs`',
        groundTruth: "The operating system's own VPN settings are the ground "
            'truth.',
        unregistered: 'singbox_tunnel declares platform implementations for '
            'Android and iOS only, and this is $osName -- app/README.md puts '
            'every other target on a privileged helper, which is a process and '
            'not a plugin. The composition root wires UnimplementedTunnel '
            'there.',
      );

  /// The fragments for one target, for the composition root that did not name
  /// them itself.
  ///
  /// Exhaustive over [TargetPlatform] deliberately: a new value added by a
  /// Flutter upgrade should be a compile error here, not a build that quietly
  /// reports the Android wording on it.
  static TunnelPlatformText forPlatform(TargetPlatform platform) =>
      switch (platform) {
        TargetPlatform.android => android,
        TargetPlatform.iOS => ios,
        TargetPlatform.macOS ||
        TargetPlatform.windows ||
        TargetPlatform.linux ||
        TargetPlatform.fuchsia =>
          TunnelPlatformText.unsupported(platform.name),
      };
}
