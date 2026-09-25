// The app's tunnel interface, which lives here because the implementation does.
//
// A Dart class can only implement a type it can import and this package cannot
// import the app (app -> package -> app is a cycle pub refuses), so the
// interface had to move to the package side rather than be depended upon from
// it. app/lib/tunnel/tunnel.dart is one `export` of this file, which is what
// keeps `import 'tunnel.dart'` resolving from every screen. While there were two
// copies, SingboxTunnel implemented a DIFFERENT TunnelController than the
// screens used -- 1,800 lines of plugin satisfying nothing, with every test
// green.
import 'dart:async';

/// Establishing the tunnel on THIS device.
///
/// The UI talks to [TunnelController] and to nothing else, so an engine drops in
/// behind this interface without a screen changing. Two already have, in this
/// package: libbox behind a `VpnService` in `android/`, libbox behind a
/// `NEPacketTunnelProvider` in `ios/`, both driven by `SingboxTunnel` beside
/// this file. The three desktop targets have none, and the sibling that serves
/// them will be a client of a privileged helper rather than another method
/// channel -- only a root process can open a TUN device there. That is the
/// whole reason this seam is an interface and not a class.
///
/// There is deliberately no mock that reports success. See
/// `unimplemented_tunnel.dart`.

/// Where the tunnel is. Four states, because those are the four a person can
/// act on: nothing running, something starting, something up, something broken.
enum TunnelStage { disconnected, connecting, connected, failed }

/// A snapshot of the tunnel, including which profile it belongs to.
///
/// [profileId] is carried so a UI with several configured servers can tell
/// "connected to this one" from "connected to another one". Without it the
/// Connect button on every server lights up as soon as any tunnel is up.
class TunnelStatus {
  const TunnelStatus(this.stage, {this.profileId, this.message});

  final TunnelStage stage;

  /// [TunnelProfile.id] of the profile this status is about, when there is one.
  final String? profileId;

  /// Human-readable detail. For [TunnelStage.failed] this is the failure text
  /// and it is shown verbatim: a tunnel that will not come up is diagnosed from
  /// exactly this string, so it must not be summarised into "an error occurred".
  final String? message;

  static const TunnelStatus idle = TunnelStatus(TunnelStage.disconnected);

  bool get isBusy => stage == TunnelStage.connecting;
  bool get isUp => stage == TunnelStage.connected;

  @override
  String toString() => 'TunnelStatus(${stage.name}, $profileId, $message)';
}

/// Everything an engine needs to bring up one tunnel.
///
/// [importUris] are the `uri`-shaped share items the server emitted, in the
/// order the protocol registry emitted them. The app does NOT pick a protocol
/// or rewrite a URI into a sing-box config: the server owns the credential
/// format (see app/README.md -- two implementations of it drift, and the drift
/// is invisible until somebody's profile stops importing), and sing-box itself
/// is the thing that parses these. Whoever writes the engine decides how a URI
/// becomes an outbound.
class TunnelProfile {
  const TunnelProfile({
    required this.id,
    required this.label,
    required this.host,
    required this.importUris,
  });

  /// Stable per configured server, so [TunnelStatus.profileId] can match it.
  final String id;

  /// Shown in the OS VPN UI, where it is the only clue which tunnel is up.
  final String label;

  final String host;

  final List<String> importUris;

  bool get isConnectable => importUris.isNotEmpty;
}

/// The seam. One implementation per platform family, swapped at composition
/// time in `main.dart`; screens depend on this type only.
abstract class TunnelController {
  /// The last known status. Read synchronously so a screen that is built before
  /// the first stream event has something truthful to draw.
  TunnelStatus get status;

  /// Status changes. Implementations MUST emit the current status to each new
  /// listener before any change, or a screen opened while connected renders as
  /// disconnected until something happens to change it.
  Stream<TunnelStatus> get statusStream;

  /// Brings the tunnel up. Completes when it is up, throws when it is not --
  /// and on failure the stream carries [TunnelStage.failed] with the same text,
  /// so a caller that did not await still learns about it.
  Future<void> connect(TunnelProfile profile);

  /// Tears the tunnel down. Tearing down nothing is not an error.
  Future<void> disconnect();

  /// Drops this device's copy of [profileId]: the VPN configuration the system
  /// installed for it, and whatever the engine persisted to start it with.
  ///
  /// Called when the app forgets a server, and it is not cosmetic. On iOS the
  /// `NETunnelProviderManager` installed at the first connect outlives the
  /// app's own record: deleting a server left a row under Settings > General >
  /// VPN & Device Management that, when somebody flipped it, started the
  /// extension from the saved configuration -- a tunnel to a server the app no
  /// longer knows, on a credential it had stopped showing anybody. The saved
  /// configuration is the credential: a VLESS UUID or a Hysteria2 password, in
  /// clear, in a container the app no longer has a screen for.
  ///
  /// **It revokes nothing.** Those credentials stay valid on the server until
  /// `vpn user rm` runs there; what goes is this device's copy and this
  /// device's ability to use it unattended. Every sentence a person reads
  /// around this has to keep saying so.
  ///
  /// Returns null when the removal was complete or there was nothing to
  /// remove, and a sentence to show otherwise -- a configuration the system
  /// refused to delete is a credential still on the phone, which is worth
  /// interrupting somebody for. It must NOT throw and must not fail on a
  /// platform with nothing of the kind: forgetting a server is the caller's
  /// decision, and a tunnel layer that cannot help may not veto it.
  Future<String?> forgetProfile(String profileId);

  Future<void> dispose();
}

/// Status bookkeeping every implementation needs, so no engine reinvents the
/// replay-on-listen rule that the UI depends on.
abstract class BaseTunnelController implements TunnelController {
  final StreamController<TunnelStatus> _changes =
      StreamController<TunnelStatus>.broadcast();
  TunnelStatus _status = TunnelStatus.idle;

  @override
  TunnelStatus get status => _status;

  @override
  Stream<TunnelStatus> get statusStream async* {
    // Replays the current value to each listener, then follows the broadcast. A
    // plain broadcast stream leaves a freshly built screen blank until the next
    // change, which for an idle tunnel is never.
    yield _status;
    yield* _changes.stream;
  }

  /// For subclasses: record and publish. Never publishes
  /// [TunnelStage.connected] on its own -- only an engine that really brought
  /// an interface up may call this with that stage.
  void emit(TunnelStatus next) {
    _status = next;
    if (!_changes.isClosed) {
      _changes.add(next);
    }
  }

  /// Nothing installed, nothing to forget.
  ///
  /// The default is a no-op because it is the truth for an engine that holds no
  /// system-level profile -- the desktop stub, and Android, where consent is
  /// per-app rather than a configuration and the persisted start request is
  /// deleted when the service stops. An engine that installs one (iOS through
  /// `NETunnelProviderManager`) overrides this and says what it could not
  /// remove.
  @override
  Future<String?> forgetProfile(String profileId) async => null;

  @override
  Future<void> dispose() async {
    await _changes.close();
  }
}
