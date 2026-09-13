import 'dart:async';

/// Establishing the tunnel on THIS device.
///
/// The UI talks to [TunnelController] and to nothing else, so a real engine --
/// libbox on Android and iOS, a privileged helper on desktop -- drops in behind
/// this interface without a screen changing. That is the only thing this layer
/// has to get right today, because the engine itself is not here yet.
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

  @override
  Future<void> dispose() async {
    await _changes.close();
  }
}
