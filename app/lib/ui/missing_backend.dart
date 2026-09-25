import '../provision/ssh.dart';
import 'ports.dart';

/// The SSH transport for a platform where the real one cannot run.
///
/// `transport/dartssh2_transport.dart` is the implementation this app wires:
/// pure Dart, so it runs on every target without a platform channel, and
/// `lib/main.dart` hands it to every screen. This is the fallback for a target
/// where that stops being true, and it is kept in the tree rather than deleted
/// because the shape of an honest fallback is worth having written down: it
/// throws, and the throw names what is missing and what was not sent.
///
/// A placeholder that returns a plausible answer is indistinguishable from a
/// working app until somebody acts on it. That is the same rule
/// `UnimplementedTunnel` follows, for the same reason.
///
/// Note where the failure lands: [connectorFor] succeeds and
/// [SshConnector.connect] is what throws, so the failure arrives on the
/// ordinary path -- the provisioning screen fails on its first step, named, and
/// the server screen shows it in its error banner. Exactly where a real
/// connection failure does.
///
/// It throws before the key exchange, so nobody ever sees the host key question
/// against this transport. That is honest rather than convenient: the question
/// belongs to a handshake that never happened.
///
/// It has no sibling for [FileSaver], and that asymmetry is deliberate. A saver
/// that always threw would put a Share button on every IKEv2 bundle and fail on
/// press, which is an offer of something impossible; the screens read
/// `FileSaver` as a nullable provider instead, so a platform with no way to hand
/// a file out registers none and the button is never drawn. A transport has no
/// such option: a server screen with no way to reach the server is not a screen,
/// so here the failure has to be sayable.

class MissingSshTransport implements SshTransport {
  const MissingSshTransport();

  @override
  SshConnector connectorFor(ServerProfile server, SshCredential credential) =>
      _MissingConnector(server, credential);
}

class _MissingConnector implements SshConnector {
  const _MissingConnector(this.server, this.credential);

  final ServerProfile server;
  final SshCredential credential;

  /// [hostKeys] is the question this fallback never gets to ask.
  ///
  /// The real connector applies it during the key exchange, BEFORE
  /// authentication: `Dartssh2Connector` calls the synchronous
  /// `hostKeys.accepts(offered)` from dartssh2's verification callback and
  /// throws `HostKeyUnknownError` when it is false, which is the path dartssh2
  /// forces because that callback cannot wait for a human. A connector that
  /// authenticated first and checked afterwards would already have sent the
  /// password.
  @override
  Future<SshConnection> connect(HostKeyPolicy hostKeys) {
    throw UnimplementedError(
      'No SSH transport on this platform. Reaching ${hostKeys.target} needs an '
      'SshConnector, and the one this app ships -- '
      'transport/dartssh2_transport.dart -- was not wired here. Everything '
      'above it is in place: control/ builds the vpnctl argv and parses the '
      'JSON, provision/ owns the step sequence, this app decides the host key, '
      'and all three take the transport injected.\n'
      'Nothing was sent: the ${credential.describe} for ${server.target} never '
      'left this device, and no host key was accepted -- there was no '
      'handshake to accept one in. The credential is held in memory until the '
      'app quits or you pick "Forget SSH credential" on the server.',
    );
  }
}
