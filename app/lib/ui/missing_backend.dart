import 'dart:typed_data';

import '../provision/ssh.dart';
import 'ports.dart';

/// The ports nothing implements yet, implemented honestly.
///
/// Both throw, and the throw names what is missing. That is the same rule
/// `UnimplementedTunnel` follows and for the same reason: a placeholder that
/// returns a plausible answer is indistinguishable from a working app until
/// somebody acts on it.
///
/// [MissingSshTransport] is the one that matters. `control/` and `provision/`
/// are complete and take their transport injected; nothing here speaks SSH.
/// Note where the failure lands: [connectorFor] succeeds and [SshConnector.connect]
/// is what throws, so the failure arrives on the ordinary path -- the
/// provisioning screen fails on its first step, named, and the server screen
/// shows it in its error banner. Exactly where a real connection failure will.
///
/// It throws before the key exchange, so nobody ever sees the host key
/// question against this transport. That is honest rather than convenient: the
/// question belongs to a handshake that never happened.

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

  /// [hostKeys] is the question this placeholder never gets to ask.
  ///
  /// Whoever writes the real connector must apply it during the key exchange,
  /// BEFORE authentication: either await `hostKeys.verify(offered)`, or call
  /// the synchronous `hostKeys.accepts(offered)` from the verification callback
  /// and throw `HostKeyUnknownError` when it is false, which is the path
  /// dartssh2 forces because its callback cannot wait for a human. A connector
  /// that authenticates first and checks afterwards has already sent the
  /// password.
  @override
  Future<SshConnection> connect(HostKeyPolicy hostKeys) {
    throw UnimplementedError(
      'No SSH transport. Reaching ${hostKeys.target} needs an SshConnector '
      'backed by a real SSH client -- dartssh2 is in pubspec.yaml for exactly '
      'this and nothing in lib/ implements it yet. Everything above it is in '
      'place: control/ builds the vpnctl argv and parses the JSON, provision/ '
      'owns the step sequence, this app decides the host key, and all three '
      'take the transport injected.\n'
      'Nothing was sent: the ${credential.describe} for ${server.target} never '
      'left this device, and no host key was accepted -- there was no '
      'handshake to accept one in. The credential is held in memory until the '
      'app quits or you pick "Forget SSH credential" on the server.',
    );
  }
}

class MissingFileSaver implements FileSaver {
  const MissingFileSaver();

  @override
  Future<String> save(String filename, Uint8List bytes) {
    throw UnimplementedError(
      'Cannot write $filename (${bytes.length} bytes): this app has no file '
      'picker. Saving needs one of file_selector, share_plus or path_provider '
      'in pubspec.yaml, and none of them is there. Until then, copy the '
      'profile off the server with `./vpn user export`.',
    );
  }
}
