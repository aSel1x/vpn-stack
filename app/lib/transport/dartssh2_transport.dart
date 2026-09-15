// SSH, for real, over dartssh2.
//
// Pure Dart, so provision/ and control/ run unchanged on all five targets with
// no platform channel. Three properties this file exists to get right, each
// because the layer above it already decided it cannot check them itself:
//
//   - The host key is decided DURING the key exchange. dartssh2 calls
//     `onVerifyHostKey` from `SSHTransport._handleMessageKexReply`, before it
//     sends NEWKEYS and therefore before any userauth message exists; refusing
//     there means the root password this app asks for on its second screen has
//     not been sent to whatever answered. With no handler it accepts every key,
//     which is the default this file must never fall back to.
//   - Every connect() is a new TCP connection: a new `SSHSocket.connect`, a new
//     SSHClient, a new authentication, and an id that says so. No pooling. The
//     firewall step's proof is worthless otherwise.
//   - Nothing logs a credential. `printDebug`/`printTrace` are deliberately not
//     wired: dartssh2 4.0.0's changelog records fixing keyboard-interactive
//     responses appearing in plaintext logs, which is what a trace handler is.
//
// Verified against dartssh2 4.1.0's own source, not from memory; the pin in
// pubspec.yaml is exact for that reason.

import 'dart:async';

import 'package:dartssh2/dartssh2.dart';

import '../provision/ssh.dart';
import '../ui/ports.dart';
import 'errors.dart';
import 'exec.dart';

/// The app's SSH transport.
class Dartssh2Transport implements SshTransport {
  const Dartssh2Transport({
    this.connectTimeout = const Duration(seconds: 30),
    this.commandTimeout = const Duration(minutes: 30),
  });

  /// Applied twice and separately -- once to the TCP connection, once to the
  /// handshake and authentication -- so the failure names which one elapsed.
  /// The firewall prover passes its own, shorter bound through `openVerified`.
  final Duration connectTimeout;

  /// A backstop against a channel that dies without closing, not a quality of
  /// service: the bounds that matter are at the call sites (`flock -w`,
  /// `proveTimeout`). Generous because a first `vpnctl apply` waits 240s for
  /// the ipsec container and `protocol on dnstt` builds an ~800 MB Go image on
  /// whatever small VPS this is -- killing either halfway leaves a server
  /// mid-converge, which is worse than a long wait with a step name on screen.
  final Duration commandTimeout;

  @override
  SshConnector connectorFor(ServerProfile server, SshCredential credential) {
    // Cheap and must not throw, per ports.dart: a PEM that will not parse fails
    // at connect(), which is the path that already shows failures. Throwing
    // here would take out the screen that was about to display the reason.
    return Dartssh2Connector(
      host: server.host,
      port: server.sshPort,
      username: server.sshUser,
      target: server.sshTarget,
      credential: credential,
      connectTimeout: connectTimeout,
      commandTimeout: commandTimeout,
    );
  }
}

/// Opens connections to one server with one credential.
///
/// It holds the credential for as long as it exists, and that is not an
/// oversight: `connect()` promises a NEW authentication every call, so the
/// secret has to survive the first one. Its lifetime is the connector's, the
/// connector's is `ServerAccess`'s, and what ends that is the vault -- quitting
/// the app, or "Forget SSH credential". Nothing here writes it anywhere, logs
/// it, or puts it in a message; `printDebug`/`printTrace` stay unwired for that
/// reason. What cannot be done is scrubbing it: a Dart String is immutable and
/// there is no buffer to overwrite.
class Dartssh2Connector implements SshConnector {
  Dartssh2Connector({
    required this.host,
    required this.port,
    required this.username,
    required this.target,
    required this.credential,
    this.connectTimeout = const Duration(seconds: 30),
    this.commandTimeout = const Duration(minutes: 30),
  });

  final String host;
  final int port;
  final String username;

  /// `root@203.0.113.7:22`, for every message this connector produces.
  final String target;

  final SshCredential credential;
  final Duration connectTimeout;
  final Duration commandTimeout;

  @override
  Future<SshConnection> connect(HostKeyPolicy hostKeys) async {
    // Before the socket: an unreadable key should cost nothing, and its failure
    // should not look like the server's.
    final List<SSHIdentity>? identities = _identities();

    final SSHSocket socket = await _openSocket();
    final String transportId = nextSshTransportId(host, port);
    final HostKeyGate gate = HostKeyGate(policy: hostKeys, target: target);

    final SSHClient client = SSHClient(
      socket,
      username: username,
      algorithms: _algorithms(hostKeys.pinned),
      // The whole reason this file is careful. Without it dartssh2 accepts any
      // host key.
      onVerifyHostKey: gate.verify,
      identities: identities,
      onPasswordRequest: _password(),
    );
    // `closeWithError` completes `done` with an error -- which is exactly what
    // a refused host key does -- and an error nobody is listening for is an
    // unhandled async error on a phone. `authenticated` below is a different
    // completer and does not cover it.
    unawaited(client.done.catchError((Object _) {}));

    try {
      await withSshDeadline(
        client.authenticated,
        limit: connectTimeout,
        phase: 'the SSH handshake and authentication',
        target: target,
      );
    } on Object catch (error) {
      await _abandon(client);
      final HostKeyQuestion? question = gate.question;
      if (gate.refused && question != null) {
        // The exchange was aborted where the key is decided, before userauth
        // could begin, so nothing was sent. `openVerified` asks the human and
        // connects again -- which is the second of the two shapes
        // SshConnector.connect documents. Chosen, not forced: dartssh2 4.x
        // AWAITS this handler, so a human could in principle be asked from
        // inside the exchange. HostKeyGate says why that is a bad idea --
        // sshd's LoginGraceTime bounds the pre-auth window and a person
        // reading a fingerprint off a console is not bounded.
        throw HostKeyUnknownError(question: question);
      }
      throw asSshFailure(
        error,
        target: target,
        credential: credential.describe,
      );
    }

    final SshHostKey? approved = gate.offered;
    if (approved == null) {
      // Unreachable while `disableHostkeyVerification` stays false, and stated
      // anyway: a connection that cannot name the key it accepted has not
      // checked one, and openVerified would have to take this file's word for
      // it.
      await _abandon(client);
      throw SshConnectFailure(
        target: target,
        cause: StateError(
          'the handshake finished without presenting a host key, which means '
          'verification was skipped',
        ),
      );
    }

    return _Dartssh2Connection(
      client: client,
      transportId: transportId,
      hostKey: approved,
      target: target,
      credentialLabel: credential.describe,
      commandTimeout: commandTimeout,
    );
  }

  Future<SSHSocket> _openSocket() async {
    try {
      return await withSshDeadline(
        SSHSocket.connect(host, port, timeout: connectTimeout),
        limit: connectTimeout,
        phase: 'the TCP connection',
        target: target,
      );
    } on Object catch (error) {
      throw asSshFailure(
        error,
        target: target,
        credential: credential.describe,
      );
    }
  }

  /// The private key, parsed, or null for a password credential.
  /// Does the PEM text itself say it is encrypted?
  ///
  /// Guarded, because this is called from inside a catch block and
  /// `isEncryptedPem` parses: on text that is not a PEM at all it throws, and
  /// an exception raised while handling one replaces it -- which turned two
  /// credential failures into whatever dartssh2 threw second. Unparseable is
  /// not encrypted; claiming otherwise sends somebody hunting for a passphrase
  /// that does not exist.
  bool _declaresEncryption(String pem) {
    try {
      return SSHKeyPair.isEncryptedPem(pem);
    } on Object {
      return false;
    }
  }

  List<SSHIdentity>? _identities() {
    final SshCredential given = credential;
    if (given is! SshPrivateKey) {
      return null;
    }
    final String? passphrase = given.passphrase;
    final List<SSHKeyPair> keys;
    try {
      keys = SSHKeyPair.fromPem(
        given.pem,
        passphrase == null || passphrase.isEmpty ? null : passphrase,
      );
    } on Object catch (error) {
      // Not `error is SSHKeyDecryptError`: dartssh2 throws that for three
      // cases and only two are about encryption -- 'Private key is encrypted',
      // 'Invalid passphrase', and 'Invalid private key', which is a malformed
      // key that has no passphrase at all. Diagnosing the third as encrypted
      // tells somebody to supply a passphrase for a key that does not have one.
      // isEncryptedPem is a pure function of the text and answers the question
      // actually being asked.
      throw SshCredentialUnusable(
        target: target,
        encrypted: _declaresEncryption(given.pem),
        cause: error,
      );
    }
    if (keys.isEmpty) {
      throw SshCredentialUnusable(
        target: target,
        encrypted: false,
        cause: const FormatException('no private key was found in it'),
      );
    }
    return keys;
  }

  /// Handed to dartssh2, which calls it during userauth -- and userauth cannot
  /// begin until the gate above accepted the host key.
  SSHPasswordRequestHandler? _password() {
    final SshCredential given = credential;
    if (given is! SshPassword) {
      return null;
    }
    return () => given.password;
  }

  /// Ask for the pinned algorithm first.
  ///
  /// A server holding both an ed25519 and an RSA host key presents whichever
  /// the client asked for, so a client that asks in a different order than last
  /// time makes an unchanged server look like a key that changed -- which
  /// access.dart refuses outright, by design.
  SSHAlgorithms _algorithms(SshHostKey? pin) {
    const SSHAlgorithms defaults = SSHAlgorithms();
    if (pin == null) {
      return defaults;
    }
    // Read out of the defaults rather than restated: a list written here would
    // drift from the package's the first time it drops an algorithm, and 4.0.0
    // dropped three.
    final List<SSHHostkeyType> preferred = <SSHHostkeyType>[
      ...defaults.hostkey.where((SSHHostkeyType t) => t.name == pin.algorithm),
      ...defaults.hostkey.where((SSHHostkeyType t) => t.name != pin.algorithm),
    ];
    return SSHAlgorithms(hostkey: preferred);
  }

  Future<void> _abandon(SSHClient client) async {
    try {
      // Closes the transport, which closes the socket: no descriptor is left
      // behind by a connection that failed to authenticate.
      await client.close();
    } on Object catch (_) {
      // Already reporting a failure. A close that also fails changes nothing
      // about what has to be said.
      return;
    }
  }
}

/// Applies the host key policy at the only moment that helps.
///
/// Synchronous on purpose. dartssh2 4.x awaits this handler, so a human COULD
/// be asked from inside the key exchange -- but the pre-authentication window
/// is bounded by sshd's LoginGraceTime (120s by default) and somebody reading a
/// fingerprint off a provider's console is not bounded by anything. So this
/// answers only what the policy can answer with nobody present, and a refusal
/// becomes `HostKeyUnknownError`, which `openVerified` answers and then
/// connects again. Nothing was authenticated in between, so nothing leaked.
class HostKeyGate {
  HostKeyGate({required this.policy, required this.target});

  final HostKeyPolicy policy;
  final String target;

  SshHostKey? _offered;
  bool _refused = false;

  /// dartssh2's `SSHHostkeyVerifyHandler`: the key type and an OpenSSH-style
  /// `SHA256:` fingerprint, which is everything it is willing to hand over.
  bool verify(String type, List<int> fingerprint) {
    final SshHostKey offered = sshHostKeyFrom(type, fingerprint);
    _offered = offered;
    final bool known = policy.accepts(offered);
    _refused = !known;
    return known;
  }

  /// The key the server presented, whether or not it was accepted. Null until
  /// the exchange got that far.
  SshHostKey? get offered => _offered;

  /// True when [verify] turned a key down, which is what makes an abandoned
  /// handshake a question rather than a failure.
  bool get refused => _refused;

  /// What to ask the human. Null before a key was presented.
  HostKeyQuestion? get question {
    final SshHostKey? seen = _offered;
    if (seen == null) {
      return null;
    }
    return HostKeyQuestion(
      target: target,
      offered: seen,
      pinned: policy.pinned,
    );
  }
}

/// One authenticated connection, and the session that runs on it.
///
/// Both interfaces on one object because they have one lifetime: `close()` has
/// to stop the session, and a session that outlived its connection would fail
/// somewhere dartssh2 chooses rather than here.
class _Dartssh2Connection implements SshConnection, SshSession {
  _Dartssh2Connection({
    required this._client,
    required this.transportId,
    required this.hostKey,
    required this.target,
    required this.credentialLabel,
    required this.commandTimeout,
  });

  final SSHClient _client;
  final String target;

  /// The word `SshCredential.describe` returned, never the secret: this object
  /// outlives the connect that authenticated and has no use for the credential
  /// itself.
  final String credentialLabel;
  final Duration commandTimeout;
  final CloseOnce _lifetime = CloseOnce();

  @override
  final String transportId;

  @override
  final SshHostKey hostKey;

  @override
  SshSession get session => this;

  @override
  Future<CommandResult> run(List<String> argv) {
    if (_lifetime.isClosed) {
      throw SshSessionClosed(target: target);
    }
    final String command = sshExecLine(argv);
    return withSshDeadline(
      _exec(command),
      limit: commandTimeout,
      phase: 'the command `${sshCommandSummary(command)}`',
      target: target,
    );
  }

  Future<CommandResult> _exec(String command) async {
    final SSHSession remote;
    try {
      remote = await _client.execute(command);
    } on Object catch (error) {
      throw asSshFailure(error, target: target, credential: credentialLabel);
    }

    final List<int> out = <int>[];
    final List<int> err = <int>[];
    try {
      // EOF on stdin at once, the way `ssh -n` does. Nothing this app runs
      // reads stdin, and one that waited for it would hang until the deadline.
      // Not awaited: the acknowledgement travels with the channel's own close,
      // so waiting here would deadlock against the streams below.
      unawaited(remote.stdin.close().catchError((Object _) {}));
      // Separately, and both to completion: stdout carries the `--json`
      // payload and stderr carries everything vpnctl says to a human, and the
      // parse fails on the server that did nothing wrong if they are merged.
      await Future.wait(<Future<void>>[
        remote.stdout.forEach(out.addAll),
        remote.stderr.forEach(err.addAll),
      ]);
      await remote.done;
    } on Object catch (error) {
      remote.close();
      throw asSshFailure(error, target: target, credential: credentialLabel);
    }

    return sshCommandResult(
      exitCode: remote.exitCode,
      stdout: out,
      stderr: err,
      target: target,
      signalName: remote.exitSignal?.signalName,
    );
  }

  @override
  Future<void> close() => _lifetime.close(_client.close);
}
