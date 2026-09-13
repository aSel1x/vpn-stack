// What this layer needs from SSH that lib/control/ does not already define.
//
// The exec abstraction is control's and is imported, not restated:
// `SshSession.run(argv) -> CommandResult`. Two connect/exec abstractions over
// one ssh client is how an app ends up with two different ideas of what a
// failed command looks like, and this file used to be exactly that.
//
// Two things live here that control/ has no use for:
//
//   - `SshConnector`, because the firewall step has to open a SECOND,
//     INDEPENDENT connection to prove the rules it just installed did not lock
//     us out. That is the whole reason this layer exists instead of one ssh
//     call, and it cannot be trimmed as surplus.
//   - `HostKeyPolicy`, because connecting is where a host key is decided and
//     nothing else in this app is in a position to decide it. dartssh2 accepts
//     any key unless it is told not to.

import 'dart:async';

import '../control/ssh_session.dart';
import 'host_key.dart';

export '../control/ssh_session.dart' show CommandResult, SshSession;
export 'host_key.dart';

/// One connection this layer opened and is therefore responsible for closing.
///
/// Lifecycle and identity only: running commands is [session]'s job, which is
/// control's interface unchanged.
abstract class SshConnection {
  /// The session to run commands on. Bound to this connection: when [close] has
  /// run, this stops working.
  SshSession get session;

  /// Identity of the underlying transport connection.
  ///
  /// The firewall step compares this against the connection it already holds,
  /// because a "fresh" connection that is really a second channel on the same
  /// TCP connection proves nothing: an established conntrack entry survives a
  /// firewall that would reject every new connection. Any two values that
  /// differ mean two transports; equal values mean the connector pooled, and
  /// the step treats that as a failure to prove rather than as success.
  String get transportId;

  /// The host key this connection was established against.
  ///
  /// Required, not optional: a connector that cannot say which key it accepted
  /// cannot have checked it, and this is the member that makes that impossible
  /// to skip quietly. It is also what lets the firewall step notice that its
  /// prover reached a *different machine* than the one it just firewalled.
  SshHostKey get hostKey;

  Future<void> close();
}

/// Opens connections to one server.
abstract class SshConnector {
  /// A NEW connection every call: new TCP handshake, new SSH transport, new
  /// authentication.
  ///
  /// Implementations must not pool, cache or multiplex here. This is the
  /// interface-level equivalent of install.sh's `-o ControlMaster=no
  /// -o ControlPath=none`, and getting it wrong disarms the deadman on a server
  /// nobody can reach any more -- which is a lockout with no recovery, not a
  /// failed install.
  ///
  /// [hostKeys] decides the server's key and MUST be applied during the key
  /// exchange, BEFORE authentication -- before a password or a private key
  /// leaves this device. There are two ways to satisfy that, and the second is
  /// the one to use when the client's verification callback is synchronous,
  /// because a human cannot be asked from inside a key exchange:
  ///
  ///   - `await hostKeys.verify(offered)` and connect only if it returns; or
  ///   - call the synchronous [HostKeyPolicy.accepts] during the exchange,
  ///     abort the handshake when it is false, and throw [HostKeyUnknownError]
  ///     carrying the offered key. [openVerified] answers the question and
  ///     connects again. Nothing was authenticated, so nothing was disclosed.
  ///
  /// When a key is pinned, offer that algorithm first. A server holding both an
  /// ed25519 and an RSA host key presents whichever the client asked for, and a
  /// client that asks for the other one makes every connection look like a key
  /// that changed.
  Future<SshConnection> connect(HostKeyPolicy hostKeys);
}

/// What this device already knows about one server's host key, and how to ask
/// about one it does not.
///
/// Stateful on purpose: a key trusted once is trusted for the rest of the run,
/// so the firewall step's prover does not re-ask about the key the primary
/// connection was established against thirty seconds earlier.
class HostKeyPolicy {
  /// Accept this key and nothing else, and never ask. For a server whose key
  /// the store already holds.
  HostKeyPolicy.pinned({required this.target, required SshHostKey key})
      : _pinned = key,
        _prompt = null,
        _remember = null;

  /// The general case: what is pinned (null the first time this server is
  /// reached), who to ask, and where to put the answer.
  HostKeyPolicy.ask({
    required this.target,
    required HostKeyPrompt this._prompt,
    this._pinned,
    this._remember,
  });

  /// Refuses every key. The policy a caller that forgot to plumb one should
  /// get: it fails closed, by name, instead of connecting to anything.
  HostKeyPolicy.refuse({required this.target})
      : _pinned = null,
        _prompt = null,
        _remember = null;

  /// `root@203.0.113.7:22`, for the question and for every failure message.
  final String target;

  SshHostKey? _pinned;
  final HostKeyPrompt? _prompt;
  final HostKeyRecorder? _remember;

  /// The key this policy currently accepts, if any. Changes when a human
  /// trusts one.
  SshHostKey? get pinned => _pinned;

  /// Pure, synchronous, and safe to call from inside a key exchange: is this
  /// the key we already decided about?
  ///
  /// It is deliberately *not* "is this key fine" -- it never says yes to a key
  /// nobody has approved. The asking is [verify]'s job, which can await.
  bool accepts(SshHostKey offered) {
    final SshHostKey? pin = _pinned;
    return pin != null && pin.sameKeyAs(offered);
  }

  /// Returns normally when [offered] may be used, throws [HostKeyRejectedError]
  /// when it may not.
  ///
  /// Asks at most one human question and remembers the answer, so the second
  /// connection of a run is silent.
  Future<void> verify(SshHostKey offered) async {
    if (accepts(offered)) {
      return;
    }
    final HostKeyQuestion question = HostKeyQuestion(
      target: target,
      offered: offered,
      pinned: _pinned,
    );
    final HostKeyPrompt? ask = _prompt;
    if (ask == null) {
      // No prompt and no matching pin. Refusing is the whole point of the
      // type: the alternative is accepting whatever answered.
      throw HostKeyRejectedError(question: question, asked: false);
    }
    final HostKeyDecision decision = await ask(question);
    if (decision == HostKeyDecision.refuse) {
      throw HostKeyRejectedError(question: question, asked: true);
    }
    _pinned = offered;
    if (decision == HostKeyDecision.trust) {
      final HostKeyRecorder? remember = _remember;
      if (remember != null) {
        await remember(offered);
      }
    }
  }
}

/// Opens one connection, answering a host key question at most once.
///
/// Every connection this layer opens goes through here -- the primary one and
/// the firewall step's prover alike -- so there is one place where "did anybody
/// approve this key" is asked, and no path around it.
Future<SshConnection> openVerified(
  SshConnector connector,
  HostKeyPolicy hostKeys, {
  Duration? timeout,
}) async {
  final SshConnection connection =
      await _openAnswering(connector, hostKeys, timeout);
  if (!hostKeys.accepts(connection.hostKey)) {
    // A promise in a doc comment is not a check -- the same reason the firewall
    // step compares transport ids rather than trusting a connector not to pool.
    // Reaching here means the transport authenticated against a key nobody
    // approved, and the credential is already gone.
    await _closeQuietly(connection);
    throw HostKeyPolicyIgnoredError(
      offered: connection.hostKey,
      target: hostKeys.target,
    );
  }
  return connection;
}

Future<SshConnection> _openAnswering(
  SshConnector connector,
  HostKeyPolicy hostKeys,
  Duration? timeout,
) async {
  try {
    return await _connect(connector, hostKeys, timeout);
  } on HostKeyUnknownError catch (unknown) {
    // The connector could not ask from inside the key exchange, so it aborted
    // before authentication. Answer, then connect again: verify() throws
    // HostKeyRejectedError if the answer was no, and this returns nothing.
    await hostKeys.verify(unknown.question.offered);
    return _connect(connector, hostKeys, timeout);
  }
}

Future<SshConnection> _connect(
  SshConnector connector,
  HostKeyPolicy hostKeys,
  Duration? timeout,
) {
  final Future<SshConnection> opening = connector.connect(hostKeys);
  return timeout == null ? opening : opening.timeout(timeout);
}

Future<void> _closeQuietly(SshConnection connection) async {
  try {
    await connection.close();
  } on Object catch (_) {
    // Already throwing about the key. A close that also fails changes nothing
    // about what has to be said.
    return;
  }
}

/// Small conveniences on control's result type, kept here so control does not
/// grow an opinion it has no use for.
extension ProvisionCommandOutput on CommandResult {
  bool get ok => exitCode == 0;

  /// Both streams, for a failure report. apt writes its errors to stderr and
  /// vpnctl puts every human line there under `--json`, so a message built from
  /// stdout alone describes a failure by saying nothing at all.
  String get combined {
    final List<String> parts = <String>[];
    if (stdout.trim().isNotEmpty) parts.add(stdout.trim());
    if (stderr.trim().isNotEmpty) parts.add(stderr.trim());
    return parts.join('\n');
  }
}
