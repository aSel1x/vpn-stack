// The parts of the transport that need no socket.
//
// Split out for one reason: there is no Dart toolchain on the machine this was
// written on and no server in CI, so anything that can be decided without a
// network should be in a file a test can reach. What is left in
// dartssh2_transport.dart is the key exchange and the channel, which only a
// real server can exercise.

import 'dart:convert';

import '../control/shell.dart';
import '../control/ssh_session.dart';
import '../provision/host_key.dart';
import 'errors.dart';

/// The argument vector as the single command string SSH can carry.
///
/// One line, named, so that the transport visibly does not build a command line
/// of its own: `shell.dart` is the only quoter in this app, because `./vpn`
/// shipped the unquoted version and one argument containing a space silently
/// became two -- which, one layer down, misaligns the space-separated IKEv2
/// user and password lists.
String sshExecLine(List<String> argv) => shellCommand(argv);

/// Enough of a command to recognise it in a failure, and no more.
///
/// Everything `provision/` sends is `sh -c <program>` and those programs run to
/// hundreds of lines; a deadline message carrying one whole is a message nobody
/// reads.
String sshCommandSummary(String command) {
  const int shown = 90;
  final int firstBreak = command.indexOf('\n');
  final String line =
      firstBreak == -1 ? command : command.substring(0, firstBreak);
  return line.length <= shown ? line : '${line.substring(0, shown)}...';
}

/// What the two streams and the exit status add up to.
///
/// stdout and stderr stay apart all the way here, because under `--json` stdout
/// is the payload and `vpnctl`'s own warnings go to stderr: one byte of stderr
/// merged in and the parse fails on a server that did nothing wrong.
CommandResult sshCommandResult({
  required int? exitCode,
  required List<int> stdout,
  required List<int> stderr,
  required String target,
  String? signalName,
}) {
  if (exitCode == null) {
    throw SshNoExitStatus(target: target, signalName: signalName);
  }
  return CommandResult(
    exitCode: exitCode,
    // allowMalformed: a decode that threw here would replace the reason a
    // command failed with a complaint about its own output. `user export`
    // moves binary bundles, base64'd inside JSON, and one truncated payload
    // must not become an unreadable failure.
    stdout: utf8.decode(stdout, allowMalformed: true),
    stderr: utf8.decode(stderr, allowMalformed: true),
  );
}

/// The host key as this transport is able to know it.
///
/// **The blob is the fingerprint.** dartssh2 hands its verification callback
/// the key TYPE and an OpenSSH-style `SHA256:...` fingerprint, and never the
/// wire blob -- it is a local in `SSHTransport._handleMessageKexReply` and no
/// public member exposes it. So `SshHostKey.sameKeyAs`, which compares the
/// blob, is a SHA-256 comparison here rather than a comparison of the key
/// itself. That is the arrangement host_key.dart's header describes and bounds:
/// SHA-256 is second-preimage resistant, so "the same fingerprint" is "the same
/// key" for anybody who cannot break it, and the party that computed it is the
/// same transport that had just verified the host's signature over that same
/// key -- there is no third party left to disagree with. What it costs is a pin
/// nothing else can read: it is not a known_hosts line and cannot be made into
/// one. Anything stronger needs a different SSH library.
///
/// It is written as blob == fingerprint deliberately: a real wire blob can
/// never equal the fingerprint string, so a stored pin from this transport is
/// recognisable for whatever has to migrate it if that library ever arrives.
SshHostKey sshHostKeyFrom(String algorithm, List<int> fingerprint) {
  final String printed = utf8.decode(fingerprint, allowMalformed: true);
  return SshHostKey(
    algorithm: algorithm,
    blob: printed,
    fingerprint: printed,
  );
}

/// Fails [work] with a sentence naming [phase] when [limit] elapses.
///
/// `Future.timeout` stops waiting; it cannot stop the far side. That is fine
/// here because every caller of this abandons the connection afterwards, and a
/// spinner that never ends is the failure being avoided.
Future<T> withSshDeadline<T>(
  Future<T> work, {
  required Duration limit,
  required String phase,
  required String target,
}) {
  return work.timeout(
    limit,
    onTimeout: () => throw SshDeadlineExceeded(
      phase: phase,
      limit: limit,
      target: target,
    ),
  );
}

/// Runs a shutdown exactly once, however many times [close] is called.
///
/// `SshConnection.close()` is called from `finally` blocks, from
/// `_closeQuietly` and again from `closePrimary`, so closing twice is ordinary
/// rather than exceptional. The second call gets the first call's future: same
/// answer, one socket closed, no second close of a descriptor that may by then
/// belong to something else.
class CloseOnce {
  Future<void>? _closing;

  /// True from the moment [close] is first called, not when it finishes: a
  /// command started during the close would be running on a connection that is
  /// already going away.
  bool get isClosed => _closing != null;

  Future<void> close(Future<void> Function() shutdown) =>
      _closing ??= shutdown();
}

int _transports = 0;

/// A new identity for every TCP connection this transport opens.
///
/// The firewall step compares these to refuse its own connection as a proof: a
/// multiplexed channel rides an established conntrack entry, which survives a
/// firewall that would reject every new connection. Minted at the one place
/// that calls `SSHSocket.connect`, so an id names exactly one TCP handshake.
String nextSshTransportId(String host, int port) {
  _transports++;
  return 'tcp-$_transports $host:$port';
}
