// What a person reads when SSH fails.
//
// `ProvisionTransportError.cause` and `VpnctlTransportError.cause` are both
// `Object` on purpose -- neither layer may know dartssh2's types -- and both
// render it straight into their own sentence with `'$cause'`. dartssh2's errors
// render as `SSHAuthFailError(All authentication methods failed)`: a class name
// and a fragment, with no target, no port and nothing to do next. So everything
// this transport throws is one sentence, already fit to be embedded in theirs.
//
// Nothing here ever carries a password, a passphrase or a private key. A
// credential appears only as the word `SshCredential.describe` returns
// ("password", "private key"), which is the type's whole purpose.

import 'package:dartssh2/dartssh2.dart';

sealed class SshTransportFailure implements Exception {
  const SshTransportFailure(this.message);

  /// One sentence, already fit to put in front of a human.
  final String message;

  @override
  String toString() => message;
}

/// The TCP connection or the SSH handshake never got as far as a session.
final class SshConnectFailure extends SshTransportFailure {
  SshConnectFailure({required this.target, required this.cause})
      : super('could not open an SSH connection to $target: '
            '${describeSshCause(cause)}');

  /// Which server, named. Every sibling in this family declares it; this one
  /// was the only class where the initializing formal had no field to name, so
  /// the whole library failed to compile.
  final String target;

  final Object cause;
}

/// The server answered, the host key was approved, and the credential was
/// refused.
///
/// Said separately from [SshConnectFailure] because the remedy is different:
/// this is a user name or a credential, not a network or a firewall.
final class SshAuthFailure extends SshTransportFailure {
  SshAuthFailure({
    required this.target,
    required this.credential,
    required this.cause,
  }) : super('$target refused the $credential. The host key was checked and '
            'accepted before it was sent, so it went to the machine you '
            'approved -- check the user name and the credential themselves '
            '(${describeSshCause(cause)}).');

  final Object cause;

  /// `SshCredential.describe`, never the secret.
  final String credential;
  final String target;
}

/// The private key this device holds cannot be used.
///
/// Raised before the socket is opened: a PEM that will not parse should not
/// cost a connection, and it must not arrive looking like a server problem.
final class SshCredentialUnusable extends SshTransportFailure {
  SshCredentialUnusable({
    required this.target,
    required this.encrypted,
    required this.cause,
  }) : super(encrypted
            ? 'the private key for $target could not be decrypted: '
                '${describeSshCause(cause)}. It is passphrase-protected and '
                'the passphrase is missing or wrong. Nothing was sent.'
            : 'the private key for $target could not be read: '
                '${describeSshCause(cause)}. Nothing was sent.');

  final Object cause;
  final String target;

  /// Whether the PEM text itself declares encryption, from
  /// `SSHKeyPair.isEncryptedPem`, not from the exception type. dartssh2
  /// throws `SSHKeyDecryptError` for a malformed key with no passphrase as
  /// well as for a real one, and reading the type told people to supply a
  /// passphrase for keys that do not have one.
  final bool encrypted;
}

/// One phase ran out of time, and the message says which.
///
/// A phone showing a spinner for ever is indistinguishable from a crash, and
/// "the connection failed" does not say whether the box is unreachable, slow to
/// answer, or busy running the command.
final class SshDeadlineExceeded extends SshTransportFailure {
  SshDeadlineExceeded({
    required this.phase,
    required this.limit,
    required this.target,
  }) : super('$phase to $target did not finish within ${limit.inSeconds}s.');

  /// "the TCP connection", "the SSH handshake and authentication", "the
  /// command `...`". Reads as the subject of the sentence above.
  final String phase;

  final Duration limit;
  final String target;
}

/// A command was run on a connection that has been closed.
///
/// Its own failure rather than whatever dartssh2 does with a closed client,
/// because `SshConnection.close()` promises the session stops working and a
/// promise that hangs instead of failing is worse than no promise.
final class SshSessionClosed extends SshTransportFailure {
  SshSessionClosed({required this.target})
      : super('this SSH connection to $target has been closed; nothing can be '
            'run on it. Open a new one.');

  final String target;
}

/// The remote process ended without reporting an exit status.
///
/// `CommandResult.exitCode` is an `int` and every caller in this app decides on
/// it, so inventing one would be inventing the answer. A process killed by a
/// signal (the OOM killer during `uv sync` is the realistic one) reports a
/// signal and no status.
final class SshNoExitStatus extends SshTransportFailure {
  SshNoExitStatus({required this.target, required this.signalName})
      : super(signalName == null
            ? 'the command on $target ended without an exit status, so whether '
                'it did its work is unknown.'
            : 'the command on $target was killed by SIG$signalName and never '
                'reported an exit status, so whether it did its work is '
                'unknown.');

  final String target;

  /// Without the leading `SIG`, as dartssh2 reports it. Null when the remote
  /// said nothing at all.
  final String? signalName;
}

/// Turns whatever dartssh2 threw into one of the above.
///
/// Anything already ours passes through untouched: the deadline wrapper throws
/// [SshDeadlineExceeded] from inside the same `try`, and re-wrapping it would
/// bury the one thing it knows -- which phase ran out.
SshTransportFailure asSshFailure(
  Object error, {
  required String target,
  String credential = 'credential',
}) {
  if (error is SshTransportFailure) {
    return error;
  }
  if (error is SSHAuthFailError) {
    return SshAuthFailure(
      target: target,
      credential: credential,
      cause: error,
    );
  }
  return SshConnectFailure(target: target, cause: error);
}

/// The readable half of a dartssh2 error.
///
/// `SSHSocketError` holds the real exception in a field and does not put it in
/// its own name, and `SSHAuthAbortError` carries the reason the transport died
/// separately from its message -- which is where "Hostkey verification failed"
/// and "Connection refused" actually live. Printing either directly loses the
/// only sentence worth reading.
String describeSshCause(Object error) {
  if (error is SSHSocketError) {
    return describeSshCause(error.error);
  }
  if (error is SSHAuthAbortError) {
    final SSHError? reason = error.reason;
    return reason == null
        ? error.message
        : '${error.message}: ${describeSshCause(reason)}';
  }
  if (error is SSHMessageError) {
    return error.message;
  }
  if (error is FormatException) {
    // `$error` is not safe here. FormatException.toString() prints a window of
    // `source` around `offset`, and on the path that matters the source is the
    // PEM body: dartssh2's SSHPem.decode calls base64.decode with no try/catch,
    // so one mangled character in a pasted private key puts tens of bytes of
    // the key blob into a banner on the provisioning screen. For an
    // unencrypted ed25519 key that window is wide enough to cover the private
    // scalar. Take the message and drop the source.
    return error.message.isEmpty ? 'it could not be parsed' : error.message;
  }
  return '$error';
}
