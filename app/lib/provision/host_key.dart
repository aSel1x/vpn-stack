// SSH host keys: the question this app did not used to ask.
//
// dartssh2's SSHClient accepts ANY host key when onVerifyHostKey is not
// supplied, so the first transport written against the seam in ssh.dart would
// have handed a root password to whatever answered on port 22 -- and this app
// asks for a root password on its second screen. `scripts/install.sh` at least
// does TOFU (`StrictHostKeyChecking=accept-new`, persisted to known_hosts) and
// refuses a key that later changes; this is the app's half of the same trade,
// with one difference a phone can afford: the first key is put in front of a
// human instead of accepted silently.
//
// Value types and one sealed failure family, nothing else. No crypto here: the
// fingerprint is computed by whoever speaks the wire protocol -- it is
// `SHA256:` plus the unpadded base64 of the SHA-256 of the key blob, exactly
// what `ssh-keygen -lf` prints -- and the comparison that decides anything is
// over the blob itself, never over a hash somebody else computed.

/// One server's public host key, exactly as it was presented in the handshake.
class SshHostKey {
  const SshHostKey({
    required this.algorithm,
    required this.blob,
    required this.fingerprint,
  });

  /// Rebuilds one from what the store persisted.
  ///
  /// Throws [FormatException] on a record this code cannot read rather than
  /// returning a key with empty fields: an empty pin matches nothing, which
  /// would quietly turn pinning back into a prompt on every connection --
  /// and a prompt people see every day is a prompt people tap through.
  factory SshHostKey.fromJson(Map<String, Object?> json) {
    final Object? algorithm = json['algorithm'];
    final Object? blob = json['blob'];
    final Object? fingerprint = json['fingerprint'];
    if (algorithm is! String ||
        blob is! String ||
        fingerprint is! String ||
        algorithm.isEmpty ||
        blob.isEmpty ||
        fingerprint.isEmpty) {
      throw const FormatException(
        'a stored host key needs a non-empty algorithm, blob and fingerprint',
      );
    }
    return SshHostKey(
      algorithm: algorithm,
      blob: blob,
      fingerprint: fingerprint,
    );
  }

  /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`. Part of the identity: a
  /// server with several host keys presents whichever one the client asked
  /// for, so a pin is a pin of one algorithm's key.
  final String algorithm;

  /// The public key blob, base64 -- the second field of a known_hosts line.
  /// This is the thing that is compared.
  final String blob;

  /// `SHA256:...`, for a human to read against what the provider's console or
  /// `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` shows. Display only.
  final String fingerprint;

  /// Same key, deliberately ignoring [fingerprint]: the fingerprint is derived,
  /// and comparing it would be trusting the transport's own arithmetic about
  /// the thing we are trying to verify.
  bool sameKeyAs(SshHostKey other) =>
      algorithm == other.algorithm && blob == other.blob;

  /// What a known_hosts line carries after the host name.
  String get knownHostsKey => '$algorithm $blob';

  /// The persisted shape. The store must keep all three fields: the blob is
  /// what pins, the algorithm is part of the identity, and the fingerprint is
  /// the only half a human can check.
  Map<String, Object?> toJson() => <String, Object?>{
        'algorithm': algorithm,
        'blob': blob,
        'fingerprint': fingerprint,
      };

  @override
  String toString() => '$algorithm $fingerprint';
}

/// What is being asked, and of which server.
class HostKeyQuestion {
  const HostKeyQuestion({
    required this.target,
    required this.offered,
    this.pinned,
  });

  /// `root@203.0.113.7:22`. In the question because "trust this key?" without
  /// naming the machine is a question nobody can answer.
  final String target;

  final SshHostKey offered;

  /// What this device had pinned. Null means it has never seen this server;
  /// non-null means the key CHANGED, which is a different question with a
  /// different answer.
  final SshHostKey? pinned;

  bool get changed => pinned != null;

  /// The sentence to put in front of the human. Written here rather than in the
  /// UI so every surface says the same thing, and so a headless caller that
  /// only logs the exception still says something useful.
  String get summary {
    final SshHostKey? was = pinned;
    if (was == null) {
      return 'The server at $target presented a host key this device has never '
          'seen:\n'
          '  ${offered.algorithm} ${offered.fingerprint}\n'
          'Nothing has been sent yet. Check it against the key the machine '
          'itself reports (`ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub`, or '
          'whatever your provider shows in its console) before trusting it: '
          'this is the one moment where an impostor is indistinguishable from '
          'the real server, and the next step sends it a root credential.';
    }
    return 'The host key for $target CHANGED.\n'
        '  pinned:  ${was.algorithm} ${was.fingerprint}\n'
        '  offered: ${offered.algorithm} ${offered.fingerprint}\n'
        'Either the box was rebuilt -- restoring a backup onto fresh hardware '
        'does exactly this -- or something is answering in its place. Do not '
        'trust it on the strength of the first explanation.';
  }
}

/// The answer.
enum HostKeyDecision {
  /// Use it, and remember it for next time. TOFU, with a human in it.
  trust,

  /// Use it for this run only. Nothing is persisted, so the question comes
  /// back -- which is the right trade for somebody who is not sure.
  trustOnce,

  /// Do not connect. No credential leaves the device.
  refuse,
}

/// Asked when the offered key is not the pinned one.
///
/// An implementation that answers [HostKeyDecision.trust] without a human in
/// the loop is `StrictHostKeyChecking=no` wearing a callback, which is the
/// thing this type exists to prevent.
typedef HostKeyPrompt = Future<HostKeyDecision> Function(HostKeyQuestion question);

/// Persists a key the human accepted. Must not throw: it runs after the
/// decision, and failing to write a file is not a reason to abandon a
/// connection the person just approved.
typedef HostKeyRecorder = Future<void> Function(SshHostKey key);

/// Every way host key verification ends badly.
///
/// Not a `ProvisionException`: these are raised by the transport seam, which
/// `control/` uses too, and they carry no step. [toString] is the sentence
/// itself so a caller that only has `'$error'` still prints something a person
/// can act on.
sealed class HostKeyError implements Exception {
  const HostKeyError(this.message);

  /// One paragraph, already fit to put in front of a human.
  final String message;

  @override
  String toString() => message;
}

/// The connector could not ask from inside the key exchange, so it aborted the
/// handshake and handed the key back.
///
/// This is a question, not a failure: the caller answers it (via
/// `HostKeyPolicy.verify`) and connects again. It exists because a client whose
/// verification callback is synchronous -- dartssh2's is -- cannot wait for a
/// human mid-exchange, and the alternative (authenticate now, check later) has
/// already given the password away.
final class HostKeyUnknownError extends HostKeyError {
  HostKeyUnknownError({required this.question})
      : super('${question.summary}\n'
            'The connection was abandoned before authentication, so nothing '
            'was sent.');

  final HostKeyQuestion question;
}

/// The key was refused -- by a human, or by a policy that had nobody to ask.
final class HostKeyRejectedError extends HostKeyError {
  HostKeyRejectedError({required this.question, required this.asked})
      : super(asked
            ? '${question.summary}\n'
                'It was refused, so nothing was sent.'
            : '${question.summary}\n'
                'There is nobody to ask: this connection was given a host key '
                'policy with no prompt and no matching pin, so it refuses. '
                'That is deliberate -- the alternative is accepting whatever '
                'answers.');

  final HostKeyQuestion question;

  /// False when the policy had no prompt at all, which is a wiring bug rather
  /// than somebody's decision, and reads differently in a report.
  final bool asked;
}

/// The transport connected against a key the policy never approved.
///
/// A promise in a doc comment is not a check. Reaching this means the
/// credential is already gone -- this cannot undo that, it can only stop the
/// run and name the key that received it.
final class HostKeyPolicyIgnoredError extends HostKeyError {
  HostKeyPolicyIgnoredError({required this.offered, required this.target})
      : super('The SSH transport connected to $target against a host key the '
            'policy never approved (${offered.algorithm} '
            '${offered.fingerprint}). The credential has already been sent to '
            'whatever holds that key. Treat it as disclosed, and fix the '
            'connector: the policy must be applied during the key exchange, '
            'before authentication.');

  final SshHostKey offered;
  final String target;
}
