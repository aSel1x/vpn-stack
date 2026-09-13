// Provisioning failures, kept apart because they ask different things of
// whoever is holding the phone.
//
//   transport      nothing ran, or we cannot know whether it did. Re-run.
//   command        a remote program ran and refused. It already wrote the
//                  sentence; showing anything else loses it.
//   unsupported    this box is not one this sequence knows how to provision.
//   already        the server has secrets or users. Re-running would mint new
//                  ones and silently invalidate every profile handed out.
//   lockout        the firewall step could not prove a fresh connection
//                  survives, so the deadman was left armed ON PURPOSE. This is
//                  the only failure in the app whose message has to say what is
//                  about to happen without anybody doing anything.
//   readiness      ports never bound. Not a warning: a check that runs against
//                  a server that is merely still starting fails, and a smoke
//                  test that cries wolf teaches people to ignore smoke tests.

// Host key failures are deliberately NOT in this family: they are raised by the
// transport seam, which control/ uses too, and they carry no step. See
// host_key.dart's sealed HostKeyError, whose toString() is the sentence itself.

sealed class ProvisionException implements Exception {
  const ProvisionException({required this.step, required this.message});

  /// Machine name of the step that failed, so a UI can point at the row.
  final String step;

  /// One sentence -- or several -- already fit to put in front of a human.
  final String message;

  @override
  String toString() => '$runtimeType [$step]: $message';
}

/// The connection failed before a command produced an exit status, so whether
/// it ran at all is unknown.
final class ProvisionTransportError extends ProvisionException {
  ProvisionTransportError({
    required super.step,
    required this.cause,
    String? what,
  }) : super(
          message: what == null
              ? 'the connection failed: $cause'
              : 'the connection failed during $what, so whether it ran is '
                  'unknown: $cause',
        );

  /// Whatever the injected transport threw. Deliberately `Object`: this layer
  /// must not know dartssh2's exception types, or it would import dartssh2.
  final Object cause;
}

/// A remote program ran and exited non-zero.
final class ProvisionCommandError extends ProvisionException {
  ProvisionCommandError({
    required super.step,
    required this.what,
    required this.exitCode,
    required this.output,
  }) : super(
          message: output.trim().isEmpty
              ? '$what exited $exitCode and printed nothing'
              : '$what exited $exitCode:\n${output.trim()}',
        );

  /// What was being attempted, in words: "installing docker", not a shell
  /// program. The program is in commands.dart and a phone screen is not where
  /// to read it.
  final String what;

  final int exitCode;

  /// stdout and stderr together, as the remote produced them.
  final String output;
}

/// Not a Debian or Ubuntu box, not root, or otherwise outside what this
/// sequence knows how to do.
final class UnsupportedHostError extends ProvisionException {
  const UnsupportedHostError({required super.step, required super.message});
}

/// The server is already provisioned, and re-running would destroy credentials.
///
/// `install.sh` is idempotent, but `bootstrap` on a server that already has
/// secrets mints new ones, and every profile already handed out stops working
/// with no error anywhere. So this refuses instead, exactly as `deploy.sh`
/// refuses to bootstrap.
final class AlreadyProvisionedError extends ProvisionException {
  AlreadyProvisionedError({required super.step, required this.evidence}) : super(
          message: 'this server is already provisioned '
              '(${evidence.join('; ')}). Provisioning it again would generate a '
              'fresh keyring and silently invalidate every profile already '
              'handed out. Update it instead, or restore a backup onto a box '
              'that really is bare.',
        );

  /// What was found, named. "there is already an install" is not actionable;
  /// "8 secrets and a users.json" is.
  final List<String> evidence;
}

/// The firewall step could not prove a fresh connection survives the rules it
/// just installed, so it deliberately did not disarm the deadman.
final class FirewallLockoutError extends ProvisionException {
  FirewallLockoutError({
    required super.step,
    required this.reason,
    required this.deadmanSeconds,
    required this.deadmanPid,
    this.attempts = const <String>[],
  }) : super(
          message: _describe(reason, deadmanSeconds, attempts),
        );

  /// Why the proof failed, in one line.
  final String reason;

  /// How long the armed deadman still has to run.
  final int deadmanSeconds;

  /// The pid it reported when it armed. Worth showing: it is what somebody with
  /// console access would kill.
  final String deadmanPid;

  /// One line per attempt, because "refused" and "timed out" are different
  /// diagnoses -- a DROPping firewall hangs, a wrong port refuses.
  final List<String> attempts;

  static String _describe(
    String reason,
    int deadmanSeconds,
    List<String> attempts,
  ) {
    final StringBuffer out = StringBuffer()
      ..writeln('A fresh SSH connection did not survive the new firewall rules.')
      ..writeln(reason)
      ..writeln()
      ..writeln('The deadman has been LEFT ARMED on purpose: the server '
          'disables ufw by itself within ${deadmanSeconds}s of it being '
          'enabled, with nothing further from this app and nothing for you to '
          'run. Wait that long, reconnect, and try again -- and check that sshd '
          'really listens on the port this was told to open.');
    if (attempts.isNotEmpty) {
      out
        ..writeln()
        ..writeln(attempts.join('\n'));
    }
    return out.toString().trimRight();
  }
}

/// Ports never came up.
final class ReadinessTimeoutError extends ProvisionException {
  ReadinessTimeoutError({
    required super.step,
    required this.pending,
    required this.waited,
  }) : super(
          message: 'after ${waited.inSeconds}s these ports are still not bound '
              'on a non-loopback address: ${pending.join(', ')}. The containers '
              'are up but not serving; `docker logs` on the server says why.',
        );

  final List<String> pending;
  final Duration waited;
}
