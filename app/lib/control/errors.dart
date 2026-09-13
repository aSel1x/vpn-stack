// Three failures, kept apart because they ask different things of whoever is
// looking at the screen.
//
//   transport  nothing ran, or we cannot know whether it did: a key, a host,
//              a network. Retrying is reasonable.
//   command    vpnctl ran and said no. It already wrote the sentence; showing
//              anything else loses it.
//   protocol   vpnctl ran and printed something this app cannot read. This is
//              the one that actually happens -- the server is newer than the
//              app -- so it carries the payload it choked on, because that is
//              the only thing that says what changed.

import 'shell.dart';

sealed class VpnctlException implements Exception {
  const VpnctlException(this.message, this.argv);

  /// One sentence that already names the failure. Safe to put in front of a
  /// human as-is.
  final String message;

  /// The argument vector that produced it. The argv *is* the contract with the
  /// server, so it belongs in every report of a broken one.
  final List<String> argv;

  /// The command as it went over the wire, for a bug report.
  String get command => shellCommand(argv);

  @override
  String toString() => '$runtimeType: $message';
}

/// The SSH transport failed before the command produced an exit status.
final class VpnctlTransportError extends VpnctlException {
  VpnctlTransportError({required List<String> argv, required this.cause})
      : super(_describe(argv, cause), argv);

  /// Whatever the injected session threw. Deliberately `Object`: this layer
  /// must not know dartssh2's exception types, or it would import dartssh2.
  final Object cause;

  static String _describe(List<String> argv, Object cause) =>
      'the connection failed before `${shellCommand(argv)}` produced an exit '
      'status, so whether it ran at all is unknown: $cause';
}

/// vpnctl ran and refused.
final class VpnctlCommandError extends VpnctlException {
  VpnctlCommandError({
    required List<String> argv,
    required this.exitCode,
    required this.error,
    required this.payload,
    required this.stderr,
  }) : super(error, argv);

  /// When vpnctl said no itself this is 1 (`die()` raises SystemExit(1)).
  /// 2 is an argparse usage error, 127 a missing vpnctl, 255 ssh itself.
  final int exitCode;

  /// vpnctl's own `error` string where there was one.
  final String error;

  /// The whole JSON body, so a caller can read the extra keys `die()` attaches
  /// -- `missing` for absent secrets, for instance. Null when there was no
  /// JSON at all, which is what an argparse usage error looks like.
  final Map<String, Object?>? payload;

  final String stderr;

  /// Non-zero exit with nothing parseable on stdout: argparse, a missing
  /// vpnctl, a broken shim. Not a protocol error -- the server never claimed to
  /// be answering in JSON -- so it stays in this class, where the message is
  /// whatever it did print.
  factory VpnctlCommandError.unparsed({
    required List<String> argv,
    required int exitCode,
    required String stdout,
    required String stderr,
  }) {
    final String detail = <String>[stderr.trim(), stdout.trim()]
        .where((String s) => s.isNotEmpty)
        .join('\n');
    return VpnctlCommandError(
      argv: argv,
      exitCode: exitCode,
      error: detail.isEmpty
          ? '`${shellCommand(argv)}` exited $exitCode and printed nothing'
          : detail,
      payload: null,
      stderr: stderr,
    );
  }
}

/// vpnctl answered, and the answer is not one this app can read.
class VpnctlProtocolError extends VpnctlException {
  VpnctlProtocolError({
    required List<String> argv,
    required this.reason,
    required this.raw,
  }) : super(_describe(reason, raw), argv);

  /// What was wrong, located: `users[2].name: expected a string, got null`.
  final String reason;

  /// The payload exactly as it arrived. Kept whole here; the message shows a
  /// prefix, because a base64 client bundle is hundreds of kilobytes and a log
  /// line of it hides the one sentence that matters.
  final String raw;

  static const int _shown = 1200;

  static String _describe(String reason, String raw) {
    final String trimmed = raw.trim();
    if (trimmed.isEmpty) {
      return '$reason (stdout was empty)';
    }
    final String shown = trimmed.length <= _shown
        ? trimmed
        : '${trimmed.substring(0, _shown)}… '
            '[truncated, ${trimmed.length} characters total]';
    return '$reason\npayload was: $shown';
  }
}

/// The server and the app disagree about the shape of the answer.
///
/// Separated from a plain protocol error because the remedy is different and
/// stateable: deploy the matching version. Worded like `users_store.load()`,
/// which refuses a database newer than the code *by name* rather than dropping
/// what it does not recognise.
final class VpnctlSchemaError extends VpnctlProtocolError {
  // `int this.serverSchema` narrows the initializing formal: the field is
  // nullable because the other constructor leaves it unset, but here it is
  // known and the comparison below has to be able to say so.
  VpnctlSchemaError.mismatch({
    required List<String> argv,
    required int this.serverSchema,
    required int appSchema,
    required String raw,
  })  : unknownField = null,
        super(
          argv: argv,
          raw: raw,
          reason: serverSchema > appSchema
              ? 'the server answers --json schema $serverSchema and this app '
                  'understands $appSchema. The server is newer than the app -- '
                  'update the app. $_unread'
              : 'the server answers --json schema $serverSchema and this app '
                  'understands $appSchema. The server is older than the app -- '
                  'deploy the matching version. $_unread',
        );

  VpnctlSchemaError.unknownField({
    required List<String> argv,
    required String where,
    required this.unknownField,
    required String raw,
  })  : serverSchema = null,
        super(
          argv: argv,
          raw: raw,
          reason: '$where has a field this app does not know '
              '($unknownField). The server is newer than the app -- update the '
              'app. $_unread',
        );

  // Never "nothing was changed": these are thrown while reading the ANSWER,
  // and `user add` has written users.json and converged the containers by the
  // time it prints one. Claiming otherwise would send somebody to re-add a
  // user who already exists.
  static const String _unread =
      'What the command did is in an answer this app cannot read.';

  /// The `schema` the server reported, when that was the disagreement.
  final int? serverSchema;

  /// The field nobody here knows about, when that was the disagreement.
  final String? unknownField;
}
