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
//
// The payload is carried, not printed. Every message in here is built from the
// payload's SHAPE -- keys, types, string lengths -- and never from its bytes,
// because `user export`'s payload reliably begins with a working VLESS URI and
// this is the error somebody is most likely to paste into a bug report: it is
// the one whose remedy is "tell the author what the server said". `raw` is
// still on the exception for whoever needs the bytes programmatically; what a
// person can select and copy carries no credential.

import 'dart:convert';

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
    // stderr whole -- it is vpnctl's own prose, argparse's usage, or a shell
    // saying it could not find the shim, and none of the three is a payload.
    // stdout only as far as the payload, for the reason at the top of this file:
    // a command that exited non-zero with a broken payload on stdout is still a
    // command whose payload may hold a credential.
    final String detail = <String>[stderr.trim(), _beforePayload(stdout.trim())]
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

  /// The payload exactly as it arrived, whole, for a caller that needs the
  /// bytes. Never rendered into [message]: see the top of this file.
  final String raw;

  static String _describe(String reason, String raw) {
    final String trimmed = raw.trim();
    if (trimmed.isEmpty) {
      return '$reason (stdout was empty)';
    }
    final Object? decoded = _decodeJson(trimmed);
    if (decoded != null) {
      // The shape is what says what changed -- a key that appeared, a value
      // that became a list -- and `reason` has already located the failure
      // inside it. The bytes add nothing except the credential.
      return '$reason\npayload shape: ${_shapeOf(decoded)}';
    }
    final String prefix = _beforePayload(trimmed);
    if (prefix.isEmpty) {
      return '$reason (stdout was ${trimmed.length} characters that begin like '
          'a payload and do not parse as one, so they are not shown: a damaged '
          '`user export` answer still starts with a live URI)';
    }
    return '$reason\nbefore the payload, stdout carried: $prefix';
  }
}

/// The shape, bounded. Depth and width already bound it for anything cli.py
/// emits; this is what keeps a payload nobody wrote from filling the screen
/// with its own diagnosis.
String _shapeOf(Object? decoded) {
  final String shape = _sketch(decoded);
  if (shape.length <= _maxShape) return shape;
  return '${shape.substring(0, _maxShape)}… '
      '[shape truncated, ${shape.length} characters]';
}

/// Decoded, or null when this is not JSON at all -- an MOTD, a wrapper, a shell.
Object? _decodeJson(String text) {
  try {
    return jsonDecode(text) as Object?;
  } on FormatException {
    return null;
  }
}

/// Everything on stdout that cannot be part of the payload, and nothing that
/// can be.
///
/// Under `--json`, `say()` is silent and `warn()` writes to stderr, so the
/// payload is one JSON object and anything a login shell, an MOTD or a wrapper
/// prepended sits in front of its opening brace. Showing that prefix is how
/// "something is speaking over vpnctl" gets diagnosed at all -- it is the whole
/// reason this layer does not scavenge for JSON inside other output. Showing
/// what follows is how a credential reaches a bug report, because a payload
/// that failed to parse is usually a payload that arrived truncated.
String _beforePayload(String text) {
  final int brace = text.indexOf('{');
  final String head = brace < 0 ? text : text.substring(0, brace);
  return _clipTokens(head.trim());
}

/// Belt and braces over text that is not supposed to hold a credential: a run
/// of base64, hex or URI characters long enough to be one is replaced by its
/// length. An MOTD has no 32-character words; a key, a UUID, a bundle and a
/// share URI all do.
String _clipTokens(String text) {
  final String noUris = text.replaceAllMapped(
    RegExp(r'[A-Za-z][A-Za-z0-9+.\-]*://\S+'),
    (Match m) => '${m.group(0)!.split('://').first}://…',
  );
  return noUris.replaceAllMapped(
    RegExp(r'[A-Za-z0-9+/=_-]{32,}'),
    (Match m) => '…[${m.group(0)!.length} characters]',
  );
}

/// The payload's shape: every key, every type, every string's length, and not
/// one byte of any value.
///
/// Values are described rather than shown because the keys that carry
/// credentials are most of the interesting ones -- `uri`, `b64`, `png_b64`,
/// `fields`, `uuid`, every `*_password` -- and a rule that listed them would be
/// an exact-path rule of the kind this repository has already been bitten by
/// (`dnstt-sshd/logins` ends in neither `.key` nor `.env`, and was rendered
/// world-readable by exactly that shape of rule). Describing every value closes
/// the set by construction, and a length is the one fact about a credential
/// worth reporting: it is how a truncated bundle is recognised.
String _sketch(Object? value, {int depth = 0}) {
  if (value == null) return 'null';
  if (value is bool) return 'boolean';
  if (value is num) return 'number';
  if (value is String) return 'string(${value.length})';
  if (depth >= _maxDepth) return '…';
  if (value is List<Object?>) {
    if (value.isEmpty) return '[]';
    final List<String> shown = <String>[
      for (final Object? element in value.take(_maxElements))
        _sketch(element, depth: depth + 1),
    ];
    if (value.length > _maxElements) {
      shown.add('…+${value.length - _maxElements} more');
    }
    return '[${shown.join(', ')}]';
  }
  if (value is Map<String, Object?>) {
    if (value.isEmpty) return '{}';
    final List<String> shown = <String>[
      for (final String key in value.keys.take(_maxKeys))
        '$key: ${_sketch(value[key], depth: depth + 1)}',
    ];
    if (value.length > _maxKeys) {
      shown.add('…+${value.length - _maxKeys} more');
    }
    return '{${shown.join(', ')}}';
  }
  // Unreachable for anything jsonDecode produced, and total anyway: a shape
  // renderer that could throw would replace the failure it was called to
  // describe.
  return 'a ${value.runtimeType}';
}

/// `user export` nests six deep -- payload, protocols, one protocol's items, an
/// item, its fields, a (setting, value) pair -- so anything shallower would
/// elide the level a failure is usually in.
const int _maxDepth = 6;

/// Enough to see that a list is a list of the same thing, few enough that a
/// three-user server and a three-hundred-user one produce the same sentence.
const int _maxElements = 4;

/// Keys are not elided the way list elements are: the key set IS the contract
/// with the server, it is what a report of a broken one has to carry, and cli.py
/// bounds it -- `apply` is the widest payload at eleven. A limit at all only so
/// that a payload nobody wrote cannot produce a page of text.
const int _maxKeys = 20;

const int _maxShape = 1200;

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
    required super.argv,
    required int this.serverSchema,
    required int appSchema,
    required super.raw,
  })  : unknownField = null,
        super(
          reason: serverSchema > appSchema
              ? 'the server answers --json schema $serverSchema and this app '
                  'understands $appSchema. The server is newer than the app -- '
                  'update the app. $_unread'
              : 'the server answers --json schema $serverSchema and this app '
                  'understands $appSchema. The server is older than the app -- '
                  'deploy the matching version. $_unread',
        );

  VpnctlSchemaError.unknownField({
    required super.argv,
    required String where,
    required this.unknownField,
    required super.raw,
  })  : serverSchema = null,
        super(
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
