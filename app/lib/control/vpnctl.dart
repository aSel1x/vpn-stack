// The app's entire view of the server.
//
// One method per vpnctl subcommand, each building an argument vector and
// parsing the JSON that comes back. Nothing here renders a config, derives a
// key or builds a share link: the server owns those and two implementations of
// a credential format drift invisibly until somebody's profile stops
// importing (app/README.md). What this file owns is the argv -- which IS the
// contract -- and the refusal to read a payload it does not fully understand.

import 'dart:convert';

import 'errors.dart';
import 'json.dart';
import 'models.dart';
import 'ssh_session.dart';

/// The `--json` envelope version this app understands. cli.py's `SCHEMA`.
const int vpnctlSchema = 1;

/// Absolute, not `vpnctl` on the PATH.
///
/// `uv` installs to /root/.local/bin, which is not on the PATH of a
/// non-interactive SSH session -- the reason install.sh symlinks the shim into
/// /usr/local/bin in the first place. Depending on the remote PATH is how this
/// repository already produced an `exit 127` that explained nothing.
const String defaultVpnctlPath = '/usr/local/bin/vpnctl';

/// The same lock `./vpn` takes, at the same path, and the same one vpnctl now
/// takes from inside for every mutating command.
///
/// "One SSH call, one lock" is the multi-operator story here: two people
/// writing users.json at once interleave instead of serialising. Holding it out
/// here as well is not redundant -- this one covers the whole remote command,
/// vpnctl's own covers vpnctl -- and an app that skipped it would be the second
/// operator. VPN_STACK_LOCK_HELD is how the two agree on who is holding it; see
/// provision/commands.dart.
const String defaultLockPath = '/run/vpn-stack.lock';

/// What flock exits with when it waited and never got the lock.
///
/// EX_TEMPFAIL, so that "somebody else is mid-apply" is distinguishable from
/// every other status either half produces -- 1 for a refusal, 2 for argparse
/// or the not-the-server guard, 127 for a missing binary. vpnctl's own lock
/// refusal exits 75 too, deliberately and for the same meaning, so a client
/// does not have to know which of the two turned the call away. `./vpn` blocks
/// for ever instead; a phone that hangs with nothing on screen is
/// indistinguishable from a crash, so this one waits with a bound and then says
/// why.
const int lockConflictExit = 75;

/// Every call is `flock … vpnctl … --json`.
class Vpnctl {
  Vpnctl(
    this.session, {
    this.vpnctlPath = defaultVpnctlPath,
    this.lockPath = defaultLockPath,
    this.lockWait = const Duration(minutes: 5),
  });

  /// Injected: nothing in this layer imports an SSH library, which is what
  /// makes every command line and every parse below testable with no server.
  final SshSession session;

  final String vpnctlPath;
  final String lockPath;

  /// How long to wait for the lock. Generous by default because `user add`
  /// runs a full apply, and apply waits up to 240s for the ipsec container's
  /// ports on a first run.
  ///
  /// Every command takes the lock, including the ones that only read: `user
  /// export` looks read-only and is not -- it runs `ikev2.sh --exportclient`
  /// inside the container and deletes the bundles afterwards -- so "which
  /// commands really mutate" is not a distinction worth encoding here. A
  /// screen that polls `status` while an apply is running should pass a short
  /// wait and render a [lockConflictExit] refusal as "busy", not as a failure.
  final Duration lockWait;

  /// `flock -w <s> -E 75 <lock> <vpnctl> --json <command…>`.
  ///
  /// A `List<String>`, never a joined string: a user name is an argument, and
  /// this repository has already been bitten by one being re-split by the
  /// remote shell -- one layer down that misaligns the space-separated IKEv2
  /// user and password lists and hands one person another's password. Quoting
  /// happens once, in shell.dart, at the transport.
  ///
  /// `--json` goes immediately after the program. argparse accepts it in any
  /// position (cli.py uses argparse.SUPPRESS to make that work), so putting it
  /// first costs nothing and means it cannot be mistaken for the value of a
  /// preceding option, nor lost when a subcommand grows one.
  ///
  /// No `cd /opt/vpn-stack` in front, unlike `./vpn`: every subprocess vpnctl
  /// runs passes cwd=ROOT explicitly and ROOT comes from `__file__`, so the
  /// remote working directory does not enter into it.
  List<String> argvFor(List<String> command) => <String>[
        'flock',
        '-w',
        '${lockWait.inSeconds}',
        '-E',
        '$lockConflictExit',
        lockPath,
        vpnctlPath,
        '--json',
        ...command,
      ];

  /// What this server is running.
  Future<ServerStatus> status() async {
    final _Envelope env = await _run(<String>['status']);
    return _parse(env, ServerStatus.fromJson);
  }

  /// Who has access.
  ///
  /// [showSecrets] adds every protocol's credential to every row. Ask for it
  /// only where they are about to be displayed: the result is a list of live
  /// passwords, and the model keeps them behind [VpnUser.secrets] so a list
  /// fetched without them cannot accidentally log one.
  Future<List<VpnUser>> listUsers({bool showSecrets = false}) async {
    final _Envelope env = await _run(<String>[
      'user',
      'list',
      if (showSecrets) '--show-secrets',
    ]);
    return _parse(env, (Map<String, Object?> body) {
      rejectUnknown(body, const <String>{'users'});
      final List<Object?> rows = readList(body, 'users');
      return <VpnUser>[
        for (int i = 0; i < rows.length; i++)
          VpnUser.fromJson(asObject(rows[i], 'users[$i]'), where: 'users[$i]'),
      ];
    });
  }

  /// Fresh credentials for every protocol, then a full apply.
  ///
  /// A [VpnctlCommandError] from here does NOT mean the user was not created:
  /// users.json is written first and the apply that follows can still fail, in
  /// which case the record exists and the config was never promoted. Re-run
  /// `apply` rather than re-adding -- the retry fails with "already exists"
  /// and tells you nothing.
  Future<UserMutation> addUser(String name) async {
    final _Envelope env = await _run(<String>['user', 'add', name]);
    return _parse(env, UserMutation.fromJson);
  }

  /// Permanent. If ikev2 is down the revocation is queued server-side, so the
  /// certificate stops working on the next apply rather than never.
  Future<UserMutation> removeUser(String name) async {
    final _Envelope env = await _run(<String>['user', 'rm', name]);
    return _parse(env, UserMutation.fromJson);
  }

  /// Enabling issues a BRAND-NEW IKEv2 certificate: any profile exported
  /// before the disable stops working and has to be re-exported.
  Future<UserEnablement> setUserEnabled(String name,
      {required bool enabled}) async {
    final _Envelope env =
        await _run(<String>['user', enabled ? 'enable' : 'disable', name]);
    return _parse(env, UserEnablement.fromJson);
  }

  /// Share links and client bundles for one person.
  ///
  /// [protocol] defaults to every enabled protocol, which is what the server
  /// does with no `--protocol`. [host] overrides VPN_SERVER_HOST, for a server
  /// reached at an address its profiles must not carry.
  ///
  /// Never `--qr`: vpnctl suppresses it under --json anyway, and ASCII art in
  /// the middle of the payload is the documented way `./vpn share` broke. The
  /// QR arrives as PNG bytes on each URI item instead.
  Future<ShareBundle> exportUser(
    String name, {
    String? protocol,
    String? host,
  }) async {
    final _Envelope env = await _run(<String>[
      'user',
      'export',
      name,
      if (protocol != null) ...<String>['--protocol', protocol],
      if (host != null) ...<String>['--host', host],
    ],
        // `ok: false` here is not a refusal -- the command exits 0 and the
        // payload still carries every bundle that did work, with the rest named
        // in `failed`. Throwing would discard the profiles that succeeded.
        allowNotOk: true);
    return _parse(env, ShareBundle.fromJson);
  }

  /// Every protocol, on or off, with its ports.
  Future<List<ProtocolEntry>> listProtocols() async {
    final _Envelope env = await _run(<String>['protocol', 'list']);
    return _parse(env, (Map<String, Object?> body) {
      rejectUnknown(body, const <String>{'protocols'});
      final List<Object?> rows = readList(body, 'protocols');
      return <ProtocolEntry>[
        for (int i = 0; i < rows.length; i++)
          ProtocolEntry.fromJson(asObject(rows[i], 'protocols[$i]'),
              where: 'protocols[$i]'),
      ];
    });
  }

  /// Turning one on may be expensive the first time -- dnstt mints its Noise
  /// keypair by building a Go image -- and a failure there rolls the toggle
  /// back rather than leaving a protocol enabled with no key.
  Future<ProtocolToggle> setProtocol(String name,
      {required bool enabled}) async {
    final _Envelope env =
        await _run(<String>['protocol', enabled ? 'on' : 'off', name]);
    return _parse(env, ProtocolToggle.fromJson);
  }

  /// Render, validate, promote, converge.
  ///
  /// [restart] false renders and validates only, and leaves the server with a
  /// pending convergence: the containers keep serving the previous config
  /// until a real apply runs, so profiles exported in between will not connect.
  Future<ApplyResult> apply({bool restart = true}) async {
    final _Envelope env = await _run(<String>[
      'apply',
      if (!restart) '--no-restart',
    ]);
    return _parse(env, (Map<String, Object?> body) =>
        ApplyResult.fromJson(body));
  }

  Future<_Envelope> _run(List<String> command,
      {bool allowNotOk = false}) async {
    final List<String> argv = argvFor(command);

    final CommandResult result;
    try {
      result = await session.run(argv);
    } catch (cause) {
      // Deliberately catch-all rather than `on Exception`: this layer must not
      // know the transport's exception types, and a session that throws a
      // StateError because it was closed under us is still a transport
      // failure, not a bug in the parse.
      throw VpnctlTransportError(argv: argv, cause: cause);
    }

    if (result.exitCode == lockConflictExit) {
      throw VpnctlCommandError(
        argv: argv,
        exitCode: result.exitCode,
        error: 'another operator holds $lockPath and did not release it within '
            '${lockWait.inSeconds}s. Nothing ran. A `vpnctl apply` on a first '
            'IKEv2 start legitimately takes minutes; wait, or retry.',
        payload: null,
        stderr: result.stderr,
      );
    }

    // No scavenging for JSON inside other output. Under --json, say() is
    // silent and warn() writes to stderr, so anything else on stdout means
    // something is speaking over vpnctl -- an MOTD, a wrapper, a shell -- and
    // showing the operator exactly what arrived is more useful than guessing
    // which braces were the payload.
    final Object? decoded = _decode(result.stdout);
    if (decoded is! Map<String, Object?>) {
      if (result.exitCode != 0) {
        // argparse exits 2 with usage on stderr, the not-the-server guard
        // exits 2 with its own paragraph, a missing shim exits 127. None of
        // them ever claimed to be answering in JSON, so none is a protocol
        // error: the message is whatever they printed.
        throw VpnctlCommandError.unparsed(
          argv: argv,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
        );
      }
      throw VpnctlProtocolError(
        argv: argv,
        reason: 'exited 0 but stdout is not a JSON object, so this is not a '
            'vpnctl --json answer',
        raw: result.stdout,
      );
    }

    // A copy, so the error path below can still hand back the payload whole --
    // die() attaches keys of its own (`missing`, for absent secrets) and they
    // are the actionable half of the message.
    final Map<String, Object?> body = Map<String, Object?>.of(decoded);
    final Object? schema = body.remove('schema');
    if (schema is! int) {
      throw VpnctlProtocolError(
        argv: argv,
        reason: 'no "schema" field: this is not a vpnctl --json envelope',
        raw: result.stdout,
      );
    }
    if (schema != vpnctlSchema) {
      throw VpnctlSchemaError.mismatch(
        argv: argv,
        serverSchema: schema,
        appSchema: vpnctlSchema,
        raw: result.stdout,
      );
    }

    final Object? ok = body.remove('ok');
    if (ok is! bool) {
      throw VpnctlProtocolError(
        argv: argv,
        reason: '"ok" is missing or is not a boolean',
        raw: result.stdout,
      );
    }

    final Object? error = body.remove('error');
    if (error != null || result.exitCode != 0 || (!ok && !allowNotOk)) {
      throw VpnctlCommandError(
        argv: argv,
        exitCode: result.exitCode,
        error: error is String
            ? error
            : error != null
                ? '$error'
                : result.exitCode != 0
                    ? 'exited ${result.exitCode} without saying why'
                    : 'reported failure without saying why',
        payload: decoded,
        stderr: result.stderr,
      );
    }

    return _Envelope(argv: argv, raw: result.stdout, ok: ok, body: body);
  }

  /// Turns a located parse failure into one that also carries the argv and the
  /// payload, which is what makes a report of it actionable.
  T _parse<T>(_Envelope env, T Function(Map<String, Object?>) parse) {
    try {
      return parse(env.body);
    } on UnknownFieldException catch (e) {
      throw VpnctlSchemaError.unknownField(
        argv: env.argv,
        where: e.where.isEmpty ? 'the payload' : e.where,
        unknownField: e.field,
        raw: env.raw,
      );
    } on PayloadFormatException catch (e) {
      throw VpnctlProtocolError(argv: env.argv, reason: e.reason, raw: env.raw);
    }
  }
}

Object? _decode(String stdout) {
  try {
    return jsonDecode(stdout);
  } on FormatException {
    return null;
  }
}

/// One decoded answer, with `schema`, `ok` and `error` already taken off so a
/// model sees only its own fields and can refuse the ones it does not know.
class _Envelope {
  const _Envelope({
    required this.argv,
    required this.raw,
    required this.ok,
    required this.body,
  });

  final List<String> argv;
  final String raw;
  final bool ok;
  final Map<String, Object?> body;
}
