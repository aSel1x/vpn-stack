// A server, as far as the control layer can tell.
//
// The payloads below are not transcriptions. Each one is a file under
// test/fixtures/ that tests/test_json_contract.py generates by calling cli.py's
// real `cmd_*` functions and then asserts cli.py still prints byte for byte. So
// the same artifact is the pytest expectation and the input to these tests: a
// key renamed on the server fails pytest, and accepting that rename means
// regenerating the file, which fails these tests until the models move too. One
// commit has to change both sides, which is the reason app/README.md gives for
// the client living in this repository at all.
//
// What it replaced: hand-typed `const String` literals of what somebody
// remembered the server printing. Three of them were already wrong -- an export
// with `failed: ["hysteria2"]` (only a share_via_container protocol can land
// there), IKEv2 bundles named `kate.p12` rather than `kate-ikev2.p12` (the
// suffix `bundle_label` matches on, so the labels were wrong too), and a dnstt
// card with four fields where share() emits two cards of five and three. All
// three parsed, and all three described a payload no server can produce.
//
// Not a _test.dart file on purpose: it holds no tests and `flutter test` should
// not collect it.

import 'dart:io';

import 'package:vpn_stack_app/control/ssh_session.dart';

/// Records every argv it is handed and answers with whatever it was built
/// with. The recording is the point: the argv IS the contract with the server.
class FakeSsh implements SshSession {
  FakeSsh(this.responder);

  /// Answers every call the same way.
  FakeSsh.replying(String stdout, {int exitCode = 0, String stderr = ''})
      : responder = ((List<String> argv) => CommandResult(
              exitCode: exitCode,
              stdout: stdout,
              stderr: stderr,
            ));

  final CommandResult Function(List<String> argv) responder;

  final List<List<String>> calls = <List<String>>[];

  @override
  Future<CommandResult> run(List<String> argv) async {
    calls.add(List<String>.unmodifiable(argv));
    return responder(argv);
  }

  List<String> get lastArgv => calls.last;
}

/// A transport that never produces an exit status -- a dropped connection, a
/// refused key. The distinction the control layer has to keep is between this
/// and a command that ran and said no.
class BrokenSsh implements SshSession {
  BrokenSsh(this.cause);

  final Object cause;

  @override
  Future<CommandResult> run(List<String> argv) async => throw cause;
}

/// The prefix every call carries: the lock `./vpn` takes, then the shim.
const List<String> lockAndBinary = <String>[
  'flock',
  '-w',
  '300',
  '-E',
  '75',
  '/run/vpn-stack.lock',
  '/usr/local/bin/vpnctl',
  '--json',
];

List<String> expectedArgv(List<String> command) =>
    <String>[...lockAndBinary, ...command];

// ------------------------------------------------- payloads: the real thing

/// One generated payload, read from disk.
///
/// `flutter test` runs with the package root as its working directory --
/// measured, not assumed: a probe printing `Directory.current.path` inside a
/// test prints `<repo>/app`. So the relative path resolves the same whether the
/// suite is invoked as `flutter test`, `flutter test test/x_test.dart`, or from
/// the IDE.
///
/// A missing file is reported with the command that makes it rather than as a
/// FileSystemException: these files are build output of the Python suite, and a
/// fresh clone has them only because they are committed.
String fixture(String name) {
  final File file = File('test/fixtures/$name');
  if (!file.existsSync()) {
    throw StateError(
      'test/fixtures/$name is missing. It is generated from vpnctl/cli.py: run '
      '`UPDATE_CONTRACT=1 uv run --frozen --with pytest pytest '
      'tests/test_json_contract.py` from the repository root and commit it.',
    );
  }
  return file.readAsStringSync();
}

final String statusJson = fixture('status.json');
final String userListJson = fixture('user-list.json');
final String userListSecretsJson = fixture('user-list-secrets.json');
final String protocolListJson = fixture('protocol-list.json');

final String applyJson = fixture('apply.json');
final String userAddJson = fixture('user-add.json');
final String userRmJson = fixture('user-rm.json');
final String userEnableJson = fixture('user-enable.json');
final String userDisableJson = fixture('user-disable.json');
final String protocolOnJson = fixture('protocol-on.json');
final String protocolOffJson = fixture('protocol-off.json');

/// `protocol on` for something already on: it returns before rendering
/// anything, so there is no apply result in here at all. The absence is part of
/// the contract -- [ProtocolToggle] must not invent one.
final String protocolUnchangedJson = fixture('protocol-unchanged.json');

/// All three share shapes in one answer: a `uri` (which gets a QR code and a
/// tappable link), `fields` (a form to copy by hand) and `filename` items (a
/// download). Picking the wrong one is not cosmetic, which is why the fixture
/// covers all three.
final String exportJson = fixture('user-export.json');

/// The same export with the IKEv2 container down. `ok` is false and the exit
/// status is 0 -- emit() does not raise -- and every bundle that did work is
/// still in the payload, which is why this cannot be treated as a refusal.
final String exportPartialJson = fixture('user-export-partial.json');

/// die(): `ok: false`, an `error` sentence, and whatever structured keys it
/// attached. `missing` is the one the app reads.
final String missingSecretsJson = fixture('apply-missing-secrets.json');

final String noSuchUserJson = fixture('user-export-no-such-user.json');

// ------------------------------------- payloads: deliberate corruption only

// Everything below is hand-written ON PURPOSE and must stay that way. These are
// not descriptions of what the server prints -- they are inputs to the
// refusals: a truncated bundle, a field of the wrong type, an envelope that
// never arrived. Generating them would defeat the test, because cli.py cannot
// produce them.
//
// If one of these ever needs to become a fixture, it has stopped being
// corruption and the test using it has stopped testing a refusal. Do not
// quietly convert one into the other.

/// The not-the-server guard: stderr, exit 2, and no JSON at all even though
/// --json was asked for. Not a fixture because it is not a payload -- guard.py
/// prints this before anything decides to answer in JSON, which is exactly the
/// case the control layer must not read as a protocol error.
const String guardStderr = '''
Refusing to run user add: this does not look like the VPN server.
  /etc/vpn-stack does not exist.
''';
