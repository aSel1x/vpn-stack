// A scripted SSH, so the whole provisioning sequence runs with no server, no
// key and no network.
//
// It answers by matching the program text, because that is what the layer
// actually produces: commands.dart builds shell programs, and a test that
// asserted on a step's name instead would pass while the program sent to the
// box was wrong. Rules are consulted most-recently-registered first, so a test
// overrides a default by registering its own.
//
// Not a mock library: a fake with a recorded command log answers the questions
// these tests ask -- what ran, in what order, on WHICH connection, and what did
// NOT run after a failure -- which is the property the firewall tests turn on.
//
// It also behaves like a connector that honours the host key policy, because
// the layer now insists on one: every connection presents a key, and nothing is
// authenticated until the policy has approved it.

import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/provision/step.dart';

/// Thrown by [ScriptedSsh.connect] once connections are refused. Stands in for
/// whatever the real transport throws; nothing in the layer may depend on the
/// type, which is exactly what `ProvisionTransportError.cause` being `Object`
/// is for.
class ScriptedConnectionRefused implements Exception {
  ScriptedConnectionRefused(this.message);

  final String message;

  @override
  String toString() => 'ScriptedConnectionRefused: $message';
}

/// The key every scripted server presents, unless a test says otherwise.
const SshHostKey scriptedHostKey = SshHostKey(
  algorithm: 'ssh-ed25519',
  blob: 'AAAAC3NzaC1lZDI1NTE5AAAAIScriptedScriptedScriptedScripted1',
  fingerprint: 'SHA256:scripted1scripted1scripted1scripted1scripted',
);

/// A different machine answering on the same address.
const SshHostKey otherHostKey = SshHostKey(
  algorithm: 'ssh-ed25519',
  blob: 'AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOtherOther2',
  fingerprint: 'SHA256:other2other2other2other2other2other2other2o',
);

class _Rule {
  _Rule(this.match, this.exact, this.results);

  final String match;
  final bool exact;
  final List<CommandResult> results;
  int _served = 0;

  bool matches(String program) =>
      exact ? program.trim() == match : program.contains(match);

  /// The last result repeats, so a rule can describe "pending, pending, then
  /// bound, and bound from then on" without counting polls.
  CommandResult take() {
    final CommandResult result =
        results[_served < results.length ? _served : results.length - 1];
    _served++;
    return result;
  }
}

class ScriptedSsh implements SshConnector {
  ScriptedSsh() {
    hostKeys = HostKeyPolicy.ask(
      target: target,
      prompt: (HostKeyQuestion question) async {
        questions.add(question);
        return answer;
      },
      remember: (SshHostKey key) async {
        remembered.add(key);
      },
    );
  }

  /// A bare Ubuntu box with nothing installed and nothing to lose: every
  /// program the happy path runs has an answer here, and every test starts from
  /// this and overrides the one thing it is about.
  factory ScriptedSsh.bareUbuntu() {
    final ScriptedSsh ssh = ScriptedSsh();
    ssh.reply('id -u', stdout: '0\n', exact: true);
    ssh.reply(
      'cat /etc/os-release',
      exact: true,
      stdout: 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\n'
          'ID_LIKE=debian\nVERSION_CODENAME=noble\n',
    );
    ssh.reply(
      'users_file',
      stdout: 'vpnctl=no\nstate_dir=no\nusers_file=no\nsecrets=0\n',
    );
    // Absent, so the happy path installs it.
    ssh.reply('command -v docker', exitCode: 1);
    ssh.reply('download.docker.com', stdout: 'Docker version 27.3.1\n');
    ssh.reply('docker --version', exact: true, stdout: 'Docker version 27.3.1\n');
    ssh.reply('docker compose version', exact: true, stdout: 'Docker Compose v5.5.1\n');
    ssh.reply('git clone', stdout: 'head=d1a9613\n');
    ssh.reply('stage=base', stdout: 'ok\n');
    ssh.reply('stage=code', stdout: 'ok\n');
    ssh.reply('vpnctl --help', stdout: '');
    ssh.reply('setsid', stdout: 'armed=4242\n');
    ssh.reply(
      'ufw allow',
      stdout: 'ufw was inactive; enabled it (existing rules kept, not reset)\n'
          'Status: active\n',
    );
    ssh.reply('kill -TERM', stdout: '');
    ssh.reply(
      'vpnctl apply',
      stdout: '{"schema":1,"ok":true,"rendered":"rendered-1",'
          '"enabled_protocols":["vless-reality","hysteria2"]}\n',
    );
    ssh.reply('protocol list', stdout: protocolListJson);
    ssh.reply('served()', stdout: 'bound=10443/tcp\nbound=20443/udp\n');
    ssh.reply('smoke.sh', stdout: '{"schema":1,"ok":true,"checks":[]}\n');
    return ssh;
  }

  /// Two protocols on, one off. The off one's ports must never be waited for:
  /// nothing binds 500/udp when ikev2 is disabled, and a readiness wait that
  /// asked for it would time out on a perfectly healthy server.
  static const String protocolListJson = '{"schema":1,"ok":true,"protocols":['
      '{"name":"vless-reality","enabled":true,"ports":["10443/tcp"],'
      '"kind":"singbox","summary":"","notes":""},'
      '{"name":"hysteria2","enabled":true,"ports":["20443/udp"],'
      '"kind":"singbox","summary":"","notes":""},'
      '{"name":"ikev2","enabled":false,"ports":["500/udp","4500/udp","1701/udp"],'
      '"kind":"compose","summary":"","notes":""}]}\n';

  static const String target = 'root@scripted:22';

  final List<_Rule> _rules = <_Rule>[];

  /// Every program that ran, in order, across every connection.
  final List<String> commands = <String>[];

  /// Every connection handed out, in order.
  final List<ScriptedConnection> connections = <ScriptedConnection>[];

  int connects = 0;

  /// The policy the tests hand to the Provisioner: asks, and the prompt answers
  /// [answer]. A test that wants a refusal sets [answer], and one that wants no
  /// prompt at all builds its own `HostKeyPolicy`.
  late final HostKeyPolicy hostKeys;

  /// What the prompt says. The default is the everyday case -- somebody looks
  /// at a fingerprint and taps yes -- not a policy that trusts silently.
  HostKeyDecision answer = HostKeyDecision.trust;

  /// Every question the prompt was asked, and every key it was told to
  /// remember. Both are assertions about how often a human is bothered.
  final List<HostKeyQuestion> questions = <HostKeyQuestion>[];
  final List<SshHostKey> remembered = <SshHostKey>[];

  /// Every policy [connect] was handed. A connect that was given none cannot
  /// happen -- it does not compile -- so this is about which one.
  final List<HostKeyPolicy> policies = <HostKeyPolicy>[];

  /// The key the first connection presents.
  SshHostKey offeredHostKey = scriptedHostKey;

  /// The key every LATER connection presents, when a test wants the prover to
  /// reach a different machine than the primary did.
  SshHostKey? keyAfterFirst;

  /// A connector whose verification callback is synchronous: it aborts the
  /// handshake and throws [HostKeyUnknownError] instead of awaiting a human.
  /// The second half of the contract in `SshConnector.connect`.
  bool askViaThrow = false;

  /// A connector that ignores the policy entirely and connects to whatever
  /// answered -- dartssh2 with no `onVerifyHostKey`. The layer has to catch it.
  bool ignorePolicy = false;

  /// After this many successful connections, [connect] throws. Null never
  /// refuses. Set to 1 to keep the first connection and lose every fresh one --
  /// which is what a firewall that locked us out looks like from here.
  int? refuseConnectsAfter;

  /// Hands every connection the same transport id: a connector that pooled or
  /// multiplexed. The firewall step has to refuse this as a proof.
  bool poolConnections = false;

  /// Once a program matching this has run on a connection, that connection is
  /// dead and every later command on it throws. `ufw enable` severing the
  /// session that issued it is the state the firewall step exists to survive,
  /// and the disarm must not need that session.
  String? severAfter;

  void reply(
    String match, {
    int exitCode = 0,
    String stdout = '',
    String stderr = '',
    bool exact = false,
  }) {
    _rules.add(_Rule(match, exact, <CommandResult>[
      CommandResult(exitCode: exitCode, stdout: stdout, stderr: stderr),
    ]));
  }

  /// One answer per call, the last repeating: a port that is pending twice and
  /// then bound.
  void replyEach(String match, List<CommandResult> results, {bool exact = false}) {
    _rules.add(_Rule(match, exact, results));
  }

  /// Makes the command matching [match] exit non-zero.
  void fail(
    String match, {
    int exitCode = 1,
    String stdout = '',
    String stderr = '',
    bool exact = false,
  }) {
    reply(match, exitCode: exitCode, stdout: stdout, stderr: stderr, exact: exact);
  }

  CommandResult _respondTo(String program) {
    for (final _Rule rule in _rules.reversed) {
      if (rule.matches(program)) return rule.take();
    }
    return const CommandResult(exitCode: 0, stdout: '', stderr: '');
  }

  bool ran(String match) => commands.any((String c) => c.contains(match));

  int countOf(String match) =>
      commands.where((String c) => c.contains(match)).length;

  /// Position of the first program containing [match], or -1. Ordering
  /// assertions read as `expect(indexOf(a), lessThan(indexOf(b)))`.
  int indexOf(String match) =>
      commands.indexWhere((String c) => c.contains(match));

  @override
  Future<SshConnection> connect(HostKeyPolicy policy) async {
    policies.add(policy);
    final int? limit = refuseConnectsAfter;
    if (limit != null && connects >= limit) {
      connects++;
      throw ScriptedConnectionRefused('connection refused (scripted)');
    }
    connects++;
    final SshHostKey offered =
        connects == 1 ? offeredHostKey : (keyAfterFirst ?? offeredHostKey);
    if (!ignorePolicy) {
      if (askViaThrow) {
        if (!policy.accepts(offered)) {
          // Aborted before authentication: nothing was sent, and the caller is
          // handed the key to ask about.
          throw HostKeyUnknownError(
            question: HostKeyQuestion(
              target: target,
              offered: offered,
              pinned: policy.pinned,
            ),
          );
        }
      } else {
        // The async path: the client can await, so it asks during the exchange
        // and connects only if the answer was yes.
        await policy.verify(offered);
      }
    }
    final ScriptedConnection connection = ScriptedConnection(
      this,
      poolConnections ? 'transport-pooled' : 'transport-$connects',
      offered,
    );
    connections.add(connection);
    return connection;
  }
}

class ScriptedConnection implements SshConnection, SshSession {
  ScriptedConnection(this._ssh, this.transportId, this.hostKey);

  final ScriptedSsh _ssh;

  @override
  final String transportId;

  @override
  final SshHostKey hostKey;

  /// What ran on THIS connection. The global log says what ran; this says
  /// where, which is the whole question the disarm turns on.
  final List<String> commands = <String>[];

  bool closed = false;
  bool severed = false;

  /// One object is both, so a test can see which connection ran what.
  @override
  SshSession get session => this;

  @override
  Future<CommandResult> run(List<String> argv) async {
    if (closed) {
      throw StateError('a command ran on a closed connection: $argv');
    }
    if (severed) {
      throw ScriptedConnectionRefused('this connection was severed (scripted)');
    }
    // Everything this layer sends is `sh -c <program>`; the prover sends a bare
    // argv. Recording the program rather than the argv is what lets the
    // assertions read like the shell they are about.
    final String program =
        argv.length == 3 && argv[0] == 'sh' && argv[1] == '-c' ? argv[2] : argv.join(' ');
    _ssh.commands.add(program);
    commands.add(program);
    final CommandResult result = _ssh._respondTo(program);
    final String? sever = _ssh.severAfter;
    if (sever != null && program.contains(sever)) {
      severed = true;
    }
    return result;
  }

  @override
  Future<void> close() async {
    closed = true;
  }
}

/// Time that moves only when something sleeps.
///
/// The readiness wait polls for minutes and the prover retries with a gap; a
/// suite that really waited for either is a suite nobody runs, and the one that
/// guards the lockout path is the one that must always be run.
class FakeClock extends ProvisionClock {
  DateTime _now = DateTime.utc(2026, 9, 13);

  /// Every sleep this clock was asked for, in order.
  final List<Duration> slept = <Duration>[];

  @override
  DateTime now() => _now;

  @override
  Future<void> sleep(Duration duration) async {
    slept.add(duration);
    _now = _now.add(duration);
  }
}
