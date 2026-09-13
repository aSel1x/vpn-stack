// A server, as far as the control layer can tell.
//
// Every payload below is the shape cli.py's emit() really produces -- schema
// and ok, then the command's own keys -- so a change to that shape breaks these
// tests rather than somebody's phone. Not a _test.dart file on purpose: it
// holds no tests and `flutter test` should not collect it.

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

// --------------------------------------------------------------- payloads

const String statusJson = r'''
{
  "schema": 1,
  "ok": true,
  "state_dir": "/etc/vpn-stack",
  "is_server": true,
  "rendered": "rendered-1757353920",
  "enabled": ["vless-reality", "hysteria2", "ikev2"],
  "revoke_pending": ["oldphone"],
  "users": 3,
  "users_enabled": 2,
  "ikev2_running": true
}
''';

const String userListJson = r'''
{
  "schema": 1,
  "ok": true,
  "users": [
    {
      "name": "asel1x",
      "enabled": true,
      "ikev2_provisioned": true,
      "created_at": "2026-09-06T09:14:02Z"
    },
    {
      "name": "guest.phone",
      "enabled": false,
      "ikev2_provisioned": false,
      "created_at": "2026-09-07T18:41:55Z"
    }
  ]
}
''';

const String userListSecretsJson = r'''
{
  "schema": 1,
  "ok": true,
  "users": [
    {
      "name": "asel1x",
      "enabled": true,
      "ikev2_provisioned": true,
      "created_at": "2026-09-06T09:14:02Z",
      "vless_uuid": "6f1d2c3b-4a59-4e87-9c10-2b7f5d0e8a41",
      "hysteria2_password": "4f9c1e2a7b3d8055c6a1e4f70b2d9a13",
      "l2tp_password": "0b7e5a1c9d34f8621ae0cc73b45d19f2"
    }
  ]
}
''';

/// What every mutating command inlines. `enabled_protocols` is apply's list;
/// an `enabled` beside it, where there is one, belongs to the user.
const String _applyBody = r'''
  "rendered": "rendered-1757354108",
  "enabled_protocols": ["vless-reality", "hysteria2", "ikev2"],
  "restarted": true,
  "config_changed": ["ikev2", "sing-box"],
  "converge_pending": false,
  "teardown": "already down: dnstt, dnstt-sshd, dnstt-socks",
  "ready": ["all 5 port(s) bound"],
  "firewall": ["+ allow 4500/udp (ikev2)"],
  "ikev2_forwarding": "forwarding rules present for 192.168.43.0/24",
  "ikev2_reconcile": {"added": ["kate"], "revoked": [], "failed": []}
''';

const String applyJson = '{"schema": 1, "ok": true,$_applyBody}';

const String userAddJson =
    '{"schema": 1, "ok": true, "user": "kate",$_applyBody}';

const String userEnableJson =
    '{"schema": 1, "ok": true, "user": "kate", "enabled": true,$_applyBody}';

const String protocolOnJson =
    '{"schema": 1, "ok": true, "changed": true,$_applyBody}';

/// `protocol on` for something already on: it returns before rendering
/// anything, so there is no apply result in here at all.
const String protocolUnchangedJson =
    '{"schema": 1, "ok": true, "changed": false}';

const String protocolListJson = r'''
{
  "schema": 1,
  "ok": true,
  "protocols": [
    {
      "name": "vless-reality",
      "enabled": true,
      "ports": ["10443/tcp"],
      "kind": "singbox",
      "summary": "VLESS+REALITY (TCP, XTLS-Vision)",
      "notes": ""
    },
    {
      "name": "ikev2",
      "enabled": true,
      "ports": ["500/udp", "4500/udp", "1701/udp"],
      "kind": "compose",
      "summary": "IKEv2 / L2TP / Cisco IPsec",
      "notes": ""
    },
    {
      "name": "dnstt",
      "enabled": false,
      "ports": ["53/udp"],
      "kind": "compose",
      "summary": "DNS tunnel (dnstt -> containerised sshd -> SOCKS5)",
      "notes": "last resort; needs a delegated zone"
    }
  ]
}
''';

/// All three share shapes in one answer, plus a protocol whose export failed.
///
/// `ok` is false and the exit status is 0: emit() does not raise. The bundles
/// that did work are all still in here, which is why this cannot be treated as
/// a refusal.
const String exportJson = r'''
{
  "schema": 1,
  "ok": false,
  "user": "kate",
  "host": "203.0.113.10",
  "protocols": {
    "vless-reality": [
      {
        "label": "VLESS + REALITY",
        "uri": "vless://6f1d2c3b-4a59-4e87-9c10-2b7f5d0e8a41@203.0.113.10:10443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=Ak1_9qF&sid=a1b2c3d4&type=tcp&headerType=none#kate",
        "png_b64": "iVBORw0KGgo="
      }
    ],
    "ikev2": [
      {"filename": "kate.p12", "label": "Windows/Linux", "b64": "PD94bWw="},
      {"filename": "kate.mobileconfig", "label": "iOS/macOS", "b64": "PD94bWw="}
    ],
    "dnstt": [
      {
        "label": "dnstt — phone (HTTP Injector / AnyBridge, mode DNSTT → SSH)",
        "fields": [
          ["Nameserver / domain", "tun.example.net"],
          ["Public key", "3c9a0f11"],
          ["SSH username", "kate"],
          ["SSH password", "Qx7yPlum2zRt"]
        ]
      }
    ]
  },
  "failed": ["hysteria2"]
}
''';

/// die(): ok false, an `error` sentence, and whatever keys it attached.
const String missingSecretsJson = r'''
{
  "schema": 1,
  "ok": false,
  "error": "cannot render: missing secrets for hysteria2 (hysteria2.crt, hysteria2.key). Run `vpnctl bootstrap`.",
  "missing": {"hysteria2": ["hysteria2.crt", "hysteria2.key"]}
}
''';

const String noSuchUserJson = r'''
{"schema": 1, "ok": false, "error": "No such user: 'ghost'"}
''';

/// The not-the-server guard: stderr, exit 2, and no JSON at all even though
/// --json was asked for.
const String guardStderr = '''
Refusing to run user add: this does not look like the VPN server.
  /etc/vpn-stack does not exist.
''';
