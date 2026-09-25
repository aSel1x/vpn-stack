// Every model, against the payload the server really prints.
//
// "Really" is now literal: every fixture these tests parse is generated from
// cli.py by tests/test_json_contract.py, which then holds cli.py to it. So a
// field name asserted here is one the server emits today, and not one somebody
// transcribed from memory -- which is how this file came to assert IKEv2
// bundles named `kate.p12` and a dnstt card with four fields, neither of which
// any server has ever printed.
//
// The happy paths are here to pin field names: `enabled` on status is the
// protocol list, `enabled` on a user payload is that person's flag, and
// `enabled_protocols` is apply's -- three near-identical keys that have
// already collided once inside emit(**result).
//
// Two values in the fixtures are placeholders, both named in
// test_json_contract.py's `_redact`: the candidate directory name (a clock plus
// mkdtemp randomness) and the state directory (a pytest tmpdir). They keep
// their shape and their key, so they are asserted by shape here.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/control.dart';
// Not re-exported by the barrel: these are what a model throws before Vpnctl
// has attached the argv and the payload to it.
import 'package:vpn_stack_app/control/json.dart';

import 'control_fakes.dart';

Map<String, Object?> _json(String text) =>
    jsonDecode(text) as Map<String, Object?>;

void main() {
  group('status', () {
    test('parses every field', () async {
      final ServerStatus status =
          await Vpnctl(FakeSsh.replying(statusJson)).status();
      expect(status.stateDir, '/etc/vpn-stack');
      expect(status.isServer, isTrue);
      // A redacted placeholder, so the shape is what there is to assert.
      expect(status.rendered, startsWith('rendered-'));
      expect(status.enabled, <String>['vless-reality', 'hysteria2', 'ikev2']);
      // The names of revocations that could not run when they were asked for.
      // Non-empty in the fixture on purpose: an always-empty list proves
      // nothing about whether this can read a full one, and this is the field
      // that says somebody's certificate may still work.
      expect(status.revokePending, <String>['oldphone']);
      expect(status.users, 2);
      expect(status.usersEnabled, 1);
      expect(status.ikev2Running, isTrue);
    });

    test('a server that has never applied has a null rendered tree', () async {
      const String payload = '{"schema": 1, "ok": true, '
          '"state_dir": "/etc/vpn-stack", "is_server": true, '
          '"rendered": null, "enabled": [], "revoke_pending": [], '
          '"users": 0, "users_enabled": 0, "ikev2_running": false}';
      final ServerStatus status =
          await Vpnctl(FakeSsh.replying(payload)).status();
      expect(status.rendered, isNull);
      expect(status.enabled, isEmpty);
    });
  });

  group('user list', () {
    test('parses rows and leaves created_at as the server wrote it', () async {
      final List<VpnUser> users =
          await Vpnctl(FakeSsh.replying(userListJson)).listUsers();
      expect(users.length, 2);
      expect(users[0].name, 'asel1x');
      expect(users[0].enabled, isTrue);
      expect(users[0].ikev2Provisioned, isTrue);
      expect(users[0].createdAt, '2026-09-06T09:14:02Z');
      expect(users[1].name, 'guest.phone');
      expect(users[1].enabled, isFalse);
    });

    test('secrets are absent unless they were asked for', () async {
      final List<VpnUser> plain =
          await Vpnctl(FakeSsh.replying(userListJson)).listUsers();
      expect(plain[0].secrets, isNull);

      final List<VpnUser> shown =
          await Vpnctl(FakeSsh.replying(userListSecretsJson))
              .listUsers(showSecrets: true);
      expect(shown[0].secrets, isNotNull);
      expect(shown[0].secrets!.vlessUuid,
          '6f1d2c3b-4a59-4e87-9c10-2b7f5d0e8a41');
      expect(shown[0].secrets!.l2tpPassword,
          '0b7e5a1c9d34f8621ae0cc73b45d19f2');
    });

    test('a row with some credentials but not others is a damaged database',
        () {
      expect(
        () => VpnUser.fromJson(_json('{"name": "kate", "enabled": true, '
            '"ikev2_provisioned": false, "created_at": "x", '
            '"vless_uuid": "u"}')),
        throwsA(isA<PayloadFormatException>().having(
            (PayloadFormatException e) => e.reason,
            'reason',
            allOf(contains('hysteria2_password'), contains('l2tp_password')))),
      );
    });
  });

  group('protocol list', () {
    test('parses rows, ports as the server formatted them', () async {
      final List<ProtocolEntry> protocols =
          await Vpnctl(FakeSsh.replying(protocolListJson)).listProtocols();
      // Registry order, every protocol, enabled or not: `protocol list` is the
      // screen that offers the ones that are off, so a filtered payload would
      // make them unreachable.
      expect(protocols.map((ProtocolEntry p) => p.name),
          <String>['vless-reality', 'hysteria2', 'ikev2', 'dnstt']);
      expect(protocols[0].ports, <String>['10443/tcp']);
      expect(protocols[0].kind, 'singbox');
      expect(protocols[0].isContainer, isFalse);
      expect(protocols[1].ports, <String>['20443/udp']);
      expect(protocols[1].isContainer, isFalse);
      expect(protocols[2].ports, <String>['500/udp', '4500/udp', '1701/udp']);
      expect(protocols[2].isContainer, isTrue);
      expect(protocols[3].enabled, isFalse);
      expect(protocols[3].notes, contains('delegated zone'));
    });
  });

  group('apply', () {
    test('parses the result and its ikev2 reconciliation', () async {
      final ApplyResult result =
          await Vpnctl(FakeSsh.replying(applyJson)).apply();
      expect(result.rendered, startsWith('rendered-'));
      expect(result.enabledProtocols,
          <String>['vless-reality', 'hysteria2', 'ikev2']);
      expect(result.restarted, isTrue);
      expect(result.configChanged, <String>['ikev2', 'sing-box']);
      expect(result.convergePending, isFalse);
      expect(result.ready, <String>['all 5 port(s) bound']);
      expect(result.portsReady, isTrue);
      expect(result.portsBound, isTrue);
      expect(result.ikev2Reconcile!.ran, isTrue);
      expect(result.ikev2Reconcile!.failed, isEmpty);
      // `ports_ready` is declared and consumed now, so it is no longer one of
      // the keys this payload merely tolerates -- which is the point of the
      // carve-out shrinking rather than growing.
      expect(result.unknownKeys, isNot(contains('ports_ready')));
      // The carve-out, doing its job for the rest. `apply` gained one boolean
      // per converge step so a caller can find out whether the server is
      // serving without pattern-matching English; [ApplyResult] does not
      // declare the other three, and it must not refuse the payload for that,
      // because these keys arrive on a receipt for work that has already
      // happened. Anything OUTSIDE this set is a key nobody has looked at,
      // which is what this pins.
      expect(
        result.unknownKeys,
        everyElement(isIn(<String>[
          'teardown_ok',
          'firewall_ok',
          'forwarding_ok',
          'not_running',
        ])),
      );
    });

    test('the verdict is the boolean, not the wording of the prose', () {
      // The whole reason `ports_ready` exists. `composectl.wait_ready`'s
      // success note is English for a person, and somebody rewording it is not
      // making a protocol change -- but a client that decided health by
      // matching "all " against it would start calling this healthy server
      // dead on that edit alone.
      final ApplyResult reworded = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": ["ikev2"], '
          '"restarted": true, "config_changed": [], "converge_pending": false, '
          '"ready": ["every expected port is serving"], "ports_ready": true}'));
      expect(reworded.portsBound, isTrue);

      // And the other way: a payload whose prose starts with "all " while the
      // server says the wait failed. The boolean is what the server measured.
      final ApplyResult contradicted = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": ["ikev2"], '
          '"restarted": true, "config_changed": [], "converge_pending": false, '
          '"ready": ["all 5 port(s) bound"], "ports_ready": false}'));
      expect(contradicted.portsBound, isFalse);
    });

    test('a server too old to send ports_ready still gets an answer', () {
      // The fallback, and the only thing keeping it alive: an app newer than
      // the server it is pointed at must not report every apply as "ports
      // never bound". It goes when no such server is left.
      final ApplyResult old = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": ["ikev2"], '
          '"restarted": true, "config_changed": [], "converge_pending": false, '
          '"ready": ["all 5 port(s) bound"]}'));
      expect(old.portsReady, isNull);
      expect(old.portsBound, isTrue);
      expect(old.unknownKeys, isEmpty);
    });

    test('null config_changed is not the same answer as an empty one', () {
      final ApplyResult nothingToCompare = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": [], "restarted": true, '
          '"config_changed": null, "converge_pending": false}'));
      expect(nothingToCompare.configChanged, isNull);

      final ApplyResult comparedAndIdentical = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": [], "restarted": true, '
          '"config_changed": [], "converge_pending": false}'));
      expect(comparedAndIdentical.configChanged, isEmpty);
    });

    test('a port that never bound is visible, because apply only warns',
        () async {
      const String payload = '{"schema": 1, "ok": true, "rendered": "r", '
          '"enabled_protocols": ["ikev2"], "restarted": true, '
          '"config_changed": [], "converge_pending": false, '
          '"ready": ["500/udp still not bound after 240s"]}';
      final ApplyResult result =
          await Vpnctl(FakeSsh.replying(payload)).apply();
      expect(result.portsBound, isFalse);
      expect(result.ready!.single, contains('still not bound'));
    });

    test('a reconcile that could not observe anything says so', () {
      final ApplyResult result = ApplyResult.fromJson(_json(
          '{"rendered": "r", "enabled_protocols": [], "restarted": true, '
          '"config_changed": null, "converge_pending": false, '
          '"ikev2_reconcile": {"skipped": "listclients failed", '
          '"error": "Error: No such container"}}'));
      expect(result.ikev2Reconcile!.ran, isFalse);
      expect(result.ikev2Reconcile!.skipped, 'listclients failed');
      expect(result.ikev2Reconcile!.added, isEmpty);
    });
  });

  group('user mutations', () {
    test('user add carries the name and the apply that followed it', () async {
      final UserMutation added =
          await Vpnctl(FakeSsh.replying(userAddJson)).addUser('kate');
      expect(added.user, 'kate');
      expect(added.apply.rendered, startsWith('rendered-'));
      expect(added.apply.ikev2Reconcile!.ran, isTrue);
    });

    test("user enable's `enabled` is the person, not the protocol list",
        () async {
      final UserEnablement result =
          await Vpnctl(FakeSsh.replying(userEnableJson))
              .setUserEnabled('kate', enabled: true);
      expect(result.enabled, isTrue);
      expect(result.apply.enabledProtocols,
          <String>['vless-reality', 'hysteria2', 'ikev2']);
    });
  });

  group('protocol toggle', () {
    test('a change carries an apply result', () async {
      final ProtocolToggle toggled =
          await Vpnctl(FakeSsh.replying(protocolOnJson))
              .setProtocol('dnstt', enabled: true);
      expect(toggled.changed, isTrue);
      expect(toggled.apply!.rendered, startsWith('rendered-'));
      // `protocol on dnstt` brings three containers with it, and the diff names
      // the two whose rendered input is new.
      expect(toggled.apply!.enabledProtocols, contains('dnstt'));
    });

    test('already on: no apply result, and none is invented', () async {
      final ProtocolToggle toggled =
          await Vpnctl(FakeSsh.replying(protocolUnchangedJson))
              .setProtocol('dnstt', enabled: true);
      expect(toggled.changed, isFalse);
      expect(toggled.apply, isNull);
    });
  });

  group('share items', () {
    test('the three shapes come back as three types', () async {
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportJson)).exportUser('kate');
      expect(bundle.user, 'kate');
      expect(bundle.host, '203.0.113.10');

      final ShareItem uri = bundle.byProtocol['vless-reality']!.single;
      expect(uri, isA<ShareUri>());
      expect((uri as ShareUri).uri, startsWith('vless://'));
      expect(uri.label, 'VLESS + REALITY');
      // The PNG the server rendered, not one this app encoded: \x89PNG\r\n.
      // A real one, because the fixture went through export.png_bytes().
      expect(uri.qrPng!.take(4), <int>[0x89, 0x50, 0x4e, 0x47]);
      expect(uri.qrPng!.length, greaterThan(100));

      // Three bundles, not two, and `<name>-ikev2.<ext>` rather than
      // `<name>.<ext>`: ikev2.sh --exportclient writes all three for every
      // client, and that suffix is what `bundle_label` matches on to say which
      // platform a file is for. The hand-typed version of this fixture had both
      // wrong, so it asserted labels no payload carries.
      final List<ShareItem> bundles = bundle.byProtocol['ikev2']!;
      expect(bundles.length, 3);
      expect(bundles.every((ShareItem i) => i is ShareFile), isTrue);
      expect(bundles.map((ShareItem i) => (i as ShareFile).filename),
          <String>['kate-ikev2.p12', 'kate-ikev2.sswan', 'kate-ikev2.mobileconfig']);
      expect((bundles[2] as ShareFile).label, 'iOS/macOS');
      expect(utf8.decode((bundles[2] as ShareFile).content), '<?xml');

      // TWO cards, not one: dnstt's share() emits the phone form and the
      // laptop's two commands. A test that read `.single` here passed only
      // because the fixture it read had been typed rather than generated, and
      // the second card -- the only instructions a laptop user gets -- was
      // invisible to every screen built against it.
      final List<ShareItem> cards = bundle.byProtocol['dnstt']!;
      expect(cards.length, 2);
      expect(cards.every((ShareItem i) => i is ShareFields), isTrue);
      final ShareFields phone = cards.first as ShareFields;
      expect(phone.fields.length, 5);
      expect(phone.fields.first.setting, 'Nameserver / domain');
      expect(phone.fields.last.setting, 'SSH password');
      // Emitted as fields and never as a uri: DNSTT-over-SSH has no import
      // format, so a QR of it is a QR nothing can read.
      expect(phone.fields.map((ShareField f) => f.setting),
          contains('DNS resolver'));
    });

    test('only URI items are offered to a tunnel engine, in payload order',
        () async {
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportJson)).exportUser('kate');
      // Both URI protocols, in the order the payload carries them, and neither
      // the ikev2 bundles nor the dnstt cards. That order is `st.enabled`'s --
      // registry order on a server whose state.json came from state.default(),
      // which is the fixture, but `protocol on` writes a SORTED list, so one
      // toggle makes it alphabetical for good. Nothing here may depend on which
      // of the two it is beyond "the payload decides".
      expect(bundle.importUris,
          <String>['vless://', 'hysteria2://'].map((String s) => startsWith(s)));
      expect(bundle.complete, isTrue);
      expect(bundle.failed, isEmpty);
    });

    test('a protocol that failed to export is named, not silently missing',
        () async {
      // ikev2 is the only name that can appear in `failed`: it is the one
      // protocol whose bundles come out of a container, and the pure share()s
      // either return items or raise. The hand-typed fixture said
      // `["hysteria2"]`, which cli.py cannot produce.
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportPartialJson)).exportUser('kate');
      expect(bundle.complete, isFalse);
      expect(bundle.failed, <String>['ikev2']);
      expect(bundle.byProtocol.containsKey('ikev2'), isFalse);
      // And what did work is still in there, which is why this is not a refusal.
      expect(bundle.byProtocol.keys, contains('vless-reality'));
    });

    test('an item in two shapes at once is refused rather than guessed', () {
      expect(
        () => ShareItem.fromJson(_json(
            '{"label": "dnstt", "uri": "dnstt://x", "fields": [["a", "b"]]}')),
        throwsA(isA<PayloadFormatException>().having(
            (PayloadFormatException e) => e.reason,
            'reason',
            contains('exactly one of uri, filename or fields'))),
      );
    });

    test('an item in no shape at all is refused too', () {
      expect(
        () => ShareItem.fromJson(_json('{"label": "dnstt"}')),
        throwsA(isA<PayloadFormatException>()),
      );
    });

    test('a file bundle with no bytes is not a download', () {
      expect(
        () => ShareItem.fromJson(
            _json('{"label": "iOS/macOS", "filename": "kate.p12"}')),
        throwsA(isA<PayloadFormatException>().having(
            (PayloadFormatException e) => e.reason, 'reason', contains('b64'))),
      );
    });

    test('a URI with no QR is still a URI', () {
      final ShareItem item =
          ShareItem.fromJson(_json('{"label": "l", "uri": "vless://x"}'));
      expect((item as ShareUri).qrPng, isNull);
      expect(item.uri, 'vless://x');
    });

    test('base64 that does not decode names the field it was in', () {
      expect(
        () => ShareItem.fromJson(_json(
            '{"label": "l", "filename": "kate.p12", "b64": "not base64!!"}')),
        throwsA(isA<PayloadFormatException>().having(
            (PayloadFormatException e) => e.reason,
            'reason',
            allOf(contains('b64'), contains('base64')))),
      );
    });
  });

  // -------------------------------------------------------- the whole corpus

  // The other half of the contract. tests/test_json_contract.py proves cli.py
  // still prints each of these files; this proves the app still accepts each of
  // them. Neither alone is enough: the Python side would happily hold cli.py to
  // a payload no model can read, and the group above only reaches the fixtures
  // somebody remembered to name.
  //
  // So it walks the directory. A fixture added on the Python side lands here as
  // a failure until it is either given a parser or declared unparsed below --
  // which is the one thing a per-fixture test list cannot do.
  group('every generated fixture', () {
    /// Fixtures the app has no model for YET. Each needs a reason, because the
    /// list is how a command silently goes unread: it is not a to-do list, it is
    /// the set of server commands nothing in this app calls.
    const Map<String, String> unmodelled = <String, String>{
      // `bootstrap` mints the keyring. The app never runs it on an existing
      // server -- provisioning does, through provision-host.sh -- and its
      // payload is one prose `message`.
      'bootstrap.json': 'run by provisioning, never by the app',
      // `ikev2 list-clients` is a diagnostic: its payload is the image's own
      // --listclients text, unparsed on purpose, and `apply` already reports
      // the reconciliation the app cares about.
      'ikev2-list-clients.json': 'a diagnostic, and its output is opaque text',
    };

    /// Every fixture a command answers with, and the call that reads it.
    ///
    /// A refusal is in here too: `ok: false` at exit 1 has to reach the app as
    /// a [VpnctlCommandError] carrying the sentence, not as a parse failure.
    final Map<String, Future<void> Function(Vpnctl v)> readers =
        <String, Future<void> Function(Vpnctl v)>{
      'status.json': (Vpnctl v) => v.status(),
      'user-list.json': (Vpnctl v) => v.listUsers(),
      'user-list-secrets.json': (Vpnctl v) => v.listUsers(showSecrets: true),
      'protocol-list.json': (Vpnctl v) => v.listProtocols(),
      'apply.json': (Vpnctl v) => v.apply(),
      'user-add.json': (Vpnctl v) => v.addUser('kate'),
      'user-rm.json': (Vpnctl v) => v.removeUser('guest.phone'),
      'user-enable.json': (Vpnctl v) =>
          v.setUserEnabled('guest.phone', enabled: true),
      'user-disable.json': (Vpnctl v) =>
          v.setUserEnabled('asel1x', enabled: false),
      'protocol-on.json': (Vpnctl v) => v.setProtocol('dnstt', enabled: true),
      'protocol-off.json': (Vpnctl v) => v.setProtocol('ikev2', enabled: false),
      'protocol-unchanged.json': (Vpnctl v) =>
          v.setProtocol('vless-reality', enabled: true),
      'user-export.json': (Vpnctl v) => v.exportUser('kate'),
      'user-export-partial.json': (Vpnctl v) => v.exportUser('kate'),
    };

    const Set<String> refusals = <String>{
      'apply-missing-secrets.json',
      'user-export-no-such-user.json',
    };

    List<String> names() => (Directory('test/fixtures')
            .listSync()
            .whereType<File>()
            .map((File f) => f.uri.pathSegments.last)
            .where((String n) => n.endsWith('.json'))
            .toList()
          ..sort());

    test('the directory is not empty, so a silent skip is not a pass', () {
      // Without this, a fixtures directory that failed to check out turns every
      // assertion below into a loop over nothing and the whole group is green.
      expect(names().length, greaterThan(10));
    });

    test('is either parsed by a command or declared unparsed', () {
      final Set<String> accounted = <String>{
        ...readers.keys,
        ...refusals,
        ...unmodelled.keys,
      };
      expect(names().toSet(), accounted,
          reason: 'a fixture nobody reads is a server command whose payload '
              'can change without this app noticing. Give it a reader above, '
              'or a reason in `unmodelled`.');
    });

    for (final String name in <String>[...readers.keys]) {
      test('$name parses', () async {
        await readers[name]!(Vpnctl(FakeSsh.replying(fixture(name))));
      });
    }

    for (final String name in refusals) {
      test('$name arrives as a refusal, not a parse failure', () async {
        final Vpnctl vpnctl = Vpnctl(FakeSsh.replying(fixture(name), exitCode: 1));
        await expectLater(
          vpnctl.apply(),
          throwsA(isA<VpnctlCommandError>().having(
              (VpnctlCommandError e) => e.error, 'error', isNotEmpty)),
        );
      });
    }

    for (final String name in unmodelled.keys) {
      test('$name is at least a vpnctl envelope', () {
        // No model, but it is still generated from cli.py and still committed
        // here, so the least that can be asserted is that it is the shape a
        // model would be given -- and that it did not stop being JSON.
        final Map<String, Object?> payload = _json(fixture(name));
        expect(payload['schema'], 1, reason: unmodelled[name]);
        expect(payload['ok'], isA<bool>());
      });
    }
  });
}
