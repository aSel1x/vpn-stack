// Every model, against the payload the server really prints.
//
// The happy paths are here to pin field names: `enabled` on status is the
// protocol list, `enabled` on a user payload is that person's flag, and
// `enabled_protocols` is apply's -- three near-identical keys that have
// already collided once inside emit(**result).

import 'dart:convert';

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
      expect(status.rendered, 'rendered-1757353920');
      expect(status.enabled, <String>['vless-reality', 'hysteria2', 'ikev2']);
      expect(status.revokePending, <String>['oldphone']);
      expect(status.users, 3);
      expect(status.usersEnabled, 2);
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
      expect(protocols.map((ProtocolEntry p) => p.name),
          <String>['vless-reality', 'ikev2', 'dnstt']);
      expect(protocols[0].ports, <String>['10443/tcp']);
      expect(protocols[0].kind, 'singbox');
      expect(protocols[0].isContainer, isFalse);
      expect(protocols[1].ports, <String>['500/udp', '4500/udp', '1701/udp']);
      expect(protocols[1].isContainer, isTrue);
      expect(protocols[2].enabled, isFalse);
      expect(protocols[2].notes, contains('delegated zone'));
    });
  });

  group('apply', () {
    test('parses the result and its ikev2 reconciliation', () async {
      final ApplyResult result =
          await Vpnctl(FakeSsh.replying(applyJson)).apply();
      expect(result.rendered, 'rendered-1757354108');
      expect(result.enabledProtocols,
          <String>['vless-reality', 'hysteria2', 'ikev2']);
      expect(result.restarted, isTrue);
      expect(result.configChanged, <String>['ikev2', 'sing-box']);
      expect(result.convergePending, isFalse);
      expect(result.ready, <String>['all 5 port(s) bound']);
      expect(result.portsBound, isTrue);
      expect(result.ikev2Reconcile!.added, <String>['kate']);
      expect(result.ikev2Reconcile!.ran, isTrue);
      expect(result.unknownKeys, isEmpty);
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
      expect(added.apply.rendered, 'rendered-1757354108');
      expect(added.apply.ikev2Reconcile!.added, <String>['kate']);
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
      expect(toggled.apply!.rendered, 'rendered-1757354108');
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
      expect(uri.qrPng!.first, 0x89);
      expect(uri.qrPng!.length, 8);

      final List<ShareItem> bundles = bundle.byProtocol['ikev2']!;
      expect(bundles.length, 2);
      expect(bundles.every((ShareItem i) => i is ShareFile), isTrue);
      expect((bundles[1] as ShareFile).filename, 'kate.mobileconfig');
      expect(utf8.decode((bundles[1] as ShareFile).content), '<?xml');

      final ShareItem settings = bundle.byProtocol['dnstt']!.single;
      expect(settings, isA<ShareFields>());
      final ShareFields fields = settings as ShareFields;
      expect(fields.fields.length, 4);
      expect(fields.fields.first.setting, 'Nameserver / domain');
      expect(fields.fields.first.value, 'tun.example.net');
      expect(fields.fields.last.setting, 'SSH password');
    });

    test('only URI items are offered to a tunnel engine, in registry order',
        () async {
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportJson)).exportUser('kate');
      expect(bundle.importUris.length, 1);
      expect(bundle.importUris.single, startsWith('vless://'));
    });

    test('a protocol that failed to export is named, not silently missing',
        () async {
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportJson)).exportUser('kate');
      expect(bundle.complete, isFalse);
      expect(bundle.failed, <String>['hysteria2']);
      expect(bundle.byProtocol.containsKey('hysteria2'), isFalse);
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
}
