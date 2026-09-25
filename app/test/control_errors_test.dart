// Three failures, kept apart, because they ask different things of whoever is
// looking at the screen: retry, read the sentence, or update something.
//
// The third -- vpnctl answered and the app cannot read it -- is the one that
// will actually happen, because the server ships ahead of the app. It must
// carry the payload it choked on, or the report of it says nothing at all.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/control.dart';

import 'control_fakes.dart';

void main() {
  group('the transport failed', () {
    test('nothing ran, or we cannot know whether it did', () async {
      final Object cause = Exception('no route to host');
      await expectLater(
        Vpnctl(BrokenSsh(cause)).status(),
        throwsA(isA<VpnctlTransportError>()
            .having((VpnctlTransportError e) => e.cause, 'cause', same(cause))
            .having((VpnctlTransportError e) => e.message, 'message',
                contains('whether it ran at all is unknown'))),
      );
    });

    test('an Error from the session is still a transport failure', () async {
      // dartssh2 is behind an interface this layer defines, and what it throws
      // is not this layer's business: a session closed under us arrives as
      // whatever type the implementation chose.
      await expectLater(
        Vpnctl(BrokenSsh(StateError('session is closed'))).status(),
        throwsA(isA<VpnctlTransportError>()),
      );
    });
  });

  group('vpnctl ran and said no', () {
    test('die(): the sentence is the message, verbatim', () async {
      final FakeSsh ssh = FakeSsh.replying(noSuchUserJson, exitCode: 1);
      await expectLater(
        Vpnctl(ssh).exportUser('ghost'),
        throwsA(isA<VpnctlCommandError>()
            .having((VpnctlCommandError e) => e.error, 'error',
                "No such user: 'ghost'")
            .having((VpnctlCommandError e) => e.exitCode, 'exitCode', 1)),
      );
    });

    test('the keys die() attached come back with it', () async {
      final FakeSsh ssh = FakeSsh.replying(missingSecretsJson, exitCode: 1);
      try {
        await Vpnctl(ssh).apply();
        fail('expected a refusal');
      } on VpnctlCommandError catch (e) {
        expect(e.error, contains('vpnctl bootstrap'));
        final Object? missing = e.payload!['missing'];
        expect(missing, isA<Map<String, Object?>>());
        expect((missing! as Map<String, Object?>)['hysteria2'],
            <String>['hysteria2.crt', 'hysteria2.key']);
      }
    });

    test('the guard exits 2 with no JSON at all, and its paragraph survives',
        () async {
      // `vpnctl --json user add` on a box with no /etc/vpn-stack prints to
      // stderr and exits 2. It never claimed to be answering in JSON, so this
      // is not a protocol error -- the message is what it printed.
      final FakeSsh ssh =
          FakeSsh.replying('', exitCode: 2, stderr: guardStderr);
      await expectLater(
        Vpnctl(ssh).addUser('kate'),
        throwsA(isA<VpnctlCommandError>()
            .having((VpnctlCommandError e) => e.exitCode, 'exitCode', 2)
            .having((VpnctlCommandError e) => e.error, 'error',
                contains('does not look like the VPN server'))
            .having(
                (VpnctlCommandError e) => e.payload, 'payload', isNull)),
      );
    });

    test('a missing shim exits 127 and says so', () async {
      final FakeSsh ssh = FakeSsh.replying('',
          exitCode: 127, stderr: 'bash: /usr/local/bin/vpnctl: No such file');
      await expectLater(
        Vpnctl(ssh).status(),
        throwsA(isA<VpnctlCommandError>()
            .having((VpnctlCommandError e) => e.exitCode, 'exitCode', 127)
            .having((VpnctlCommandError e) => e.error, 'error',
                contains('No such file'))),
      );
    });

    test('a non-zero exit that printed nothing still names the command',
        () async {
      final FakeSsh ssh = FakeSsh.replying('', exitCode: 1);
      await expectLater(
        Vpnctl(ssh).status(),
        throwsA(isA<VpnctlCommandError>().having(
            (VpnctlCommandError e) => e.error,
            'error',
            allOf(contains('exited 1'), contains('vpnctl')))),
      );
    });

    test('ok:false with no error, where that cannot mean anything else',
        () async {
      final FakeSsh ssh =
          FakeSsh.replying('{"schema": 1, "ok": false, "users": []}');
      await expectLater(
        Vpnctl(ssh).listUsers(),
        throwsA(isA<VpnctlCommandError>().having(
            (VpnctlCommandError e) => e.error,
            'error',
            contains('without saying why'))),
      );
    });

    test('but on export it means a partial bundle, not a refusal', () async {
      // emit(ok=not failures) exits 0 and still carries every bundle that did
      // work. Throwing here would discard the profiles that succeeded.
      final ShareBundle bundle =
          await Vpnctl(FakeSsh.replying(exportJson)).exportUser('kate');
      expect(bundle.failed, <String>['hysteria2']);
      expect(bundle.byProtocol.keys, contains('ikev2'));
    });

    test('an export that really was refused still throws', () async {
      final FakeSsh ssh = FakeSsh.replying(noSuchUserJson, exitCode: 1);
      await expectLater(
        Vpnctl(ssh).exportUser('ghost'),
        throwsA(isA<VpnctlCommandError>()),
      );
    });

    test('a lock nobody released is its own answer', () async {
      // flock -E 75. Without it this arrives as "exited 1 and printed
      // nothing", which sends somebody looking for a bug in vpnctl.
      final FakeSsh ssh = FakeSsh.replying('', exitCode: 75);
      await expectLater(
        Vpnctl(ssh).addUser('kate'),
        throwsA(isA<VpnctlCommandError>()
            .having((VpnctlCommandError e) => e.exitCode, 'exitCode', 75)
            .having(
                (VpnctlCommandError e) => e.error,
                'error',
                allOf(contains('/run/vpn-stack.lock'),
                    contains('Nothing ran')))),
      );
    });

    test('the failing command is reproducible from the error', () async {
      final FakeSsh ssh = FakeSsh.replying(noSuchUserJson, exitCode: 1);
      try {
        await Vpnctl(ssh).addUser('two words');
        fail('expected a refusal');
      } on VpnctlCommandError catch (e) {
        expect(e.argv.last, 'two words');
        expect(e.command, contains("'two words'"));
        expect(e.command, startsWith('flock -w 300'));
      }
    });
  });

  group('vpnctl answered and this app cannot read it', () {
    test('stdout that is not JSON comes back whole, because it names the cause',
        () async {
      const String motd = 'Welcome to Ubuntu 24.04.1 LTS\n'
          '  System restart required\n';
      final FakeSsh ssh = FakeSsh.replying(motd);
      try {
        await Vpnctl(ssh).status();
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.raw, motd);
        expect(e.message, contains('Welcome to Ubuntu'));
        expect(e.reason, contains('not a JSON object'));
      }
    });

    test('a payload too big to show is described, not shown', () async {
      // A base64 client bundle is hundreds of kilobytes. The length is the one
      // fact about it worth reporting -- it is how a truncated bundle is
      // recognised -- and the bytes are how a credential reaches a bug report.
      final String filler = 'A' * 5000;
      final String huge = '{"schema": 1, "ok": true, "users": "$filler"}';
      final FakeSsh ssh = FakeSsh.replying(huge);
      try {
        await Vpnctl(ssh).listUsers();
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.raw.length, greaterThan(5000));
        expect(e.message, contains('string(5000)'));
        expect(e.message, isNot(contains(filler)));
        expect(e.message.length, lessThan(500));
      }
    });

    test('JSON that is not a vpnctl envelope', () async {
      final FakeSsh ssh = FakeSsh.replying('{"result": "ok"}');
      await expectLater(
        Vpnctl(ssh).status(),
        throwsA(isA<VpnctlProtocolError>().having(
            (VpnctlProtocolError e) => e.reason, 'reason', contains('schema'))),
      );
    });

    test('a newer schema is refused by version, and says which way to move',
        () async {
      final FakeSsh ssh = FakeSsh.replying(
          statusJson.replaceFirst('"schema": 1', '"schema": 2'));
      await expectLater(
        Vpnctl(ssh).status(),
        throwsA(isA<VpnctlSchemaError>()
            .having((VpnctlSchemaError e) => e.serverSchema, 'serverSchema', 2)
            .having((VpnctlSchemaError e) => e.message, 'message',
                contains('server is newer than the app'))),
      );
    });

    test('an unknown field in a record is refused by name', () async {
      // The same stance as users_store.load(), which refuses a database with a
      // field it does not know rather than dropping it: the field may be the
      // credential, and rendering the rest as if nothing happened is how that
      // stays invisible.
      final String payload = userListJson.replaceFirst(
          '"name": "asel1x",', '"name": "asel1x", "wireguard_key": "aGk=",');
      await expectLater(
        Vpnctl(FakeSsh.replying(payload)).listUsers(),
        throwsA(isA<VpnctlSchemaError>()
            .having((VpnctlSchemaError e) => e.unknownField, 'unknownField',
                'wireguard_key')
            .having((VpnctlSchemaError e) => e.message, 'message',
                allOf(contains('users[0]'), contains('update the app')))),
      );
    });

    test('an unknown key on a mutation receipt is named but not fatal',
        () async {
      // The one deliberate exception. This payload is printed AFTER users.json
      // was written and the containers converged; refusing to parse it would
      // report a failure for something that succeeded, and the obvious retry
      // then fails with "already exists".
      final String payload = userAddJson.replaceFirst(
          '"user": "kate",', '"user": "kate", "wg": 1,');
      final UserMutation added =
          await Vpnctl(FakeSsh.replying(payload)).addUser('kate');
      expect(added.user, 'kate');
      expect(added.apply.unknownKeys, <String>['wg']);
    });

    test('a missing field says which one, and where', () async {
      final String payload = userListJson
          .replaceFirst(',\n      "created_at": "2026-09-06T09:14:02Z"', '');
      await expectLater(
        Vpnctl(FakeSsh.replying(payload)).listUsers(),
        throwsA(isA<VpnctlProtocolError>().having(
            (VpnctlProtocolError e) => e.reason,
            'reason',
            'users[0].created_at is missing')),
      );
    });

    test('a field of the wrong type says what was expected', () async {
      final FakeSsh ssh =
          FakeSsh.replying('{"schema": 1, "ok": true, "users": 3}');
      await expectLater(
        Vpnctl(ssh).listUsers(),
        throwsA(isA<VpnctlProtocolError>().having(
            (VpnctlProtocolError e) => e.reason,
            'reason',
            contains('users: expected a list, got a number'))),
      );
    });
  });

  group('messages are safe to log', () {
    // The message is what somebody selects, copies and pastes into a bug report
    // -- and a schema error is precisely the failure whose remedy is "tell the
    // author what the server said", so it is the one that gets pasted. Building
    // it from the payload's bytes therefore published a credential every time,
    // because `user export`'s payload BEGINS with a working VLESS URI. Same
    // stance as share_uri.dart, which refuses a link without echoing it.

    /// An export payload with one field of the wrong type: parseable enough to
    /// reach the models, broken enough to be refused there.
    String brokenExport() => exportJson.replaceFirst(
        '"label": "VLESS + REALITY",', '"label": 5,');

    const String uuid = '6f1d2c3b-4a59-4e87-9c10-2b7f5d0e8a41';

    test('no refusal over an export payload echoes the uuid or the bundles',
        () async {
      try {
        await Vpnctl(FakeSsh.replying(brokenExport())).exportUser('kate');
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, isNot(contains('vless://')));
        // The .p12 has an empty password, so its bytes ARE the access.
        expect(e.message, isNot(contains('PD94bWw=')));
        // dnstt's settings are a form of plaintext fields, so the shape has to
        // hide those values too and not only the ones that look like keys.
        expect(e.message, isNot(contains('Qx7yPlum2zRt')));
      }
    });

    test('a schema refusal over an export payload echoes nothing either',
        () async {
      // The named case: a server that grew a key refuses the export BY NAME,
      // and it is the refusal whose remedy is "update the app" -- so it is the
      // one somebody screenshots. Both schema paths build their message through
      // the same describer as a plain protocol error, which is why neither can
      // carry the URI.
      final String grown = exportJson.replaceFirst(
          '"label": "VLESS + REALITY",',
          '"label": "VLESS + REALITY", "wireguard_uri": "wg://x",');
      try {
        await Vpnctl(FakeSsh.replying(grown)).exportUser('kate');
        fail('expected a schema error');
      } on VpnctlSchemaError catch (e) {
        expect(e.unknownField, 'wireguard_uri');
        expect(e.message, contains('update the app'));
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, isNot(contains('vless://')));
      }

      try {
        await Vpnctl(FakeSsh.replying(exportJson.replaceFirst(
                '"schema": 1', '"schema": 2')))
            .exportUser('kate');
        fail('expected a schema error');
      } on VpnctlSchemaError catch (e) {
        expect(e.serverSchema, 2);
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, isNot(contains('vless://')));
      }
    });

    test('but the shape is still there, so the report says what changed',
        () async {
      try {
        await Vpnctl(FakeSsh.replying(brokenExport())).exportUser('kate');
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.reason, contains('label'));
        // Key names are the contract with the server and are not secrets.
        expect(e.message, contains('protocols'));
        expect(e.message, contains('vless-reality'));
        expect(e.message, contains('png_b64'));
      }
    });

    test('raw keeps the payload whole, for a caller that needs the bytes',
        () async {
      // Redacting the exception as well as the message would mean a screen that
      // wanted to show the payload behind a deliberate tap could not.
      try {
        await Vpnctl(FakeSsh.replying(brokenExport())).exportUser('kate');
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.raw, contains(uuid));
      }
    });

    test('a credential in user list --show-secrets is not echoed either',
        () async {
      final String payload = userListSecretsJson
          .replaceFirst('"enabled": true,', '"enabled": "yes",');
      try {
        await Vpnctl(FakeSsh.replying(payload)).listUsers(showSecrets: true);
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.message, isNot(contains('4f9c1e2a7b3d8055c6a1e4f70b2d9a13')));
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, contains('hysteria2_password: string(32)'));
      }
    });

    test('a payload that arrived damaged is described, not quoted', () async {
      // Under --json the payload is one JSON object, so everything before its
      // opening brace is an MOTD or a wrapper and everything from there on is
      // payload. A truncated export answer does not parse AND begins with a
      // live URI, which is why the second half is never shown.
      final String cut =
          brokenExport().trim().substring(0, 220);
      try {
        await Vpnctl(FakeSsh.replying(cut)).exportUser('kate');
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, isNot(contains('vless://')));
        expect(e.message, contains('not shown'));
        expect(e.raw, contains(uuid));
      }
    });

    test('an MOTD in front of the payload is still shown, because that is the '
        'diagnosis', () async {
      // The reason this layer refuses to scavenge for JSON inside other output:
      // something speaking over vpnctl is a real failure and the text is the
      // only thing that names it.
      const String motd = 'Welcome to Ubuntu 24.04.1 LTS\n';
      final FakeSsh ssh = FakeSsh.replying('$motd$exportJson');
      try {
        await Vpnctl(ssh).exportUser('kate');
        fail('expected a protocol error');
      } on VpnctlProtocolError catch (e) {
        expect(e.message, contains('Welcome to Ubuntu'));
        expect(e.message, isNot(contains(uuid)));
      }
    });

    test('a non-zero exit with a damaged payload on stdout is not quoted either',
        () async {
      // The other message built from stdout. An argparse usage error or a
      // missing shim never claimed to be answering in JSON, so its text is
      // shown -- but a payload that failed to parse is still a payload.
      final FakeSsh ssh = FakeSsh.replying(
        brokenExport().trim().substring(0, 220),
        exitCode: 1,
        stderr: 'warning: ikev2 container is not running',
      );
      try {
        await Vpnctl(ssh).exportUser('kate');
        fail('expected a refusal');
      } on VpnctlCommandError catch (e) {
        expect(e.error, contains('ikev2 container is not running'));
        expect(e.message, isNot(contains(uuid)));
        expect(e.message, isNot(contains('vless://')));
      }
    });
  });

  group('the streams stay apart', () {
    test('warnings on stderr do not contaminate the payload', () async {
      // apply() warns on stderr about ports that never bound and firewall
      // reconciliation; say() is silent under --json. A parser that read both
      // streams would fail on every healthy server that had something to warn
      // about.
      final FakeSsh ssh = FakeSsh.replying(
        applyJson,
        stderr: 'warning: some ports never came up:\n  53/udp\n',
      );
      final ApplyResult result = await Vpnctl(ssh).apply();
      expect(result.rendered, 'rendered-1757354108');
    });
  });
}
