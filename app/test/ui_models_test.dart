// What the models keep, and what they must throw away.
//
// Two properties, both about state that outlives the thing that produced it.
//
// `ServerSession` caches one SSH connection for the whole detail screen, which
// is right -- a dozen vpnctl calls over one handshake instead of twelve. The
// property asserted here is the other half: when the transport under it fails,
// the cache has to go. Without that, one lost connection turned the screen into
// a dead end where every later action failed against a socket that would never
// answer again, and the only way back was restarting the app.
//
// `CredentialVault` holds a root password for the life of the process and writes
// it nowhere. That is why it is a separate type from `ServerProfile`: the
// profile is the thing that gets listed, persisted and put in a log, and a
// credential riding along in all three ends up somewhere nobody intended.
//
// Neither needs a widget harness. The session takes a `ServerAccess`, which
// takes a transport, and `ScriptedSsh` from provision_fake_ssh.dart already
// plays a server that honours a host key policy -- so the vpnctl payloads from
// control_fakes.dart go over a connection a test can kill on demand.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/ui/access.dart';
import 'package:vpn_stack_app/ui/models.dart';
import 'package:vpn_stack_app/ui/ports.dart';
import 'package:vpn_stack_app/ui/server_store.dart';

import 'control_fakes.dart';
import 'provision_fake_ssh.dart';

class _OneConnectorTransport implements SshTransport {
  _OneConnectorTransport(this.connector);

  final SshConnector connector;

  @override
  SshConnector connectorFor(ServerProfile server, SshCredential credential) =>
      connector;
}

/// A server that answers every vpnctl call this screen makes.
///
/// The rules match on the program text, which for a vpnctl call is the whole
/// `flock … vpnctl --json <command>` line -- so `'--json status'` is an
/// assertion about the argv as well as a lookup.
ScriptedSsh _vpnctlServer() {
  final ScriptedSsh ssh = ScriptedSsh();
  ssh.reply('--json status', stdout: statusJson);
  ssh.reply('--json protocol list', stdout: protocolListJson);
  ssh.reply('--json user list', stdout: userListJson);
  ssh.reply('--json user export', stdout: exportJson);
  return ssh;
}

/// The pin already matches the key the scripted server presents, so no question
/// is asked. A test about connection lifetime should not also be a test about
/// host keys; ui_access_test.dart is that one.
ServerAccess _accessTo(ScriptedSsh ssh) => ServerAccess.trustOnFirstUse(
      transport: _OneConnectorTransport(ssh),
      server: const ServerProfile(
        id: 'stockholm',
        label: 'stockholm',
        host: 'scripted',
        hostKey: scriptedHostKey,
      ),
      credential: const SshPassword('never-leaves-this-test'),
      prompt: (HostKeyQuestion question) async =>
          fail('nothing should be asked about a key that matches the pin'),
      remember: (SshHostKey key) async =>
          fail('nothing should be pinned again'),
    );

void main() {
  group('a session whose transport died', () {
    test('drops the connection and reconnects on the next action', () async {
      final ScriptedSsh ssh = _vpnctlServer();
      final ServerSession session = ServerSession(access: _accessTo(ssh));
      addTearDown(session.dispose);

      expect(await session.refresh(), isTrue);
      expect(ssh.connects, 1);
      expect(session.status, isNotNull);
      expect(session.users, hasLength(2));

      // The phone changed network, or sshd timed the session out. Everything on
      // this connection throws from here.
      ssh.connections.single.severed = true;

      expect(await session.refresh(), isFalse);
      expect(session.error, isNotNull);
      // The banner has to say the connection is gone AND that this is
      // recoverable, because the failure text underneath it ("whether it ran at
      // all is unknown") reads like a server problem on its own.
      expect(session.error, contains('has been closed'));
      expect(session.error, contains('opens a new one'));
      // Let go of, not left holding a descriptor.
      expect(ssh.connections.single.closed, isTrue);
      // Nothing was reconnected on the failure path: reopening there would put
      // a second handshake inside a command the caller already lost.
      expect(ssh.connects, 1);

      expect(await session.refresh(), isTrue);
      expect(ssh.connects, 2);
      expect(session.error, isNull);
      expect(session.status, isNotNull);
    });

    test('invalidates on a share export too, which does not use the guard',
        () async {
      final ScriptedSsh ssh = _vpnctlServer();
      final ServerSession session = ServerSession(access: _accessTo(ssh));
      addTearDown(session.dispose);

      expect(await session.refresh(), isTrue);
      ssh.connections.single.severed = true;

      await session.loadShare('kate');
      expect(session.bundleFor('kate'), isNull);
      expect(session.bundleErrorFor('kate'), contains('opens a new one'));
      expect(session.isLoadingBundle('kate'), isFalse);
      expect(ssh.connects, 1);

      // `force`, because the failure left no cached bundle but the loader
      // would otherwise be free to return early on a second ask.
      await session.loadShare('kate', force: true);
      expect(ssh.connects, 2);
      expect(session.bundleErrorFor('kate'), isNull);
      expect(session.bundleFor('kate'), isNotNull);
    });

    test('keeps the connection when vpnctl itself refuses', () async {
      // The deliberate other half. A refusal arrived over a connection that
      // plainly works; tearing it down would make one rejected user name cost a
      // fresh handshake, a fresh authentication and -- on a server whose key is
      // not pinned -- a fresh question.
      final ScriptedSsh ssh = _vpnctlServer();
      ssh.fail(
        '--json user add',
        exitCode: 1,
        stdout: '{"schema": 1, "ok": false, "error": '
            '"invalid user name: \'bad name\'"}',
      );
      final ServerSession session = ServerSession(access: _accessTo(ssh));
      addTearDown(session.dispose);

      expect(await session.refresh(), isTrue);
      expect(await session.addUser('bad name'), isFalse);

      expect(session.error, contains('invalid user name'));
      expect(session.error, isNot(contains('has been closed')));
      expect(ssh.connections.single.closed, isFalse);

      expect(await session.refresh(), isTrue);
      expect(ssh.connects, 1);
    });

    test('a closed session lets go of its connection', () async {
      final ScriptedSsh ssh = _vpnctlServer();
      final ServerSession session = ServerSession(access: _accessTo(ssh));

      expect(await session.refresh(), isTrue);
      session.dispose();

      // Nothing else holds a reference to it, so this is the only chance.
      expect(ssh.connections.single.closed, isTrue);
    });
  });

  group('CredentialVault', () {
    test('holds a credential in memory and puts none of it in the store',
        () async {
      final InMemoryServerStore store = InMemoryServerStore();
      final ServersModel servers = ServersModel(store);
      addTearDown(servers.dispose);
      await servers.load();
      await servers.add(const ServerProfile(
        id: 'a',
        label: 'stockholm',
        host: '203.0.113.7',
      ));
      expect(servers.error, isNull);

      final CredentialVault vault = CredentialVault();
      addTearDown(vault.dispose);
      int notified = 0;
      vault.addListener(() => notified++);

      vault.remember('a', const SshPassword('correct-horse-battery'));
      expect(vault.holds('a'), isTrue);
      expect((vault.of('a')! as SshPassword).password,
          'correct-horse-battery');
      expect(notified, 1);

      // The whole persisted record, as the store holds it. The vault has no
      // store to write to at all -- what this pins is that the object which IS
      // persisted never grew somewhere to put one.
      final String persisted = jsonEncode(
        (await store.load()).map((ServerProfile s) => s.toJson()).toList(),
      );
      expect(persisted, isNot(contains('correct-horse-battery')));
      expect(persisted, isNot(contains('password')));
      expect(persisted, contains('203.0.113.7'));

      vault.forget('a');
      expect(vault.of('a'), isNull);
      expect(vault.holds('a'), isFalse);
      expect(notified, 2);

      // Forgetting nothing tells nobody. A notify here would rebuild every
      // watcher on a menu action that did not change anything.
      vault.forget('a');
      expect(notified, 2);
    });

    test('nothing a credential can be asked to describe is the secret', () {
      // `describe` is the only part of a credential that is allowed on screen
      // or in a provisioning log, which is the reason the type has the method
      // at all.
      expect(const SshPassword('correct-horse-battery').describe, 'password');
      expect(
        const SshPrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----').describe,
        'private key',
      );
      expect(
        const SshPrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----',
                passphrase: 'shibboleth')
            .describe,
        'private key (passphrase)',
      );
      // An empty passphrase is not a passphrase, and saying it was would send
      // somebody looking for one they never set.
      expect(
        const SshPrivateKey('pem', passphrase: '').describe,
        'private key',
      );
    });
  });
}
