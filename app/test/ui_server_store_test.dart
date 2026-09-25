// What the secure store refuses, and why each refusal is not a defensive
// nicety.
//
// This is the Dart twin of `users_store.load()` on the server, whose three
// refusals are already covered by `tests/` on the Python side: a schema newer
// than the code, an unknown field, and a load that never writes. The reasoning
// is identical -- a record this code cannot read whole is a record it must not
// write back, because the next save would drop whatever it did not understand,
// and here the thing being dropped is a pinned SSH host key. A server silently
// demoted from pinned to trust-on-first-use is exactly the state somebody
// tampering with this store would want.
//
// No stub of `FlutterSecureStorage` is written here. The package ships
// `setMockInitialValues`, which swaps its platform for an in-memory map and
// hands the map's own reference to the store, so the assertions below can read
// the blob that was actually persisted -- including asserting that a refused
// load persisted nothing at all. A hand-written stub would be a second
// implementation of the same interface, free to drift from the one the app runs
// against.

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/ui/ports.dart';
import 'package:vpn_stack_app/ui/server_store.dart';

/// The one key the store reads and writes, spelled out rather than imported.
///
/// It is `v1` while the schema inside is 2, deliberately: bumping the key would
/// make an older build find nothing under its own key and show an empty server
/// list, which looks like data loss. Keeping one key is what lets the schema
/// check below refuse by name instead. A change to this string is a change to
/// that property, and this test is where it stops being silent.
const String _storageKey = 'vpn_stack.servers.v1';

const SshHostKey _pin = SshHostKey(
  algorithm: 'ssh-ed25519',
  blob: 'AAAAC3NzaC1lZDI1NTE5AAAAIStoredStoredStoredStoredStored1',
  fingerprint: 'SHA256:stored1stored1stored1stored1stored1stored1st',
);

/// Installs the in-memory platform and returns the map the store writes into.
Map<String, String> _install([String? existing]) {
  final Map<String, String> data = <String, String>{};
  if (existing != null) {
    data[_storageKey] = existing;
  }
  FlutterSecureStorage.setMockInitialValues(data);
  return data;
}

Map<String, Object?> _blobIn(Map<String, String> data) =>
    jsonDecode(data[_storageKey]!) as Map<String, Object?>;

void main() {
  group('round trip', () {
    test('every field survives, pinned host key included', () async {
      final Map<String, String> data = _install();
      final SecureServerStore store = SecureServerStore();

      await store.save(<ServerProfile>[
        ServerProfile(
          id: 'a',
          label: 'stockholm',
          host: '203.0.113.7',
          sshUser: 'admin',
          sshPort: 2222,
          provisionedAt: DateTime.utc(2026, 9, 6, 9, 14, 2),
          hostKey: _pin,
        ),
        const ServerProfile(id: 'b', label: 'spare', host: '198.51.100.4'),
      ]);

      final List<ServerProfile> read = await SecureServerStore().load();
      expect(read, hasLength(2));

      final ServerProfile first = read.first;
      expect(first.id, 'a');
      expect(first.label, 'stockholm');
      expect(first.host, '203.0.113.7');
      expect(first.sshUser, 'admin');
      // The port is part of the identity a host key question names, and it is
      // what the firewall step has to open: allowing 22 on a box whose sshd is
      // elsewhere is the lockout the deadman exists to survive.
      expect(first.sshPort, 2222);
      expect(first.sshTarget, 'admin@203.0.113.7:2222');
      expect(first.provisionedAt, DateTime.utc(2026, 9, 6, 9, 14, 2));
      expect(first.pinned, isTrue);
      expect(first.hostKey!.sameKeyAs(_pin), isTrue);
      expect(first.hostKey!.fingerprint, _pin.fingerprint);

      // Defaults, not nulls: a server added and never provisioned has no
      // vpnctl on it, and saying so beats showing an SSH failure.
      expect(read.last.sshUser, 'root');
      expect(read.last.sshPort, 22);
      expect(read.last.provisioned, isFalse);
      expect(read.last.pinned, isFalse);

      expect(data.keys, <String>[_storageKey]);
    });

    test('save writes the schema this build understands', () async {
      final Map<String, String> data = _install();

      await SecureServerStore().save(
        const <ServerProfile>[
          ServerProfile(id: 'a', label: 'a', host: '203.0.113.7'),
        ],
      );

      expect(_blobIn(data)['schema'], 2);
    });

    test('an empty store is an empty list, not a failure', () async {
      _install();
      expect(await SecureServerStore().load(), isEmpty);

      _install('   ');
      expect(await SecureServerStore().load(), isEmpty);
    });
  });

  group('refusals', () {
    test('a newer schema is refused by name, and nothing is written back',
        () async {
      const String written =
          '{"schema": 3, "servers": [{"id": "a", "label": "a", '
          '"host": "203.0.113.7", "future_field": "who knows"}]}';
      final Map<String, String> data = _install(written);

      await expectLater(
        SecureServerStore().load(),
        throwsA(
          isA<FormatException>().having(
            (FormatException e) => e.message,
            'message',
            // BOTH numbers. "Update the app" without saying which way the
            // versions run is a sentence nobody can act on.
            allOf(contains('schema 3'), contains('understands 2')),
          ),
        ),
      );

      // The load is a read. A store that rewrote anything here would be the bug
      // the message is about: the record it could not read whole would come
      // back without `future_field`, and nothing would ever know it was lost.
      expect(data[_storageKey], written);
    });

    test('an older schema loads, with no pin and no migration', () async {
      // Schema 1 had nowhere to put a host key, so every record it holds reads
      // back as "never asked" -- which prompts on the next connection. Reading
      // it as "trusted" would not, and a pin cannot be invented for a key this
      // device has never seen.
      const String written = '{"schema": 1, "servers": [{"id": "a", '
          '"label": "stockholm", "host": "203.0.113.7"}]}';
      final Map<String, String> data = _install(written);

      final List<ServerProfile> read = await SecureServerStore().load();
      expect(read.single.hostKey, isNull);
      expect(read.single.pinned, isFalse);
      expect(read.single.label, 'stockholm');
      expect(data[_storageKey], written);
    });

    test('a blob that is not an object is refused rather than guessed at',
        () async {
      for (final String written in <String>['[]', '"servers"', '42', 'null']) {
        final Map<String, String> data = _install(written);
        await expectLater(
          SecureServerStore().load(),
          throwsA(isA<FormatException>().having(
            (FormatException e) => e.message,
            'message',
            contains('not an object'),
          )),
          reason: 'stored blob was $written',
        );
        expect(data[_storageKey], written);
      }
    });

    test('a host_key that is not an object names the server it belongs to',
        () async {
      final Map<String, String> data = _install(
        '{"schema": 2, "servers": [{"id": "a", "label": "a", '
        '"host": "203.0.113.7", "host_key": "ssh-ed25519 AAAA"}]}',
      );

      await expectLater(
        SecureServerStore().load(),
        throwsA(isA<FormatException>().having(
          (FormatException e) => e.message,
          'message',
          allOf(contains('"a"'), contains('host_key')),
        )),
      );
      expect(data, hasLength(1));
    });

    test('a damaged pin fails instead of reading as no pin', () async {
      // The failure that matters. A pin with an empty blob matches nothing, so
      // treating it as absent would put a pinned server quietly back to
      // trust-on-first-use -- a prompt where there should be a refusal.
      _install(
        '{"schema": 2, "servers": [{"id": "a", "label": "a", '
        '"host": "203.0.113.7", "host_key": {"algorithm": "ssh-ed25519", '
        '"blob": "", "fingerprint": "SHA256:x"}}]}',
      );

      await expectLater(
        SecureServerStore().load(),
        throwsA(isA<FormatException>().having(
          (FormatException e) => e.message,
          'message',
          allOf(contains('damaged pinned host key'), contains('"a"')),
        )),
      );
    });
  });

  group('InMemoryServerStore', () {
    test('round trips, and hands back copies', () async {
      // Its doc calls it "for tests", and nothing imported it, which makes that
      // a claim rather than a fact. The copy is the part worth pinning: a store
      // that handed back its own list would let a model mutate persisted state
      // without saving, and the save failure path in `ServersModel` -- which
      // puts the previous list back -- depends on the two being distinct.
      final InMemoryServerStore store = InMemoryServerStore(
        const <ServerProfile>[
          ServerProfile(id: 'a', label: 'a', host: '203.0.113.7'),
        ],
      );

      final List<ServerProfile> read = await store.load();
      expect(read, hasLength(1));
      read.clear();
      expect(await store.load(), hasLength(1));

      await store.save(const <ServerProfile>[
        ServerProfile(id: 'b', label: 'b', host: '198.51.100.4'),
      ]);
      expect((await store.load()).single.id, 'b');
    });
  });
}
