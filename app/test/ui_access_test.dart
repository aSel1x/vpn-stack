// The changed-host-key refusal, which is the app's whole defence against
// somebody answering in the server's place.
//
// `ServerAccess.trustOnFirstUse` wraps the caller's prompt so that a CHANGED
// key is refused whatever the prompt says. That wrapper is four lines and it is
// the only thing standing between a rebuilt-or-impostor box and a root
// password, so it is asserted here rather than left to a reading of the code:
// a prompt that answers `trust` against a non-null pin must still produce a
// refusal, and must pin nothing.
//
// It needs no widget harness. `ServerAccess` takes its transport, its prompt and
// its recorder injected, which is what `ScriptedSsh` from provision_fake_ssh.dart
// is already shaped for -- it honours a host key policy the way the real
// connector does, including the synchronous-callback path dartssh2 forces.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/ui/access.dart';
import 'package:vpn_stack_app/ui/ports.dart';

import 'provision_fake_ssh.dart';

/// Hands out one connector and records what it was asked for.
///
/// `ServerAccess` is the only thing in the app that may call
/// `connectorFor`, and the recording is how a test sees that the credential it
/// supplied is the one that would have been sent.
class _OneConnectorTransport implements SshTransport {
  _OneConnectorTransport(this.connector);

  final SshConnector connector;
  final List<SshCredential> credentials = <SshCredential>[];

  @override
  SshConnector connectorFor(ServerProfile server, SshCredential credential) {
    credentials.add(credential);
    return connector;
  }
}

ServerProfile _server({SshHostKey? pinned}) => ServerProfile(
      id: 'stockholm',
      label: 'stockholm',
      host: 'scripted',
      hostKey: pinned,
    );

/// What a test saw of the human's side of the conversation.
class _Prompted {
  final List<HostKeyQuestion> asked = <HostKeyQuestion>[];
  final List<SshHostKey> remembered = <SshHostKey>[];
}

ServerAccess _accessTo(
  ScriptedSsh ssh,
  _Prompted seen, {
  SshHostKey? pinned,
  HostKeyDecision answer = HostKeyDecision.trust,
}) {
  return ServerAccess.trustOnFirstUse(
    transport: _OneConnectorTransport(ssh),
    server: _server(pinned: pinned),
    credential: const SshPassword('never-sent-in-these-tests'),
    prompt: (HostKeyQuestion question) async {
      seen.asked.add(question);
      return answer;
    },
    remember: (SshHostKey key) async {
      seen.remembered.add(key);
    },
  );
}

void main() {
  group('a host key that changed', () {
    test('is refused even when the prompt says trust', () async {
      // A different machine answering on the same address, and a pin already in
      // the record: the two conditions that make this the dangerous question.
      final ScriptedSsh ssh = ScriptedSsh()
        ..askViaThrow = true
        ..offeredHostKey = otherHostKey;
      final _Prompted seen = _Prompted();
      final ServerAccess access =
          _accessTo(ssh, seen, pinned: scriptedHostKey);

      await expectLater(access.open(), throwsA(isA<HostKeyRejectedError>()));

      // The person was still shown it. They are entitled to read the
      // explanation -- which fingerprint was pinned and which arrived -- and it
      // is their answer, not the showing, that is disregarded.
      expect(seen.asked, hasLength(1));
      expect(seen.asked.single.changed, isTrue);
      expect(seen.asked.single.summary, contains('CHANGED'));
      expect(seen.asked.single.summary, contains(scriptedHostKey.fingerprint));
      expect(seen.asked.single.summary, contains(otherHostKey.fingerprint));

      // Nothing pinned. A key recorded here would make the NEXT connection
      // silent, which is the whole attack this refusal exists to stop.
      expect(seen.remembered, isEmpty);

      // One aborted handshake, and no second attempt: the connector threw
      // before authentication, and the refusal stopped the retry that answers a
      // first-contact question.
      expect(ssh.connects, 1);
      expect(ssh.connections, isEmpty);
    });

    test('names both keys in the failure, so the refusal is diagnosable',
        () async {
      final ScriptedSsh ssh = ScriptedSsh()
        ..askViaThrow = true
        ..offeredHostKey = otherHostKey;
      final _Prompted seen = _Prompted();

      await expectLater(
        _accessTo(ssh, seen, pinned: scriptedHostKey).open(),
        throwsA(
          isA<HostKeyRejectedError>()
              .having((HostKeyRejectedError e) => e.asked, 'asked', isTrue)
              .having((HostKeyRejectedError e) => e.message, 'message',
                  allOf(contains('CHANGED'), contains('root@scripted:22'))),
        ),
      );
    });

    test('is refused on the async path too, where the policy is awaited',
        () async {
      // The other half of `SshConnector.connect`'s contract: a client that CAN
      // await asks during the key exchange. The refusal has to arrive from
      // `HostKeyPolicy.verify` there as well, or one of the two transports is
      // unguarded.
      final ScriptedSsh ssh = ScriptedSsh()..offeredHostKey = otherHostKey;
      final _Prompted seen = _Prompted();

      await expectLater(
        _accessTo(ssh, seen, pinned: scriptedHostKey).open(),
        throwsA(isA<HostKeyRejectedError>()),
      );
      expect(seen.remembered, isEmpty);
      expect(ssh.connections, isEmpty);
    });
  });

  group('first contact', () {
    test('records the key the person trusted', () async {
      final ScriptedSsh ssh = ScriptedSsh()..askViaThrow = true;
      final _Prompted seen = _Prompted();

      final SshConnection connection = await _accessTo(ssh, seen).open();

      expect(seen.asked, hasLength(1));
      expect(seen.asked.single.changed, isFalse);
      expect(seen.remembered, hasLength(1));
      expect(seen.remembered.single.sameKeyAs(scriptedHostKey), isTrue);
      expect(connection.hostKey.sameKeyAs(scriptedHostKey), isTrue);

      // Twice: the aborted exchange that produced the question, then the real
      // one once it was answered. Nothing was authenticated in between.
      expect(ssh.connects, 2);
    });

    test('trust-once connects and pins nothing', () async {
      final ScriptedSsh ssh = ScriptedSsh()..askViaThrow = true;
      final _Prompted seen = _Prompted();

      await _accessTo(ssh, seen, answer: HostKeyDecision.trustOnce).open();

      // The right trade for somebody who is not sure: it works now and the
      // question comes back next launch.
      expect(seen.remembered, isEmpty);
    });

    test('a refusal sends nothing', () async {
      final ScriptedSsh ssh = ScriptedSsh()..askViaThrow = true;
      final _Prompted seen = _Prompted();

      await expectLater(
        _accessTo(ssh, seen, answer: HostKeyDecision.refuse).open(),
        throwsA(isA<HostKeyRejectedError>()),
      );
      expect(seen.remembered, isEmpty);
      expect(ssh.connections, isEmpty);
    });

    test('asks once for the whole access, not once per connection', () async {
      // One policy per ServerAccess is deliberate: the firewall step's prover
      // opens a SECOND connection thirty seconds after the primary one, and a
      // policy per connection would ask again. The second question is the one
      // people learn to tap through.
      final ScriptedSsh ssh = ScriptedSsh()..askViaThrow = true;
      final _Prompted seen = _Prompted();
      final ServerAccess access = _accessTo(ssh, seen);

      await access.open();
      await access.open();

      expect(seen.asked, hasLength(1));
      expect(ssh.connections, hasLength(2));
    });
  });
}
