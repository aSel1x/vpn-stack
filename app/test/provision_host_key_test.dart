// Who is on the other end.
//
// dartssh2's SSHClient accepts ANY host key when onVerifyHostKey is not
// supplied, and this app's second screen asks for a root password. So the seam
// grew a policy: a connector is handed one on every connect, the key it settles
// on has to be one the policy approved, and a key nobody has approved stops the
// run before a credential is sent.
//
// These tests are about that last clause. Everything else here is arranging for
// it to be checkable.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/config.dart';
import 'package:vpn_stack_app/provision/firewall.dart';
import 'package:vpn_stack_app/provision/provisioner.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/provision/step.dart';

import 'provision_fake_ssh.dart';

const ProvisionConfig config = ProvisionConfig(host: '203.0.113.7');
const String target = 'root@203.0.113.7:22';

List<ProvisionStep> connectOnly() => <ProvisionStep>[
      ProvisionStep(
        name: 'connect',
        label: 'Connecting',
        run: (ProvisionContext ctx) => ctx.openPrimary(),
      ),
    ];

/// Connect, then the firewall step -- which opens the second connection. Two
/// connections is what makes "asked once" a statement worth making.
List<ProvisionStep> connectAndProve() => <ProvisionStep>[
      ProvisionStep(
        name: 'connect',
        label: 'Connecting',
        run: (ProvisionContext ctx) => ctx.openPrimary(),
      ),
      const ProvisionStep(
        name: 'firewall',
        label: 'Closing the firewall',
        run: runFirewallStep,
      ),
    ];

Future<ProvisionResult> runWith(
  ScriptedSsh ssh,
  HostKeyPolicy hostKeys, {
  List<ProvisionStep>? steps,
}) =>
    Provisioner(
      config: config,
      connector: ssh,
      hostKeys: hostKeys,
      clock: FakeClock(),
      steps: steps ?? connectOnly(),
    ).run();

void main() {
  group('a key nobody has approved', () {
    test('is refused, and nothing is sent', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      try {
        await runWith(ssh, HostKeyPolicy.refuse(target: target));
        fail('a policy with nobody to ask must not connect');
      } on HostKeyRejectedError catch (error) {
        expect(error.asked, isFalse);
        expect(error.message, contains('nobody to ask'));
      }

      // The whole point, in two assertions: no session, no command, no
      // password. A check that happens after authentication is a check that
      // happens after the credential has gone.
      expect(ssh.connections, isEmpty);
      expect(ssh.commands, isEmpty);
    });

    test('is refused when the human says no', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.answer = HostKeyDecision.refuse;

      try {
        await runWith(ssh, ssh.hostKeys);
        fail('"no" has to mean no');
      } on HostKeyRejectedError catch (error) {
        expect(error.asked, isTrue);
        expect(error.message, contains('refused'));
      }
      expect(ssh.commands, isEmpty);
      expect(ssh.questions, hasLength(1));
    });
  });

  group('a key the human accepts', () {
    test('is asked about once per run, not once per connection', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      final ProvisionResult result =
          await runWith(ssh, ssh.hostKeys, steps: connectAndProve());

      expect(result.steps, <String>['connect', 'firewall']);
      expect(ssh.connects, 2);
      // The prover meets the same key the primary did. Asking again would
      // train people to tap through the one question that matters.
      expect(ssh.questions, hasLength(1));
      expect(ssh.questions.single.changed, isFalse);
      expect(ssh.remembered, <SshHostKey>[scriptedHostKey]);
    });

    test('is recorded in the run facts, so a report can name it', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      final ProvisionResult result = await runWith(ssh, ssh.hostKeys);

      expect(result.facts['host_key'], scriptedHostKey.fingerprint);
    });

    test('"just this once" is not persisted', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.answer = HostKeyDecision.trustOnce;

      await runWith(ssh, ssh.hostKeys);

      expect(ssh.questions, hasLength(1));
      // Nothing to store means the question comes back next time, which is the
      // right trade for somebody who was not sure.
      expect(ssh.remembered, isEmpty);
    });
  });

  group('a pinned key', () {
    test('connects with no question at all', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      final ProvisionResult result = await runWith(
        ssh,
        HostKeyPolicy.pinned(target: target, key: scriptedHostKey),
      );

      expect(result.steps, <String>['connect']);
      expect(ssh.questions, isEmpty);
    });

    test('makes a changed key a different question, and says so', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      final List<HostKeyQuestion> asked = <HostKeyQuestion>[];
      final HostKeyPolicy policy = HostKeyPolicy.ask(
        target: target,
        pinned: otherHostKey,
        prompt: (HostKeyQuestion question) async {
          asked.add(question);
          return HostKeyDecision.refuse;
        },
      );

      await expectLater(
        runWith(ssh, policy),
        throwsA(isA<HostKeyRejectedError>()),
      );

      expect(asked, hasLength(1));
      expect(asked.single.changed, isTrue);
      expect(asked.single.pinned, otherHostKey);
      // A rebuilt box does this too, which is why it is a question and not a
      // refusal -- but it must never read like the everyday one.
      expect(asked.single.summary, contains('CHANGED'));
      expect(asked.single.summary, contains(otherHostKey.fingerprint));
      expect(asked.single.summary, contains(scriptedHostKey.fingerprint));
    });
  });

  group('the two ways a connector can satisfy the policy', () {
    test('the asynchronous one: verify during the exchange', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      await runWith(ssh, ssh.hostKeys);

      // One TCP connection: the client could await, so it asked mid-exchange.
      expect(ssh.connects, 1);
      expect(ssh.connections, hasLength(1));
    });

    test('the synchronous one: abort, ask, connect again', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // dartssh2's verification callback cannot wait for a human, so the
      // connector aborts the handshake and hands the key back instead of
      // authenticating first.
      ssh.askViaThrow = true;

      final ProvisionResult result = await runWith(ssh, ssh.hostKeys);

      expect(result.steps, <String>['connect']);
      expect(ssh.connects, 2);
      // The aborted attempt produced no session at all -- nothing to send a
      // password down.
      expect(ssh.connections, hasLength(1));
      expect(ssh.questions, hasLength(1));
    });

    test('a connector that ignores the policy is caught and named', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // dartssh2 with no onVerifyHostKey: it connects to whatever answered.
      ssh.ignorePolicy = true;

      try {
        await runWith(ssh, HostKeyPolicy.refuse(target: target));
        fail('a connector that skips the policy must not go unnoticed');
      } on HostKeyPolicyIgnoredError catch (error) {
        expect(error.offered, scriptedHostKey);
        // It cannot un-send the credential. It can say so, which is the only
        // useful thing left.
        expect(error.message, contains('already been sent'));
      }
      expect(ssh.connections.single.closed, isTrue);
      expect(ssh.commands, isEmpty);
    });
  });

  group('the key itself', () {
    test('survives a round trip through the store', () {
      final Map<String, Object?> json = scriptedHostKey.toJson();
      expect(json['algorithm'], 'ssh-ed25519');
      expect(json['blob'], scriptedHostKey.blob);
      expect(json['fingerprint'], scriptedHostKey.fingerprint);
      expect(SshHostKey.fromJson(json).sameKeyAs(scriptedHostKey), isTrue);
    });

    test('refuses a damaged record instead of matching nothing', () {
      // An empty pin matches no key, which would silently turn pinning back
      // into a prompt on every connection.
      expect(
        () => SshHostKey.fromJson(<String, Object?>{
          'algorithm': 'ssh-ed25519',
          'blob': '',
          'fingerprint': 'SHA256:x',
        }),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => SshHostKey.fromJson(<String, Object?>{'algorithm': 'ssh-ed25519'}),
        throwsA(isA<FormatException>()),
      );
    });

    test('the pin decides, and the field a screen displays does not', () {
      // Under dartssh2 the two fields carry the same string -- the transport
      // never exposes the wire blob, so a pin IS a fingerprint -- which is
      // exactly why `sameKeyAs` has to read one nominated field rather than
      // whichever happens to be there. `fingerprint` is round-tripped through
      // the store for display; a comparison that read it would let a record
      // whose display half was edited match a key it does not identify.
      const SshHostKey lying = SshHostKey(
        algorithm: 'ssh-ed25519',
        blob: 'AAAAsomethingelse',
        fingerprint: 'SHA256:scripted1scripted1scripted1scripted1scripted',
      );
      expect(lying.fingerprint, scriptedHostKey.fingerprint);
      expect(lying.sameKeyAs(scriptedHostKey), isFalse);
    });

    test('offers no known_hosts line, because it cannot build one', () {
      // It used to offer `'$algorithm $blob'`, documented as "what a
      // known_hosts line carries after the host name". With this transport the
      // blob is the `SHA256:` fingerprint string, so that line was one no
      // known_hosts could ever use -- and nothing called it, so nothing failed.
      // A promise in a doc comment that no caller exercises is the kind that
      // survives until somebody believes it.
      expect(
        scriptedHostKey.toJson().keys.toSet(),
        <String>{'algorithm', 'blob', 'fingerprint'},
      );
      expect(scriptedHostKey.toString(), 'ssh-ed25519 ${scriptedHostKey.fingerprint}');
    });
  });
}
