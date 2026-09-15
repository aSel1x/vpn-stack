// The gate that runs inside the key exchange.
//
// This app asks for a root password on its second screen, and dartssh2 accepts
// any host key when `onVerifyHostKey` is not supplied. So the transport hands
// dartssh2 a callback that answers only what the policy can answer with nobody
// present -- no prompt, no await, no human inside a handshake -- and turns a
// refusal into a question the caller answers before connecting again.
//
// These tests drive that callback directly, which is the whole of the decision.
// They cannot drive a real key exchange; that the callback runs before
// authentication is a property of dartssh2 4.1.0's transport
// (`_handleMessageKexReply` verifies, then sends NEWKEYS), read from its
// source, not something a test here can assert.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/transport/dartssh2_transport.dart';
import 'package:vpn_stack_app/transport/exec.dart';

const String target = 'root@203.0.113.7:22';

/// What dartssh2 hands the callback: a type and an OpenSSH `SHA256:`
/// fingerprint, never the wire blob.
SshHostKey presented(String printed) =>
    sshHostKeyFrom('ssh-ed25519', utf8.encode(printed));

void main() {
  group('sshHostKeyFrom', () {
    test('the blob is the fingerprint, and says so', () {
      // dartssh2 never exposes the host key blob -- it is a local in
      // _handleMessageKexReply -- so `sameKeyAs`, which compares blobs, is a
      // SHA-256 comparison here. Asserted rather than left in a comment,
      // because a stored pin is recognisable by exactly this and whoever
      // migrates it needs the property to be true.
      final SshHostKey key = presented('SHA256:abcdef');
      expect(key.algorithm, 'ssh-ed25519');
      expect(key.fingerprint, 'SHA256:abcdef');
      expect(key.blob, key.fingerprint);
    });
  });

  group('HostKeyGate', () {
    test('accepts the pinned key, and asks nobody', () {
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.pinned(
          target: target,
          key: presented('SHA256:aa'),
        ),
        target: target,
      );
      expect(gate.verify('ssh-ed25519', utf8.encode('SHA256:aa')), isTrue);
      expect(gate.refused, isFalse);
      expect(gate.offered?.fingerprint, 'SHA256:aa');
    });

    test('refuses a key nobody has approved', () {
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.refuse(target: target),
        target: target,
      );
      expect(gate.verify('ssh-ed25519', utf8.encode('SHA256:bb')), isFalse);
      expect(gate.refused, isTrue);
    });

    test('does not ask the human from inside the exchange', () async {
      // The pre-authentication window is bounded by sshd's LoginGraceTime and
      // somebody reading a fingerprint off a provider's console is not. So the
      // prompt is never called here: the handshake is abandoned and the
      // question handed back, with nothing authenticated in between.
      int asked = 0;
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.ask(
          target: target,
          prompt: (HostKeyQuestion question) async {
            asked++;
            return HostKeyDecision.trust;
          },
        ),
        target: target,
      );
      expect(gate.verify('ssh-ed25519', utf8.encode('SHA256:cc')), isFalse);
      expect(asked, 0);
      expect(gate.refused, isTrue);
    });

    test('the question it hands back names the key and the pin it replaced',
        () {
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.pinned(
          target: target,
          key: presented('SHA256:old'),
        ),
        target: target,
      );
      expect(gate.verify('ssh-ed25519', utf8.encode('SHA256:new')), isFalse);
      final HostKeyQuestion? question = gate.question;
      expect(question, isNotNull);
      // `changed` is what access.dart refuses outright however the human
      // answers, so the gate has to report the pin it was measured against.
      expect(question!.changed, isTrue);
      expect(question.offered.fingerprint, 'SHA256:new');
      expect(question.pinned?.fingerprint, 'SHA256:old');
      expect(question.target, target);
    });

    test('a first contact is a question with no pin behind it', () {
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.ask(
          target: target,
          prompt: (HostKeyQuestion question) async => HostKeyDecision.trust,
        ),
        target: target,
      );
      expect(gate.question, isNull);
      expect(gate.verify('ssh-ed25519', utf8.encode('SHA256:dd')), isFalse);
      expect(gate.question?.changed, isFalse);
    });

    test('a pin of a different algorithm is not the same key', () {
      // A server holding both an ed25519 and an RSA host key presents whichever
      // the client asked for, which is why the connector asks for the pinned
      // algorithm first -- and why a match on the fingerprint alone must not
      // count.
      final HostKeyGate gate = HostKeyGate(
        policy: HostKeyPolicy.pinned(
          target: target,
          key: presented('SHA256:ee'),
        ),
        target: target,
      );
      expect(gate.verify('rsa-sha2-512', utf8.encode('SHA256:ee')), isFalse);
    });
  });
}
