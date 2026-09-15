// What a person reads when SSH fails.
//
// The layers above take the cause as `Object` on purpose and render it with
// `'$cause'` straight into their own sentence, so whatever the transport throws
// IS the sentence somebody reads on a phone. dartssh2's own errors render as a
// class name wrapped round a fragment -- and `SSHSocketError` renders as
// nothing useful at all, because the real exception is in a field.
//
// These run against dartssh2's real error types, constructed here. Nothing is
// mocked: the translation is a pure function of an exception object.

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/transport/errors.dart';
import 'package:vpn_stack_app/ui/ports.dart';

const String target = 'root@203.0.113.7:22';

void main() {
  group('asSshFailure', () {
    test('a refused credential is not reported as a broken network', () {
      // Different remedy, different failure: this is a user name or a
      // credential, not a firewall.
      final SshTransportFailure failure = asSshFailure(
        SSHAuthFailError('All authentication methods failed'),
        target: target,
        credential: const SshPassword('hunter2').describe,
      );
      expect(failure, isA<SshAuthFailure>());
      expect(failure.message, contains(target));
      expect(failure.message, contains('password'));
    });

    test('the secret is never in the sentence', () {
      // The only thing this layer is given is the word `describe` returns. A
      // provisioning log that echoes the password is a log nobody can paste
      // into an issue.
      const SshCredential credential = SshPassword('hunter2');
      final SshTransportFailure failure = asSshFailure(
        SSHAuthFailError('All authentication methods failed'),
        target: target,
        credential: credential.describe,
      );
      expect(failure.message, isNot(contains('hunter2')));
    });

    test('a socket error says what the socket said', () {
      // SSHSocketError keeps the real exception in a field and does not put it
      // in its own name: printed directly it says nothing at all.
      final SshTransportFailure failure = asSshFailure(
        SSHSocketError(Exception('Connection refused')),
        target: target,
      );
      expect(failure, isA<SshConnectFailure>());
      expect(failure.message, contains('Connection refused'));
      expect(failure.message, contains(target));
    });

    test('an aborted handshake keeps the reason it was aborted for', () {
      // This is the shape a refused host key arrives in -- the abort message is
      // generic and the reason is the whole diagnosis.
      final SshTransportFailure failure = asSshFailure(
        SSHAuthAbortError(
          'Connection closed before authentication',
          SSHHostkeyError('Hostkey verification failed'),
        ),
        target: target,
      );
      expect(
        failure.message,
        contains('Connection closed before authentication'),
      );
      expect(failure.message, contains('Hostkey verification failed'));
    });

    test('a deadline passes through with its phase intact', () {
      // Re-wrapping would bury the one thing it knows: which phase ran out.
      final SshDeadlineExceeded elapsed = SshDeadlineExceeded(
        phase: 'the SSH handshake and authentication',
        limit: const Duration(seconds: 30),
        target: target,
      );
      expect(asSshFailure(elapsed, target: target), same(elapsed));
    });

    test('anything unrecognised still names the server', () {
      final SshTransportFailure failure = asSshFailure(
        StateError('something the library did not document'),
        target: target,
      );
      expect(failure, isA<SshConnectFailure>());
      expect(failure.message, contains(target));
      expect(failure.message, contains('something the library did not'));
    });
  });

  group('the sentences themselves', () {
    test('toString is the sentence, not the class name', () {
      // `'$cause'` is how ProvisionTransportError and VpnctlTransportError
      // embed this, so toString has to be the whole of it.
      final SshSessionClosed closed = SshSessionClosed(target: target);
      expect('$closed', closed.message);
      expect('$closed', contains(target));
    });

    test('an unreadable key blames the key, and says nothing was sent', () {
      final SshCredentialUnusable unusable = SshCredentialUnusable(
        target: target,
        encrypted: true,
        cause: SSHKeyDecryptError('Failed to decrypt private key'),
      );
      expect(unusable.message, contains('passphrase'));
      expect(unusable.message, contains('Nothing was sent'));
    });
  });
}
