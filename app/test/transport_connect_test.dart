// Where a failure lands, and what it costs to get there.
//
// Two properties this file can hold to without a server:
//
//   - `connectorFor` is cheap and cannot throw. ports.dart says so for a
//     reason: it runs on the screen that is about to display the failure, and a
//     throw there takes that screen out.
//   - A credential this device cannot use fails BEFORE the socket is opened. A
//     PEM that will not parse is not a server problem and must not be reported
//     as one, and it should not cost a TCP connection to find out.
//
// Everything past the socket -- the key exchange, the authentication, the
// channel -- needs a real sshd and lives in nobody's unit test. There is
// deliberately no fake SSHClient here: a fake thorough enough to answer a
// handshake would only be asserting itself.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/transport/dartssh2_transport.dart';
import 'package:vpn_stack_app/transport/errors.dart';
import 'package:vpn_stack_app/ui/ports.dart';

const ServerProfile server = ServerProfile(
  id: 'a',
  label: 'box',
  // TEST-NET-3: routed nowhere, so a test that reached the network by mistake
  // would hang rather than quietly succeed against something real.
  host: '203.0.113.7',
);

void main() {
  group('connectorFor', () {
    test('cannot throw, whatever it is handed', () {
      // Including a credential that is plainly unusable: the failure belongs at
      // connect(), which is the path that already shows failures.
      expect(
        () => const Dartssh2Transport().connectorFor(
          server,
          const SshPrivateKey('this is not a PEM'),
        ),
        returnsNormally,
      );
    });

    test('hands out a new connector every call, and never pools', () {
      // The firewall step proves the rules it installed did not lock us out by
      // opening a SECOND, INDEPENDENT connection; a connector that handed back
      // something shared would make that proof meaningless.
      const Dartssh2Transport transport = Dartssh2Transport();
      const SshCredential credential = SshPassword('irrelevant');
      expect(
        transport.connectorFor(server, credential),
        isNot(same(transport.connectorFor(server, credential))),
      );
    });
  });

  group('connect', () {
    test('an unreadable private key fails before any socket is opened',
        () async {
      final SshConnector connector = const Dartssh2Transport().connectorFor(
        server,
        const SshPrivateKey('this is not a PEM'),
      );
      // No timeout on this expectation on purpose: if the key were parsed after
      // the socket instead of before it, this would hang against an
      // unroutable address rather than fail, and that is the point being made.
      await expectLater(
        connector.connect(HostKeyPolicy.refuse(target: server.sshTarget)),
        throwsA(
          isA<SshCredentialUnusable>().having(
            (SshCredentialUnusable e) => e.message,
            'message',
            allOf(contains('private key'), contains('Nothing was sent')),
          ),
        ),
      );
    });

    test('a PEM that is not a usable key is a credential failure, not a '
        'server one', () async {
      // The distinction the message draws -- unreadable versus encrypted --
      // matters because the remedy differs: one is the wrong file, the other a
      // missing word. It used to be dartssh2's call, and it got it wrong:
      // SSHKeyDecryptError also covers a malformed key with no passphrase, so
      // an unreadable key was reported as encrypted and the person was told to
      // supply a passphrase for a key that has none. The flag now comes from
      // isEncryptedPem, which reads the text, so this body -- valid base64, no
      // encryption header -- must report NOT encrypted.
      const String pem = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
          'bm90IHJlYWxseSBhIGtleQ==\n'
          '-----END OPENSSH PRIVATE KEY-----\n';
      final SshConnector connector = const Dartssh2Transport().connectorFor(
        server,
        const SshPrivateKey(pem),
      );
      await expectLater(
        connector.connect(HostKeyPolicy.refuse(target: server.sshTarget)),
        throwsA(
          isA<SshCredentialUnusable>()
              .having((SshCredentialUnusable e) => e.encrypted, 'encrypted', isFalse),
        ),
      );
    });
  });
}
