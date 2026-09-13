// The argv is the contract with the server. A silent change to it is how this
// breaks: the command still runs, argparse still accepts it, and the answer is
// about something other than what the screen asked for. So every command line
// this layer can emit is written out here in full, by hand, from cli.py's
// parser -- not generated from the same builder it is checking.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/vpnctl.dart';

import 'control_fakes.dart';

void main() {
  group('argv', () {
    test('status', () async {
      final FakeSsh ssh = FakeSsh.replying(statusJson);
      await Vpnctl(ssh).status();
      expect(ssh.lastArgv, expectedArgv(<String>['status']));
    });

    test('user list, with and without secrets', () async {
      final FakeSsh ssh = FakeSsh.replying(userListJson);
      final Vpnctl vpnctl = Vpnctl(ssh);
      await vpnctl.listUsers();
      expect(ssh.lastArgv, expectedArgv(<String>['user', 'list']));

      final FakeSsh withSecrets = FakeSsh.replying(userListSecretsJson);
      await Vpnctl(withSecrets).listUsers(showSecrets: true);
      expect(withSecrets.lastArgv,
          expectedArgv(<String>['user', 'list', '--show-secrets']));
    });

    test('user add', () async {
      final FakeSsh ssh = FakeSsh.replying(userAddJson);
      await Vpnctl(ssh).addUser('kate');
      expect(ssh.lastArgv, expectedArgv(<String>['user', 'add', 'kate']));
    });

    test('user rm', () async {
      final FakeSsh ssh = FakeSsh.replying(userAddJson);
      await Vpnctl(ssh).removeUser('kate');
      expect(ssh.lastArgv, expectedArgv(<String>['user', 'rm', 'kate']));
    });

    test('user enable and disable', () async {
      final FakeSsh on = FakeSsh.replying(userEnableJson);
      await Vpnctl(on).setUserEnabled('kate', enabled: true);
      expect(on.lastArgv, expectedArgv(<String>['user', 'enable', 'kate']));

      final FakeSsh off = FakeSsh.replying(userEnableJson);
      await Vpnctl(off).setUserEnabled('kate', enabled: false);
      expect(off.lastArgv, expectedArgv(<String>['user', 'disable', 'kate']));
    });

    test('user export, alone and with both options', () async {
      final FakeSsh plain = FakeSsh.replying(exportJson);
      await Vpnctl(plain).exportUser('kate');
      expect(plain.lastArgv, expectedArgv(<String>['user', 'export', 'kate']));

      final FakeSsh narrowed = FakeSsh.replying(exportJson);
      await Vpnctl(narrowed).exportUser(
        'kate',
        protocol: 'ikev2',
        host: 'vpn.example.org',
      );
      expect(
        narrowed.lastArgv,
        expectedArgv(<String>[
          'user',
          'export',
          'kate',
          '--protocol',
          'ikev2',
          '--host',
          'vpn.example.org',
        ]),
      );
    });

    test('user export never asks for a QR', () async {
      // --qr is suppressed under --json server-side, and ASCII art in the
      // middle of the payload is how `./vpn share` broke. The PNG comes back on
      // the item instead, so there is nothing to ask for.
      final FakeSsh ssh = FakeSsh.replying(exportJson);
      await Vpnctl(ssh).exportUser('kate');
      expect(ssh.lastArgv, isNot(contains('--qr')));
    });

    test('protocol list', () async {
      final FakeSsh ssh = FakeSsh.replying(protocolListJson);
      await Vpnctl(ssh).listProtocols();
      expect(ssh.lastArgv, expectedArgv(<String>['protocol', 'list']));
    });

    test('protocol on and off', () async {
      final FakeSsh on = FakeSsh.replying(protocolOnJson);
      await Vpnctl(on).setProtocol('dnstt', enabled: true);
      expect(on.lastArgv, expectedArgv(<String>['protocol', 'on', 'dnstt']));

      final FakeSsh off = FakeSsh.replying(protocolOnJson);
      await Vpnctl(off).setProtocol('dnstt', enabled: false);
      expect(off.lastArgv, expectedArgv(<String>['protocol', 'off', 'dnstt']));
    });

    test('apply, and apply --no-restart', () async {
      final FakeSsh ssh = FakeSsh.replying(applyJson);
      await Vpnctl(ssh).apply();
      expect(ssh.lastArgv, expectedArgv(<String>['apply']));

      final FakeSsh dry = FakeSsh.replying(applyJson);
      await Vpnctl(dry).apply(restart: false);
      expect(dry.lastArgv, expectedArgv(<String>['apply', '--no-restart']));
    });
  });

  group('argv shape', () {
    test('--json comes first, so no subcommand flag can displace it', () async {
      final FakeSsh ssh = FakeSsh.replying(userListSecretsJson);
      await Vpnctl(ssh).listUsers(showSecrets: true);
      final List<String> argv = ssh.lastArgv;
      expect(argv[argv.indexOf('/usr/local/bin/vpnctl') + 1], '--json');
      expect(argv.where((String a) => a == '--json').length, 1);
    });

    test('a user name is one element, never spliced into a string', () async {
      // The server joins names into a space-separated VPN_ADDL_USERS. A name
      // that arrived as two arguments would misalign that list against the
      // password list and hand one person another's credential -- which is
      // why the name is passed as an argv element and quoted once, at the
      // transport, and why nothing here builds a command line by concatenation.
      final FakeSsh ssh = FakeSsh.replying(userAddJson);
      await Vpnctl(ssh).addUser('two words');
      expect(ssh.lastArgv.last, 'two words');
      expect(ssh.lastArgv.length, lockAndBinary.length + 3);
    });

    test('the lock is taken on every call, with a bounded wait', () async {
      final FakeSsh ssh = FakeSsh.replying(statusJson);
      await Vpnctl(ssh, lockWait: const Duration(seconds: 45)).status();
      expect(
        ssh.lastArgv.take(6),
        <String>['flock', '-w', '45', '-E', '75', '/run/vpn-stack.lock'],
      );
    });

    test('the paths are injectable, for a server that is laid out elsewhere',
        () async {
      final FakeSsh ssh = FakeSsh.replying(statusJson);
      await Vpnctl(
        ssh,
        vpnctlPath: '/opt/bin/vpnctl',
        lockPath: '/tmp/test.lock',
      ).status();
      expect(ssh.lastArgv, contains('/opt/bin/vpnctl'));
      expect(ssh.lastArgv, contains('/tmp/test.lock'));
    });
  });
}
