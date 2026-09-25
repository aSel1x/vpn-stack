// The sequence: does it do the right things, in the right order, and does it
// stop when one of them fails.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/config.dart';
import 'package:vpn_stack_app/provision/errors.dart';
import 'package:vpn_stack_app/provision/provisioner.dart';
import 'package:vpn_stack_app/provision/step.dart';

import 'provision_fake_ssh.dart';

const ProvisionConfig config = ProvisionConfig(host: '203.0.113.7');

/// The order is the contract. A step that moves changes what a half-finished
/// install looks like, and this is where that has to be noticed.
const List<String> expectedOrder = <String>[
  'preflight',
  'docker',
  'clone',
  'host',
  'firewall',
  'bootstrap',
  'apply',
  'readiness',
  'verify',
];

List<String> started(List<ProvisionEvent> events) => events
    .where((ProvisionEvent e) => e.phase == StepPhase.started)
    .map((ProvisionEvent e) => e.step)
    .toList();

void main() {
  group('happy path', () {
    test('runs every step in order on a bare Ubuntu box', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      final List<ProvisionEvent> events = <ProvisionEvent>[];

      final ProvisionResult result = await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run(onEvent: events.add);

      expect(result.steps, expectedOrder);
      expect(started(events), expectedOrder);
      expect(
        events.where((ProvisionEvent e) => e.phase == StepPhase.failed),
        isEmpty,
      );
      expect(result.facts['os'], 'Ubuntu 24.04.1 LTS');
      expect(result.facts['head'], 'd1a9613');
      expect(result.facts['ports'], '10443/tcp 20443/udp');
    });

    test('the steps run in the order the shell would have', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();

      // The clone has to precede both host stages, which are a script inside it.
      expect(ssh.indexOf('git clone'), lessThan(ssh.indexOf('stage=base')));
      // Arm, THEN enable. The other order is a firewall with no way back.
      expect(ssh.indexOf('setsid'), lessThan(ssh.indexOf('ufw allow')));
      // base installs ufw, so it has to come before the firewall step; code
      // mints the keyring, so it has to come after the proof. That interleaving
      // is why provision-host.sh is two stages rather than one script.
      expect(ssh.indexOf('stage=base'), lessThan(ssh.indexOf('setsid')));
      // The keyring is generated only after we know we can still get in: a
      // bootstrap that succeeds on a box we have locked ourselves out of is a
      // server that has to be rebuilt, not reconnected to.
      expect(ssh.indexOf('kill -TERM'), lessThan(ssh.indexOf('stage=code')));
      expect(ssh.indexOf('stage=code'), lessThan(ssh.indexOf('vpnctl apply')));
      expect(ssh.indexOf('vpnctl apply'), lessThan(ssh.indexOf('served()')));
      expect(ssh.indexOf('served()'), lessThan(ssh.indexOf('smoke.sh')));
    });

    test('waits only for the ports the enabled protocols claim', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();

      final String probe =
          ssh.commands.firstWhere((String c) => c.contains('served()'));
      expect(probe, contains('10443/tcp'));
      expect(probe, contains('20443/udp'));
      // ikev2 is off, and nothing binds 500/udp when it is. Waiting for it
      // would time out on a healthy server.
      expect(probe, isNot(contains('500/udp')));
    });

    test('leaves a docker that is already installed alone', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply('command -v docker'); // present
      await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();

      expect(ssh.ran('download.docker.com'), isFalse);
      expect(ssh.ran('docker compose version'), isTrue);
    });

    test('opens exactly one connection beyond the prover', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();

      expect(ssh.connects, 2);
      expect(ssh.connections.first.transportId,
          isNot(ssh.connections.last.transportId));
      // Both closed on the way out: the prover by the firewall step, the
      // primary by the runner.
      expect(ssh.connections.every((ScriptedConnection c) => c.closed), isTrue);
    });
  });

  group('preflight', () {
    test('refuses a server that already has a keyring and users', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'users_file',
        stdout: 'vpnctl=yes\nstate_dir=yes\nusers_file=yes\nsecrets=8\n',
      );
      final List<ProvisionEvent> events = <ProvisionEvent>[];

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      )
            .run(onEvent: events.add),
        throwsA(isA<AlreadyProvisionedError>()),
      );

      // Nothing may have run. Re-bootstrapping mints a new keyring and every
      // profile already handed out stops working with no error anywhere.
      expect(ssh.ran('stage=code'), isFalse);
      expect(ssh.ran('setsid'), isFalse);
      expect(ssh.ran('download.docker.com'), isFalse);
      expect(ssh.ran('git clone'), isFalse);
      expect(started(events), <String>['preflight']);
      expect(events.last.phase, StepPhase.failed);
      expect(events.last.step, 'preflight');
    });

    test('names what it found, so the refusal is actionable', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'users_file',
        stdout: 'vpnctl=yes\nstate_dir=yes\nusers_file=yes\nsecrets=8\n',
      );

      try {
        await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();
        fail('provisioning an installed server should have been refused');
      } on AlreadyProvisionedError catch (error) {
        expect(error.evidence, hasLength(2));
        expect(error.message, contains('users.json'));
        expect(error.message, contains('8 secrets'));
        expect(error.message, contains('invalidate'));
      }
    });

    test('continues on a half-finished install, which has nothing to lose',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'users_file',
        stdout: 'vpnctl=yes\nstate_dir=yes\nusers_file=no\nsecrets=0\n',
      );

      final ProvisionResult result =
          await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();

      expect(result.steps, expectedOrder);
    });

    test('refuses a box that is not Debian or Ubuntu', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'cat /etc/os-release',
        exact: true,
        stdout: 'PRETTY_NAME="Alpine Linux v3.20"\nID=alpine\n',
      );

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run(),
        throwsA(isA<UnsupportedHostError>()),
      );
      expect(ssh.ran('git clone'), isFalse);
    });

    test('refuses a connection that is not root', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply('id -u', exact: true, stdout: '1000\n');

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run(),
        throwsA(isA<UnsupportedHostError>()),
      );
      expect(ssh.ran('cat /etc/os-release'), isFalse);
    });

    test('an unreachable server fails on the first step, by name', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.refuseConnectsAfter = 0;
      final List<ProvisionEvent> events = <ProvisionEvent>[];

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      )
            .run(onEvent: events.add),
        throwsA(isA<ProvisionTransportError>()),
      );
      expect(events.last.step, 'preflight');
      expect(events.last.phase, StepPhase.failed);
    });
  });

  group('a failure mid-sequence', () {
    test('stops there instead of carrying on', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail(
        'git clone',
        exitCode: 128,
        stderr: 'fatal: could not read from remote repository',
      );
      final List<ProvisionEvent> events = <ProvisionEvent>[];

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      )
            .run(onEvent: events.add),
        throwsA(isA<ProvisionCommandError>()),
      );

      expect(started(events), <String>['preflight', 'docker', 'clone']);
      expect(events.last.step, 'clone');
      expect(events.last.phase, StepPhase.failed);
      expect(events.last.message, contains('could not read from remote'));

      // Everything after it assumed it happened. The firewall step in
      // particular: arming a deadman and enabling ufw on a box we are about to
      // abandon is the one thing worse than failing here.
      // By stage, not by script name: the clone program itself names
      // provision-host.sh now, because it asserts the file is in the tree it
      // fetched. The stages are what must not have run.
      expect(ssh.ran('stage=base'), isFalse);
      expect(ssh.ran('stage=code'), isFalse);
      expect(ssh.ran('setsid'), isFalse);
      expect(ssh.ran('ufw allow'), isFalse);
      expect(ssh.ran('smoke.sh'), isFalse);
    });

    test('a ref with no provision-host.sh is refused at the clone, by name',
        () async {
      // What the app used to do instead: clone `main` -- which has no
      // scripts/provision-host.sh, the script being a pure addition -- and then
      // die on the host stage at exit 127, on a box whose apt and git had
      // already been touched, with nothing naming the ref or the file. The
      // clone step asserts the file is in the fetched tree, so the failure
      // arrives before the box has been changed any further.
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail(
        'git clone',
        exitCode: 1,
        stderr: 'this build of the app needs a server tree containing '
            'scripts/provision-host.sh; ref v0.2.0 has none',
      );

      try {
        await Provisioner(
          config: config,
          connector: ssh,
          hostKeys: ssh.hostKeys,
          clock: FakeClock(),
        ).run();
        fail('a tree that cannot serve this build must not be provisioned from');
      } on ProvisionCommandError catch (error) {
        expect(error.step, 'clone');
        expect(error.what, contains('v0.2.0'));
        expect(error.message, contains('scripts/provision-host.sh'));
      }

      // Nothing after it. The host stage is the step that would have failed
      // with exit 127 and no explanation, and the firewall step is the one that
      // must never run on a box about to be abandoned.
      expect(ssh.ran('stage=base'), isFalse);
      expect(ssh.ran('setsid'), isFalse);
    });

    test('a lock somebody else holds stops the run and says nothing ran',
        () async {
      // Every vpnctl call here passes `flock -E 75`, and this is why: without
      // the translation an apply that never started arrives as "exited 75 and
      // printed nothing", which sends somebody looking for a bug in vpnctl
      // instead of waiting out the operator who is mid-apply.
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('vpnctl apply', exitCode: 75);

      try {
        await Provisioner(
          config: config,
          connector: ssh,
          hostKeys: ssh.hostKeys,
          clock: FakeClock(),
        ).run();
        fail('a lock conflict is not a converge that failed');
      } on LockBusyError catch (error) {
        expect(error.step, 'apply');
        expect(error.lockPath, '/run/vpn-stack.lock');
        expect(error.message, contains('never ran'));
        expect(error.message, contains('Nothing on the server was changed'));
      }
      // And nothing after it believed the config was promoted.
      expect(ssh.ran('served()'), isFalse);
      expect(ssh.ran('smoke.sh'), isFalse);
    });

    test('a failed smoke test fails the run, with what failed', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail(
        'smoke.sh',
        stdout: '{"schema":1,"ok":false,"checks":[]}\n',
        stderr: '  x hysteria2 20443/udp is not bound\n',
      );

      try {
        await Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run();
        fail('a red smoke test must fail the run');
      } on ProvisionCommandError catch (error) {
        expect(error.step, 'verify');
        expect(error.message, contains('20443/udp'));
      }
    });

    test('the connection is closed even when a step throws', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('git clone', exitCode: 128);

      await expectLater(
        Provisioner(
        config: config,
        connector: ssh,
        hostKeys: ssh.hostKeys,
        clock: FakeClock(),
      ).run(),
        throwsA(isA<ProvisionCommandError>()),
      );
      expect(ssh.connections.single.closed, isTrue);
    });
  });
}
