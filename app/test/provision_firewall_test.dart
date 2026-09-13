// The most important test in the app.
//
// The firewall step arms a detached deadman, enables ufw, and then has to
// decide one thing: did a BRAND-NEW connection get through the rules it just
// installed? Answer yes wrongly and the deadman is disarmed on a server nobody
// can reach again -- a lockout with no recovery, on a box whose only door is
// the one that just closed. Answer no and the server undoes the firewall by
// itself in three minutes with nobody doing anything.
//
// So these tests assert on one command more than on any message: `kill -TERM`,
// the disarm. It must run when the proof succeeded, and it must NOT run in
// every other case.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/commands.dart';
import 'package:vpn_stack_app/provision/config.dart';
import 'package:vpn_stack_app/provision/errors.dart';
import 'package:vpn_stack_app/provision/firewall.dart';
import 'package:vpn_stack_app/provision/provisioner.dart';
import 'package:vpn_stack_app/provision/step.dart';

import 'provision_fake_ssh.dart';

const ProvisionConfig config = ProvisionConfig(host: '203.0.113.7');

/// The step under test, with just enough in front of it to have a connection.
List<ProvisionStep> firewallOnly() => <ProvisionStep>[
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

Future<ProvisionResult> runFirewall(ScriptedSsh ssh, {ProvisionReporter? onEvent}) =>
    Provisioner(
      config: config,
      connector: ssh,
      hostKeys: ssh.hostKeys,
      clock: FakeClock(),
      steps: firewallOnly(),
    ).run(onEvent: onEvent);

void main() {
  group('the fresh connection succeeds', () {
    test('disarms the deadman', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      final ProvisionResult result = await runFirewall(ssh);

      expect(result.steps, <String>['connect', 'firewall']);
      expect(ssh.indexOf('setsid'), lessThan(ssh.indexOf('ufw allow')));
      expect(ssh.ran('kill -TERM'), isTrue);
      expect(result.facts['deadman_pid'], '4242');
    });

    test('proves it on a connection that is genuinely a different one',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      await runFirewall(ssh);

      expect(ssh.connects, 2);
      final ScriptedConnection primary = ssh.connections.first;
      final ScriptedConnection prover = ssh.connections.last;
      expect(prover.transportId, isNot(primary.transportId));
      // Connecting proves the handshake passed the new rules; running something
      // proves the session is usable, not merely accepted.
      expect(ssh.commands.contains('true'), isTrue);
      expect(prover.closed, isTrue);
    });

    test('refuses a connector that handed back the connection we already have',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // A pooled or multiplexed "fresh" connection. An established conntrack
      // entry survives a firewall that rejects every new connection, so this
      // proves nothing -- and accepting it would disarm the net on a server
      // that is already unreachable.
      ssh.poolConnections = true;

      try {
        await runFirewall(ssh);
        fail('a multiplexed connection must not count as proof');
      } on FirewallLockoutError catch (error) {
        expect(error.message, contains('proves nothing'));
        expect(ssh.ran('kill -TERM'), isFalse);
      }
    });
  });

  group('the fresh connection fails', () {
    test('leaves the deadman ARMED and says so', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // The primary connection survives -- it is established, and conntrack
      // keeps it. Every new one is dropped. This is exactly what locking
      // yourself out looks like from here, and why the prover cannot be the
      // session that installed the rules.
      ssh.refuseConnectsAfter = 1;
      final List<ProvisionEvent> events = <ProvisionEvent>[];

      try {
        await runFirewall(ssh, onEvent: events.add);
        fail('a firewall we cannot get through must fail the run');
      } on FirewallLockoutError catch (error) {
        // The whole safety net, in one assertion: we did NOT disarm.
        expect(ssh.ran('kill -TERM'), isFalse);

        expect(error.step, 'firewall');
        expect(error.deadmanSeconds, config.deadmanSeconds);
        expect(error.deadmanPid, '4242');
        expect(error.message, contains('LEFT ARMED'));
        expect(error.message, contains('${config.deadmanSeconds}s'));
        // It has to say the recovery happens by itself. Somebody locked out of
        // their own server cannot run a command to fix it.
        expect(error.message, contains('disables ufw by itself'));
        expect(error.attempts, hasLength(config.proveAttempts));

        expect(events.last.phase, StepPhase.failed);
        expect(events.last.step, 'firewall');
        expect(events.last.message, contains('LEFT ARMED'));
      }

      // ufw really was enabled first: this is the dangerous state, and the test
      // is worthless if the step bailed out before reaching it.
      expect(ssh.ran('setsid'), isTrue);
      expect(ssh.ran('ufw allow'), isTrue);
      // One primary plus one attempt each.
      expect(ssh.connects, 1 + config.proveAttempts);
    });

    test('retries before giving up, because the cost is asymmetric', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.refuseConnectsAfter = 1;
      final FakeClock clock = FakeClock();

      await expectLater(
        Provisioner(
          config: config,
          connector: ssh,
          hostKeys: ssh.hostKeys,
          clock: clock,
          steps: firewallOnly(),
        ).run(),
        throwsA(isA<FirewallLockoutError>()),
      );

      // A gap between attempts, but no gap before the first one.
      expect(clock.slept, hasLength(config.proveAttempts - 1));
      expect(clock.slept.first, config.proveGap);
    });

    test('a connection that opens but cannot run anything is not proof',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('true', exitCode: 255, exact: true, stderr: 'shell failed');

      await expectLater(
        runFirewall(ssh),
        throwsA(isA<FirewallLockoutError>()),
      );
      expect(ssh.ran('kill -TERM'), isFalse);
    });

    test('a fresh connection to a DIFFERENT machine is not proof', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // Same address, another host key. Whatever answered, it is not the box
      // whose firewall we just changed, so it says nothing about whether that
      // box is still reachable -- and disarming on the strength of it would
      // switch the net off for the one server that still needs it.
      ssh.keyAfterFirst = otherHostKey;

      try {
        await runFirewall(ssh);
        fail('another machine answering is not proof about this one');
      } on FirewallLockoutError catch (error) {
        expect(error.message, contains('different host key'));
      }
      expect(ssh.ran('kill -TERM'), isFalse);
    });
  });

  group('the disarm goes over the connection that was just proved', () {
    test('and never over the session that installed the rules', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();

      await runFirewall(ssh);

      final ScriptedConnection primary = ssh.connections.first;
      final ScriptedConnection prover = ssh.connections.last;
      expect(prover.transportId, isNot(primary.transportId));
      expect(prover.commands.any((String c) => c.contains('kill -TERM')), isTrue);
      // install.sh sends its disarm through `on` -- a new ssh invocation -- for
      // the same reason the verification is a new connection. The primary is
      // the one connection whose survival this step has NOT established.
      expect(
        primary.commands.any((String c) => c.contains('kill -TERM')),
        isFalse,
      );
      expect(prover.closed, isTrue);
    });

    test('so a primary severed by `ufw enable` does not abort the run',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // The exact state this step has just PROVED it is in: new connections are
      // fine, the established one is gone. Disarming over the primary throws
      // here, the run aborts with the deadman still armed, and the firewall
      // then disables itself three minutes later on a healthy server.
      ssh.severAfter = 'ufw allow';

      final ProvisionResult result = await runFirewall(ssh);

      expect(result.steps, <String>['connect', 'firewall']);
      expect(ssh.ran('kill -TERM'), isTrue);
      expect(ssh.connections.first.severed, isTrue);
    });
  });

  group('before the proof', () {
    test('will not touch ufw if the deadman did not arm', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail(
        'setsid',
        stderr: 'deadman failed to arm; refusing to touch ufw',
      );

      try {
        await runFirewall(ssh);
        fail('no deadman, no firewall');
      } on ProvisionCommandError catch (error) {
        expect(error.step, 'firewall');
        expect(error.message, contains('refusing to touch ufw'));
      }

      // The order that matters: nothing enabled a firewall we had no way back
      // through. And no disarm either -- there is nothing to disarm.
      expect(ssh.ran('ufw allow'), isFalse);
      expect(ssh.ran('kill -TERM'), isFalse);
      expect(ssh.connects, 1);
    });

    test('a failed ufw enable is reported as a lockout, net left armed',
        () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('ufw allow', stderr: 'ERROR: problem running ufw-init');

      try {
        await runFirewall(ssh);
        fail('a half-enabled firewall is a lockout risk, not a warning');
      } on FirewallLockoutError catch (error) {
        expect(error.message, contains('ufw could not be enabled'));
        expect(error.message, contains('LEFT ARMED'));
      }
      expect(ssh.ran('kill -TERM'), isFalse);
      // No point proving anything: we do not know what the rules are now.
      expect(ssh.connects, 1);
    });
  });

  group('after the proof', () {
    test('a deadman that will not disarm fails the run', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('kill -TERM', exitCode: 1, stderr: 'no such process group');

      try {
        await runFirewall(ssh);
        fail('a deadman still running on a healthy server has to be said out loud');
      } on ProvisionCommandError catch (error) {
        // ufw disabling itself minutes later, on a server that is fine and
        // that nobody is watching, is worse than an install that stops here.
        expect(error.step, 'firewall');
        expect(error.message, contains('disarming the deadman'));
        expect(error.message, contains('${config.deadmanSeconds}s'));
      }
    });
  });

  group('the programs themselves', () {
    // Two properties install.sh paid for, and neither is visible from the Dart:
    // get either wrong and the tests above still pass while the server either
    // never disarms or disarms a timer that keeps running.
    test('the deadman records its OWN pid, not \$!', () {
      final String program = armDeadmanCommand(config).text;
      expect(program, contains('setsid'));
      // `\$!` is unreliable: setsid forks when the caller is already a
      // process-group leader, so the pid it reports is not the one that sleeps.
      expect(program, contains(r'echo $$ > "$1"'));
      expect(program, isNot(contains(r'$!')));
      expect(program, contains('ufw --force disable'));
      expect(program, contains(r'sleep "$2"'));
      // The pid file and the TTL go into that subshell as positional
      // parameters. Splicing them into its body would splice a quoted word
      // inside a single-quoted string, which ends the string rather than
      // nesting inside it.
      expect(program, contains(r'deadman "$pidfile" "$ttl"'));
      expect(program, contains('\npidfile=/run/vpn-stack.deadman\n'));
      expect(program, contains('\nttl=${config.deadmanSeconds}\n'));
    });

    test('the disarm kills the process GROUP, so the sleep goes with it', () {
      final String program = disarmDeadmanCommand(config).text;
      // Negative pid first -- setsid made the child a group leader. The plain
      // pid is the fallback, not the intent: killing only the shell leaves the
      // sleep to fire `ufw --force disable` on a healthy server.
      expect(program, contains(r'kill -TERM -"$pid"'));
      expect(program.indexOf(r'kill -TERM -"$pid"'),
          lessThan(program.indexOf(r'|| kill -TERM "$pid"')));
    });

    test('opens the port we actually reach sshd on', () {
      const ProvisionConfig moved = ProvisionConfig(host: 'h', sshPort: 2222);
      final String program = enableUfwCommand(moved).text;
      expect(program, contains('\nport=2222\n'));
      // Allowing 22 on a box whose sshd listens elsewhere is precisely the
      // lockout the deadman exists to survive.
      expect(program, isNot(contains('\nport=22\n')));
      expect(program, contains(r'ufw allow "$port"/tcp'));
      expect(program, contains("comment 'vpn-stack:ssh'"));
    });
  });
}
