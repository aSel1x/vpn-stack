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

import 'dart:io';

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

/// Runs one of this layer's programs under a real `/bin/sh`, which is the only
/// thing that can answer what it actually does.
///
/// ScriptedSsh answers by matching program text, so every exit code it hands
/// back is one a test chose. That is right for "what did the step do with this
/// outcome" and useless for "can the program produce this outcome at all" --
/// and the two were conflated here once, against a disarm that ended in `true`
/// and could not fail.
Future<ProcessResult> runProgram(
  RemoteProgram program, {
  Map<String, String>? environment,
}) =>
    // `/bin/sh` by path, not by PATH: these runs hand the program a PATH of
    // their own so it can find a stubbed ufw, and resolving the shell through
    // that would be resolving it through the fixture.
    Process.run('/bin/sh', <String>['-c', program.text],
        environment: environment);

/// A config whose deadman pid file is somewhere a test may write.
ProvisionConfig withPidFile(String path, {int seconds = 180}) =>
    ProvisionConfig(
      host: '203.0.113.7',
      deadmanPidFile: path,
      deadmanSeconds: seconds,
    );

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
      // The exit code and the sentence below are the disarm program's own, run
      // under a real shell against a pid file that is not there -- the state
      // the bash half also calls fatal, because it means either that the timer
      // already fired (ufw is off right now) or that nothing ever armed it.
      //
      // That is the repair. The old program ended in `true` and could not exit
      // non-zero whatever happened, so scripting a 1 against `kill -TERM` here
      // exercised ScriptedSsh and nothing else: coverage for a path the
      // program had no way to take.
      final Directory dir =
          await Directory.systemTemp.createTemp('deadman-never-armed');
      addTearDown(() => dir.delete(recursive: true));
      final ProcessResult real = await runProgram(
          disarmDeadmanCommand(withPidFile('${dir.path}/deadman')));
      expect(real.exitCode, isNot(0),
          reason: 'a disarm that cannot fail is not half of a safety net');

      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('kill -TERM',
          exitCode: real.exitCode, stderr: real.stderr as String);

      try {
        await runFirewall(ssh);
        fail('a deadman still running on a healthy server has to be said out loud');
      } on ProvisionCommandError catch (error) {
        // ufw disabling itself minutes later, on a server that is fine and
        // that nobody is watching, is worse than an install that stops here.
        expect(error.step, 'firewall');
        expect(error.message, contains('disarming the deadman'));
        expect(error.message, contains('${config.deadmanSeconds}s'));
        // The server's own words reach the person, not a summary of them: this
        // is the sentence that says ufw may already be off.
        expect(error.message, contains('ufw status'));
      }
    });
  });

  // The disarm is the one program in this step that is allowed to fail, and
  // the step above can only be tested against outcomes the program can really
  // produce. These run it.
  group('the disarm, under a real shell', () {
    late Directory dir;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('deadman');
    });

    tearDown(() async => dir.delete(recursive: true));

    test('a missing pid file is fatal, and says which of the two it is',
        () async {
      final ProcessResult ran =
          await runProgram(disarmDeadmanCommand(withPidFile('${dir.path}/gone')));
      expect(ran.exitCode, isNot(0));
      // Both readings have to be in the sentence, because the operator's next
      // move differs: a timer that already fired means the firewall is down
      // NOW, and one that never armed means it went up with no net under it.
      expect(ran.stderr, contains('${dir.path}/gone'));
      expect(ran.stderr, contains('ufw status'));
      expect(ran.stderr, contains('nothing ever armed it'));
    });

    test('a pid file with no pid in it is fatal, and is left on disk', () async {
      final File pidFile = File('${dir.path}/deadman');
      await pidFile.writeAsString('not-a-pid\n');

      final ProcessResult ran =
          await runProgram(disarmDeadmanCommand(withPidFile(pidFile.path)));

      expect(ran.exitCode, isNot(0));
      // Not deleted. A file this cannot parse is still the only record that
      // something may be counting down towards `ufw --force disable`, and
      // removing it is the one irreversible move available here.
      expect(pidFile.existsSync(), isTrue);
    });

    test('kills the process group, escalating past a TERM it ignored',
        () async {
      final String pidFile = '${dir.path}/deadman';
      // A stand-in deadman: its own process group (setsid, exactly as the arm
      // does it), ignoring TERM, sleeping where the real one sleeps before
      // running `ufw --force disable`. A program that sends one TERM and
      // reports success leaves this alive -- which on a server is a firewall
      // that switches itself off minutes after the install said it was done.
      final Process timer = await Process.start('setsid', <String>[
        'sh',
        '-c',
        r'trap "" TERM; echo $$ > "$1"; sleep 40',
        'deadman',
        pidFile,
      ]);
      addTearDown(() async {
        timer.kill(ProcessSignal.sigkill);
        final String pid = await _pidIn(pidFile);
        if (pid.isNotEmpty) {
          await Process.run('sh', <String>['-c', 'kill -KILL -$pid 2>/dev/null']);
        }
      });
      final String pid = await _pidIn(pidFile, waitFor: true);
      expect(pid, isNotEmpty, reason: 'the stand-in never wrote its pid');

      final ProcessResult ran =
          await runProgram(disarmDeadmanCommand(withPidFile(pidFile)));

      expect(ran.exitCode, 0, reason: '${ran.stderr}');
      expect(ran.stdout, contains('disarmed=$pid'));
      // Provably gone, not assumed gone: the KILL is the whole reason the
      // program polls instead of returning after the TERM.
      expect(await _alive(pid), isFalse);
      // And only now is the record of it removed.
      expect(File(pidFile).existsSync(), isFalse);
    },
        // `setsid` is util-linux; macOS has no such binary, and a stand-in
        // that is not a group leader would test the fallback branch instead of
        // the one that matters.
        skip: Platform.isLinux ? null : 'needs setsid to make a process group');
  });

  // The arm's other half: it must never write its pid over a live timer's.
  // Run A arms pid 100, its proof fails, somebody reconnects and taps retry,
  // run B writes 200 over the same file -- and whichever the disarm kills, the
  // other wakes at its own T+180 and runs `ufw --force disable`, possibly
  // minutes after this reported success. An unattended firewall-off is meant to
  // be the ONE thing this net causes.
  group('the arm, under a real shell', () {
    late Directory dir;
    late String pidFile;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('deadman-arm');
      pidFile = '${dir.path}/deadman';
      // The arm refuses to touch ufw on a box that has none, so a stub stands
      // in. Nothing in these tests lets a timer live long enough to reach it.
      final File stub = File('${dir.path}/ufw');
      await stub.writeAsString('#!/bin/sh\nexit 0\n');
      await Process.run('chmod', <String>['+x', stub.path]);
    });

    tearDown(() async => dir.delete(recursive: true));

    Map<String, String> stubbedUfw() => <String, String>{
          'PATH': '${dir.path}:${Platform.environment['PATH'] ?? '/usr/bin:/bin'}',
        };

    test('refuses to arm a second deadman over a live one', () async {
      final Process timer = await Process.start('setsid', <String>[
        'sh',
        '-c',
        r'echo $$ > "$1"; sleep 40',
        'deadman',
        pidFile,
      ]);
      addTearDown(() async {
        timer.kill(ProcessSignal.sigkill);
        await Process.run('/bin/sh',
            <String>['-c', 'kill -KILL -${await _pidIn(pidFile)} 2>/dev/null']);
      });
      final String live = await _pidIn(pidFile, waitFor: true);
      expect(live, isNotEmpty);

      final ProcessResult ran = await runProgram(
          armDeadmanCommand(withPidFile(pidFile)),
          environment: stubbedUfw());

      expect(ran.exitCode, isNot(0));
      expect(ran.stderr, contains('still armed'));
      expect(ran.stdout, isNot(contains('armed=')));
      // The live timer's pid is still the only one in the file. Refused rather
      // than reaped on this side on purpose: a pid the previous run did not
      // clean up may have been recycled, and signalling a process group we did
      // not create, on a box whose firewall is about to change, is a worse
      // accident than stopping. Waiting is the fix -- the timer expires by
      // itself -- and the message says so.
      expect((await File(pidFile).readAsString()).trim(), live);
    });

    test('clears a pid file whose timer is already gone, and arms', () async {
      final String dead = await _deadPid();
      await File(pidFile).writeAsString('$dead\n');

      final ProcessResult ran = await runProgram(
          armDeadmanCommand(withPidFile(pidFile, seconds: 300)),
          environment: stubbedUfw());

      expect(ran.exitCode, 0, reason: '${ran.stderr}');
      final String? armed = valueOf(ran.stdout as String, 'armed');
      expect(armed, isNotNull);
      addTearDown(() => Process.run(
          '/bin/sh', <String>['-c', 'kill -KILL -$armed 2>/dev/null']));
      // A pid file whose timer is gone is not a predecessor, and refusing on
      // one would make every re-run after a crash impossible to arm. What came
      // back is a pid that is really running, not the number that was in the
      // file. (The `rm -f` in front of the arm closes a narrower race in the
      // same place -- the wait loop only tests that the file is non-empty, so
      // stale content can satisfy it before the new timer writes its own pid --
      // and that ordering is too tight to pin from here.)
      expect(armed, isNot(dead));
      expect(await _alive(armed!), isTrue);
    });
  },
      // `setsid` is util-linux, and a stand-in that is not a process-group
      // leader would exercise the fallback branch instead of the real one.
      skip: Platform.isLinux ? null : 'needs setsid to make a process group');

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
      // sleep to fire `ufw --force disable` on a healthy server. The group is
      // killed for real in 'the disarm, under a real shell'; what this pins is
      // the ORDER, which an execution cannot show when both forms work.
      expect(program, contains(r'kill -TERM -"$pid"'));
      expect(program.indexOf(r'kill -TERM -"$pid"'),
          lessThan(program.indexOf(r'|| kill -TERM "$pid"')));
      // It must not be able to report success it did not achieve. A trailing
      // `true` was what made the old one unfailable.
      expect(program.trimRight(), isNot(endsWith('true')));
      expect(program, contains('exit 1'));
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

/// The pid the stand-in deadman wrote, or '' -- optionally waiting for it, the
/// same way the arm program waits before reporting `armed=`.
Future<String> _pidIn(String path, {bool waitFor = false}) async {
  final File file = File(path);
  for (int i = 0; i < (waitFor ? 50 : 1); i++) {
    if (file.existsSync()) {
      final String text = (await file.readAsString()).trim();
      if (text.isNotEmpty) return text;
    }
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return '';
}

/// Whether that process group is still there, asked the way the program asks.
Future<bool> _alive(String pid) async {
  final ProcessResult ran = await Process.run('sh', <String>[
    '-c',
    'kill -0 -$pid 2>/dev/null || kill -0 $pid 2>/dev/null',
  ]);
  return ran.exitCode == 0;
}


/// A pid that is definitely not in use: one we started and watched exit.
///
/// Not a large number picked by hand -- `pid_max` is in the millions on a
/// modern kernel, so a made-up pid can be somebody's live process, and this
/// fixture would then be testing the opposite branch.
Future<String> _deadPid() async {
  final Process gone = await Process.start('/bin/sh', <String>['-c', 'exit 0']);
  await gone.exitCode;
  for (int i = 0; i < 50; i++) {
    if (!await _alive('${gone.pid}')) return '${gone.pid}';
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return '${gone.pid}';
}
