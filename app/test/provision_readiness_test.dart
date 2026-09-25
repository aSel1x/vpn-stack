// The readiness wait, which exists because `docker compose up` returns long
// before anything is served: hwdsl2/ipsec-vpn-server takes ~30s to bind, and
// far longer on its first run, where it also builds the NSS database and issues
// the CA. A step that returns early makes the NEXT check fail on a server that
// is merely still starting, and a smoke test that cries wolf is one people
// learn to ignore.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/provision/config.dart';
import 'package:vpn_stack_app/provision/errors.dart';
import 'package:vpn_stack_app/provision/provisioner.dart';
import 'package:vpn_stack_app/provision/ssh.dart';
import 'package:vpn_stack_app/provision/step.dart';
import 'package:vpn_stack_app/provision/steps.dart';

import 'provision_fake_ssh.dart';

const ProvisionConfig config = ProvisionConfig(
  host: '203.0.113.7',
  readinessTimeout: Duration(seconds: 10),
  pollInterval: Duration(seconds: 2),
);

List<ProvisionStep> readinessOnly() => <ProvisionStep>[
      ProvisionStep(
        name: 'connect',
        label: 'Connecting',
        run: (ProvisionContext ctx) => ctx.openPrimary(),
      ),
      const ProvisionStep(
        name: 'readiness',
        label: 'Waiting for the ports to bind',
        run: awaitReadiness,
      ),
    ];

Future<ProvisionResult> runReadiness(
  ScriptedSsh ssh, {
  ProvisionClock? clock,
  ProvisionReporter? onEvent,
}) =>
    Provisioner(
      config: config,
      connector: ssh,
      hostKeys: ssh.hostKeys,
      clock: clock ?? FakeClock(),
      steps: readinessOnly(),
    ).run(onEvent: onEvent);

CommandResult out(String stdout) =>
    CommandResult(exitCode: 0, stdout: stdout, stderr: '');

void main() {
  test('keeps polling while a port is still coming up', () async {
    final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
    ssh.replyEach('served()', <CommandResult>[
      out('bound=10443/tcp\npending=20443/udp\n'),
      out('bound=10443/tcp\npending=20443/udp\n'),
      out('bound=10443/tcp\nbound=20443/udp\n'),
    ]);
    final List<ProvisionEvent> events = <ProvisionEvent>[];

    final ProvisionResult result = await runReadiness(ssh, onEvent: events.add);

    expect(result.steps, <String>['connect', 'readiness']);
    expect(ssh.countOf('served()'), 3);
    expect(result.facts['ports'], '10443/tcp 20443/udp');
    // Something has to move on the screen while this happens, or a four-minute
    // CA build is indistinguishable from a hang.
    expect(
      events.where((ProvisionEvent e) => e.phase == StepPhase.progress),
      isNotEmpty,
    );
  });

  test('gives up naming the ports that never bound', () async {
    final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
    ssh.reply('served()', stdout: 'bound=10443/tcp\npending=20443/udp\n');

    try {
      await runReadiness(ssh);
      fail('ports that never bind must fail, not warn');
    } on ReadinessTimeoutError catch (error) {
      expect(error.step, 'readiness');
      expect(error.pending, <String>['20443/udp']);
      expect(error.message, contains('20443/udp'));
      expect(error.waited.inSeconds, config.readinessTimeout.inSeconds);
    }
  });

  test('a broken probe is named rather than waited out', () async {
    final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
    ssh.fail('served()', exitCode: 127, stderr: 'ss: command not found');

    try {
      await runReadiness(ssh);
      fail('a probe that cannot run is not a server that is slow');
    } on ProvisionCommandError catch (error) {
      expect(error.message, contains('ss: command not found'));
    }
    // Once, not for the whole timeout.
    expect(ssh.countOf('served()'), 1);
  });

  group('an answer this app cannot read is not an empty answer', () {
    // The degradation this group exists for: the step used to decode the
    // payload itself and `continue` past any row it could not read, so a shape
    // it did not recognise produced an empty spec list, "no protocol is
    // enabled, so there is nothing to wait for", and a readiness step that
    // reported success without waiting for anything -- on a server where every
    // port may well have been unbound. Asking through `Vpnctl.listProtocols()`
    // makes the unreadable row a named failure instead.

    test('a row whose enabled is not a boolean fails the step', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      // The quiet one. A loose reader tests `row['enabled'] != true`, which is
      // true of the string "true", so the row is skipped and the protocol that
      // IS enabled is never waited for.
      ssh.reply(
        'protocol list',
        stdout: '{"schema":1,"ok":true,"protocols":['
            '{"name":"vless-reality","enabled":"true","ports":["10443/tcp"],'
            '"kind":"singbox","summary":"","notes":""}]}\n',
      );

      try {
        await runReadiness(ssh);
        fail('an unreadable protocol list must not pass as an empty one');
      } on ProvisionControlError catch (error) {
        expect(error.step, 'readiness');
        expect(error.message, contains('protocols[0].enabled'));
        expect(error.message, contains('expected a boolean'));
      }
      expect(ssh.ran('served()'), isFalse);
    });

    test('rows that are not objects fail the step', () async {
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'protocol list',
        stdout: '{"schema":1,"ok":true,"protocols":["vless-reality"]}\n',
      );

      await expectLater(
        runReadiness(ssh),
        throwsA(isA<ProvisionControlError>().having(
            (ProvisionControlError e) => e.message,
            'message',
            contains('protocols[0]'))),
      );
    });

    test('a field this app does not know is refused by name', () async {
      // Same stance as users_store.load(): the field may be the one that says a
      // port moved, and waiting for the ports we did recognise would be reading
      // a changed answer as an unchanged one.
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.reply(
        'protocol list',
        stdout: '{"schema":1,"ok":true,"protocols":['
            '{"name":"wireguard","enabled":true,"ports":["51820/udp"],'
            '"kind":"compose","summary":"","notes":"","obfuscated":true}]}\n',
      );

      await expectLater(
        runReadiness(ssh),
        throwsA(isA<ProvisionControlError>().having(
            (ProvisionControlError e) => e.message,
            'message',
            allOf(contains('obfuscated'), contains('update the app')))),
      );
    });

    test('a lock somebody else holds says nothing ran', () async {
      // flock -E 75. Without the translation this is "exited 75 and printed
      // nothing", which sends somebody looking for a bug in vpnctl instead of
      // waiting a minute.
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      ssh.fail('protocol list', exitCode: 75);

      try {
        await runReadiness(ssh);
        fail('a lock conflict is not a server that never binds');
      } on LockBusyError catch (error) {
        expect(error.step, 'readiness');
        expect(error.lockPath, '/run/vpn-stack.lock');
        expect(error.message, contains('never ran'));
      }
      expect(ssh.ran('served()'), isFalse);
    });

    test('asks under the lock, like every other vpnctl call', () async {
      // app/README.md: a call that skips the lock is a bug even on the run
      // where it works. This one ran outside it while control/vpnctl.dart put
      // every one of its own inside.
      final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
      await runReadiness(ssh);

      final String asked = ssh.commands
          .firstWhere((String c) => c.contains('protocol list'));
      expect(asked, contains('flock'));
      expect(asked, contains('/run/vpn-stack.lock'));
      expect(asked, contains('-E 75'));
    });
  });

  test('waits for nothing when no protocol is enabled', () async {
    final ScriptedSsh ssh = ScriptedSsh.bareUbuntu();
    ssh.reply(
      'protocol list',
      stdout: '{"schema":1,"ok":true,"protocols":['
          '{"name":"ikev2","enabled":false,"ports":["500/udp"],'
          '"kind":"compose","summary":"","notes":""}]}\n',
    );

    final ProvisionResult result = await runReadiness(ssh);

    expect(result.steps, <String>['connect', 'readiness']);
    expect(ssh.ran('served()'), isFalse);
  });
}
