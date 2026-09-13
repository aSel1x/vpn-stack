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
