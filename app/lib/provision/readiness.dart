// Waiting until the server is actually serving, rather than until docker
// returned.
//
// `docker compose up` returns immediately, and hwdsl2/ipsec-vpn-server needs
// ~30s to bind -- much longer on its FIRST run, where it also builds the NSS
// database and issues the CA on whatever small VPS this is. A step that returns
// before the ports are bound makes the next check fail on a server that is
// merely still starting, and a smoke test that cries wolf is a smoke test
// people learn to ignore.
//
// `vpnctl apply` already waits, but it *warns* and returns ok when ports never
// come up, and its ceiling is short. So the app waits again, longer, and fails
// instead of warning.

import '../control/models.dart';
import '../control/vpnctl.dart';
import 'commands.dart';
import 'errors.dart';
import 'step.dart';
import 'ssh.dart';

/// The ports the enabled protocols claim, as `10443/tcp` specs.
///
/// Asked of the server rather than hardcoded here: which protocols are on is
/// the server's state, and the port list belongs to the protocol registry in
/// `vpnctl/protocols/`. A copy in Dart is the second definition this repository
/// keeps refusing to have.
///
/// Asked through the control layer rather than parsed here, for the same
/// reason one level down. This function used to decode the payload itself and
/// skip any row it could not read -- so a shape it did not recognise produced
/// an empty spec list, "no protocol is enabled, so there is nothing to wait
/// for", and a readiness step that passed without waiting for anything. That is
/// the exact failure mode `control/json.dart` was written to refuse: a
/// half-read answer looks like it worked. `Vpnctl.listProtocols()` names the
/// field it cannot read and this step fails on it.
Future<List<String>> enabledPortSpecs(ProvisionContext ctx) async {
  final List<ProtocolEntry> protocols = await ctx.control(
    (Vpnctl vpnctl) => vpnctl.listProtocols(),
    what: 'asking which protocols are enabled',
  );
  final List<String> specs = <String>[];
  for (final ProtocolEntry protocol in protocols) {
    if (!protocol.enabled) continue;
    for (final String spec in protocol.ports) {
      // `protocols.assert_ports_disjoint` on the server means this cannot
      // fire today. It stays because the wait below compares counts: a spec
      // listed twice would be bound once and the wait could never finish,
      // which is a timeout on a healthy server rather than a duplicate line.
      if (!specs.contains(spec)) specs.add(spec);
    }
  }
  return specs;
}

/// Polls until every spec is bound on a non-loopback address, or gives up.
///
/// "Bound" excludes loopback in the shell half, exactly as smoke.sh and
/// composectl define it: substring-matching a port number reports dnstt's
/// 53/udp as served on any stock Ubuntu, because systemd-resolved holds
/// 127.0.0.53:53.
Future<void> waitForPorts(ProvisionContext ctx, List<String> specs) async {
  if (specs.isEmpty) {
    ctx.progress('no protocol is enabled, so there is nothing to wait for');
    return;
  }
  final DateTime start = ctx.clock.now();
  final DateTime deadline = start.add(ctx.config.readinessTimeout);
  final RemoteProgram program = portsBoundCommand(specs);
  while (true) {
    final CommandResult result = await ctx.run(program);
    final List<String> bound = valuesOf(result.stdout, 'bound');
    final List<String> pending = valuesOf(result.stdout, 'pending');
    if (!result.ok && bound.isEmpty && pending.isEmpty) {
      // The probe itself broke -- no `ss`, no `awk`. Said now, by name: left to
      // the loop this is indistinguishable from a server that never binds, and
      // costs the whole timeout before saying nothing useful.
      throw ProvisionCommandError(
        step: ctx.stepName,
        what: 'checking which ports are bound',
        exitCode: result.exitCode,
        output: result.combined,
      );
    }
    if (pending.isEmpty && bound.length == specs.length) {
      ctx.facts['ports'] = bound.join(' ');
      ctx.progress('serving ${bound.join(', ')}');
      return;
    }
    final Duration waited = ctx.clock.now().difference(start);
    if (!ctx.clock.now().isBefore(deadline)) {
      throw ReadinessTimeoutError(
        step: ctx.stepName,
        pending: pending.isEmpty ? specs : pending,
        waited: waited,
      );
    }
    // Said every poll, with the elapsed time, because the honest answer to "is
    // it stuck?" during a first ipsec run is "no, it is building a CA", and a
    // screen that has not changed in four minutes cannot say that.
    ctx.progress(
      'waiting for ${pending.isEmpty ? specs.join(', ') : pending.join(', ')} '
      '(${waited.inSeconds}s; the first ipsec run builds its CA before it binds)',
    );
    await ctx.clock.sleep(ctx.config.pollInterval);
  }
}
