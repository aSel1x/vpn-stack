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

import 'dart:convert';

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
Future<List<String>> enabledPortSpecs(ProvisionContext ctx) async {
  final CommandResult result = await ctx.runChecked(
    protocolListCommand(ctx.config),
    what: 'asking which protocols are enabled',
  );
  final Object? decoded = jsonDecode(result.stdout) as Object?;
  if (decoded is! Map<String, Object?>) {
    throw ProvisionCommandError(
      step: ctx.stepName,
      what: '`protocol list --json` did not answer with a JSON object',
      exitCode: result.exitCode,
      output: result.combined,
    );
  }
  final Object? rows = decoded['protocols'];
  if (rows is! List<Object?>) {
    throw ProvisionCommandError(
      step: ctx.stepName,
      what: '`protocol list --json` has no `protocols` list',
      exitCode: result.exitCode,
      output: result.combined,
    );
  }
  final List<String> specs = <String>[];
  for (final Object? row in rows) {
    if (row is! Map<String, Object?>) continue;
    if (row['enabled'] != true) continue;
    final Object? ports = row['ports'];
    if (ports is! List<Object?>) continue;
    for (final Object? port in ports) {
      if (port is String && !specs.contains(port)) specs.add(port);
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
