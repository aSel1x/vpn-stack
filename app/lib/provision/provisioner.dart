// The runner: opens nothing, decides nothing, and stops on the first failure.
//
// Stopping is the point. Every step after a failed one assumes the failed one
// happened -- `apply` on a box with no keyring, a smoke test against containers
// that were never started -- and the errors it would then produce describe the
// consequence instead of the cause. install.sh gets this from `set -e`; here it
// is an exception that is reported and rethrown, never swallowed.

import 'config.dart';
import 'errors.dart';
import 'ssh.dart';
import 'step.dart';
import 'steps.dart';

/// What a finished run leaves behind.
class ProvisionResult {
  const ProvisionResult({required this.steps, required this.facts});

  /// Machine names of the steps that completed, in order.
  final List<String> steps;

  /// What was learned on the way: the distribution, the cloned commit, the
  /// deadman's pid, the ports that came up.
  final Map<String, String> facts;
}

/// Bare Debian or Ubuntu box -> serving VPN.
class Provisioner {
  Provisioner({
    required this.config,
    required this.connector,
    required this.hostKeys,
    this.clock = const ProvisionClock(),
    List<ProvisionStep>? steps,
  }) : steps = steps ?? provisionSteps();

  final ProvisionConfig config;
  final SshConnector connector;

  /// Which host key this run will accept, and who to ask about one it has never
  /// seen. Required rather than defaulted: a default would be a decision about
  /// somebody's root password made by whoever forgot to pass one.
  final HostKeyPolicy hostKeys;

  final ProvisionClock clock;

  /// Injectable so a test can run one step in isolation, and so a future
  /// "repair" path can run a subset. The order is the contract; nothing here
  /// reorders it.
  final List<ProvisionStep> steps;

  Future<ProvisionResult> run({ProvisionReporter? onEvent}) async {
    final ProvisionContext ctx = ProvisionContext(
      config: config,
      connector: connector,
      hostKeys: hostKeys,
      clock: clock,
      onEvent: onEvent,
    );
    final List<String> done = <String>[];
    try {
      for (int i = 0; i < steps.length; i++) {
        final ProvisionStep step = steps[i];
        ctx.beginStep(step, i + 1, steps.length);
        ctx.emit(StepPhase.started, step.label);
        try {
          await step.run(ctx);
        } catch (error) {
          ctx.emit(
            StepPhase.failed,
            error is ProvisionException ? error.message : '$error',
          );
          // Deliberately not wrapped: a ProvisionException already says what
          // happened in words a person can act on, and the firewall one has to
          // arrive intact -- its message is the only place that says the server
          // will undo the firewall by itself.
          rethrow;
        }
        ctx.emit(StepPhase.succeeded, step.label);
        done.add(step.name);
      }
    } finally {
      // Closed on the way out of a failure too. Not in the failure path proper:
      // whether the connection closes has nothing to do with whether the
      // deadman stays armed, and confusing the two is how a lockout gets
      // "cleaned up".
      await ctx.closePrimary();
    }
    return ProvisionResult(steps: done, facts: Map<String, String>.of(ctx.facts));
  }
}
