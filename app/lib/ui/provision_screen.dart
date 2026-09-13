import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../provision/step.dart';
import 'common.dart';
import 'host_key_prompt.dart';
import 'models.dart';
import 'ports.dart';
import 'server_detail_screen.dart';

/// Provisioning, as a list of steps that was known before it started.
///
/// The whole plan is on screen from the first frame, greyed out, rather than
/// appearing a line at a time. Two reasons, both from the layer below: some of
/// these take minutes -- apt fetching docker, the first ipsec run building an
/// NSS database -- and a screen with nothing moving on it is indistinguishable
/// from a hang; and a run that stops early is then visibly a run that stopped
/// early, with the steps it never reached still sitting there.
class ProvisionScreen extends StatelessWidget {
  const ProvisionScreen({
    super.key,
    required this.server,
    required this.credential,
  });

  final ServerProfile server;
  final SshCredential credential;

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<ProvisionRun>(
      create: (BuildContext context) {
        final ProvisionRun run = ProvisionRun(
          // Same route the detail screen takes. The provisioning run opens two
          // connections -- the primary one and the firewall step's prover --
          // and both answer to the single policy this builds.
          access: serverAccessFor(
            context,
            server: server,
            credential: credential,
          ),
        );
        unawaited(run.start());
        return run;
      },
      child: _ProvisionBody(server: server),
    );
  }
}

class _ProvisionBody extends StatelessWidget {
  const _ProvisionBody({required this.server});

  final ServerProfile server;

  @override
  Widget build(BuildContext context) {
    final ProvisionRun run = context.watch<ProvisionRun>();
    // No type argument: PopScope grew one in a later Flutter than it shipped
    // in, and this repository cannot run the analyzer to find out which is on
    // the runner. Inference handles both.
    return PopScope(
      // Leaving mid-run abandons a server halfway through, and one of these
      // steps has a deadman running behind it.
      canPop: !run.running,
      child: Scaffold(
        appBar: AppBar(
          title: Text('Provisioning ${server.label}'),
          automaticallyImplyLeading: !run.running,
        ),
        body: ListView(
          padding: const EdgeInsets.only(bottom: 32),
          children: <Widget>[
            SectionCard(
              title: server.target,
              subtitle: _headline(run),
              children: <Widget>[
                for (int i = 0; i < run.steps.length; i++)
                  _StepRow(
                    index: i + 1,
                    total: run.steps.length,
                    step: run.steps[i],
                    phase: run.phaseOf(run.steps[i].name),
                    message: run.messageOf(run.steps[i].name),
                  ),
              ],
            ),
            if (run.failure != null)
              Padding(
                padding: const EdgeInsets.all(12),
                // Verbatim. This is the only text that says what went wrong,
                // and for the firewall step it is also the only place that says
                // the server will undo the firewall by itself.
                child: FailureText(run.failure!),
              ),
            if (run.succeeded && run.facts.isNotEmpty)
              SectionCard(
                title: 'What it found',
                children: <Widget>[
                  for (final MapEntry<String, String> fact in run.facts.entries)
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2),
                      child: Text('${fact.key}: ${fact.value}'),
                    ),
                ],
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 6, 12, 6),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  if (run.succeeded)
                    FilledButton(
                      onPressed: () => _finish(context),
                      child: const Text('Open server'),
                    ),
                  if (run.finished && !run.succeeded) ...<Widget>[
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).maybePop(),
                      child: const Text('Back'),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Nothing retries on its own. Fix what the message names '
                      'and provision again: every step is written to be safe '
                      'to re-run, and anything already installed is left '
                      'alone.',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _headline(ProvisionRun run) {
    if (run.running) {
      return 'Running. Some steps take minutes.';
    }
    if (run.succeeded) {
      return 'Done. The ports are bound and the server is serving.';
    }
    return 'Stopped. The steps below show where.';
  }

  Future<void> _finish(BuildContext context) async {
    final ServersModel servers = context.read<ServersModel>();
    final CredentialVault vault = context.read<CredentialVault>();
    await servers.markProvisioned(server.id);
    final ServerProfile updated = servers.byId(server.id) ?? server;
    final SshCredential? credential = vault.of(server.id);
    if (!context.mounted) {
      return;
    }
    if (credential == null) {
      Navigator.of(context).popUntil((Route<dynamic> route) => route.isFirst);
      return;
    }
    await Navigator.of(context).pushReplacement<void, void>(
      MaterialPageRoute<void>(
        builder: (_) =>
            ServerDetailScreen(server: updated, credential: credential),
      ),
    );
  }
}

class _StepRow extends StatelessWidget {
  const _StepRow({
    required this.index,
    required this.total,
    required this.step,
    required this.phase,
    this.message,
  });

  final int index;
  final int total;
  final ProvisionStep step;

  /// Null for a step that has not reported yet -- which is what "pending"
  /// means here. The runner has no such phase, and inventing one in the model
  /// would be a third place that knows the sequence.
  final StepPhase? phase;

  final String? message;

  @override
  Widget build(BuildContext context) {
    final ColorScheme colors = Theme.of(context).colorScheme;
    final TextTheme text = Theme.of(context).textTheme;
    final bool pending = phase == null;
    final bool active =
        phase == StepPhase.started || phase == StepPhase.progress;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(width: 28, child: Center(child: _icon(colors))),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  '$index of $total  ${step.label}',
                  style: text.bodyLarge?.copyWith(
                    color: pending ? colors.onSurfaceVariant : colors.onSurface,
                    fontWeight: active ? FontWeight.w600 : FontWeight.normal,
                  ),
                ),
                if (message != null && message!.isNotEmpty) ...<Widget>[
                  const SizedBox(height: 6),
                  FailureText(
                    message!,
                    tone: phase == StepPhase.failed
                        ? FailureTone.error
                        : FailureTone.warning,
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _icon(ColorScheme colors) {
    switch (phase) {
      case null:
        return Icon(Icons.circle_outlined, size: 18, color: colors.outline);
      case StepPhase.started:
      case StepPhase.progress:
        return const InlineSpinner();
      case StepPhase.succeeded:
        return Icon(Icons.check_circle, size: 20, color: colors.primary);
      case StepPhase.failed:
        return Icon(Icons.error, size: 20, color: colors.error);
    }
  }
}
