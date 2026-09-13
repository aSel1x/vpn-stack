// The host key question, as a screen somebody has to answer.
//
// Two questions that look alike and are not:
//
//   - No pin. This device has never reached this server, so the key is shown
//     and nothing connects until somebody accepts it. `scripts/install.sh` does
//     the same trade with `StrictHostKeyChecking=accept-new` and accepts
//     silently; a phone can afford to ask, and this is the one moment where an
//     impostor is indistinguishable from the real server.
//   - A pin that no longer matches. That is not a prompt. The box was rebuilt
//     or somebody is answering in its place, and the next thing this app would
//     send is a root password, so the dialog has no accept button at all --
//     re-pinning is a separate, deliberate action from the server list.
//
// The sentences come from `HostKeyQuestion.summary` rather than being written
// again here: a headless caller that only logs the exception has to say the
// same thing this dialog says.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../provision/ssh.dart';
import 'access.dart';
import 'common.dart';
import 'models.dart';
import 'ports.dart';

/// Builds the one object that can open a connection to [server].
///
/// Every screen that reaches a server goes through here, so there is a single
/// place that decides what this app does about a host key. Adding a sixth call
/// path means calling this; a sixth path that does not is a path with no
/// connector, because nothing else hands one out.
ServerAccess serverAccessFor(
  BuildContext context, {
  required ServerProfile server,
  required SshCredential credential,
}) {
  final ServersModel servers = context.read<ServersModel>();
  final SshTransport transport = context.read<SshTransport>();
  // The pin as the store holds it now, not as the screen that pushed this route
  // remembered it: a profile captured before somebody answered the question
  // elsewhere would ask it a second time, and asking twice is how a question
  // becomes something people tap through.
  final ServerProfile current = servers.byId(server.id) ?? server;
  final BuildContext asking = context;
  return ServerAccess.trustOnFirstUse(
    transport: transport,
    server: current,
    credential: credential,
    prompt: (HostKeyQuestion question) async {
      if (!asking.mounted) {
        // Nothing is on screen to show it. Refusing is the only answer
        // available: a question nobody saw has not been answered, and the
        // credential stays on this device.
        return HostKeyDecision.refuse;
      }
      return askAboutHostKey(asking, question);
    },
    // Must not throw, and does not: ServersModel puts a save failure in its own
    // error banner rather than raising. Failing to write a file is not a reason
    // to abandon a connection somebody just approved.
    remember: (SshHostKey key) => servers.rememberHostKey(current.id, key),
  );
}

/// Puts one host key question in front of a person.
///
/// Dismissal returns [HostKeyDecision.refuse]. Every way out of this dialog
/// that is not an explicit tap on an accept button is a refusal, which is the
/// only default that does not send a root password to an unknown machine.
Future<HostKeyDecision> askAboutHostKey(
  BuildContext context,
  HostKeyQuestion question,
) async {
  final HostKeyDecision? answer = await showDialog<HostKeyDecision>(
    context: context,
    // Tapping the barrier is not an answer to this one.
    barrierDismissible: false,
    builder: (BuildContext dialogContext) => AlertDialog(
      title: Text(question.changed ? 'Host key CHANGED' : 'Unknown host key'),
      // No fixed width: a dialog wider than the phone it is on overflows.
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            // Verbatim, and in the error colour when the key changed: this is
            // the only text that says the box may have been rebuilt and that
            // the next step sends a root credential.
            FailureText(
              question.summary,
              tone: question.changed ? FailureTone.error : FailureTone.warning,
            ),
            _KeyFacts(heading: 'Offered now', hostKey: question.offered),
            if (question.pinned != null)
              _KeyFacts(
                heading: 'Pinned on this device',
                hostKey: question.pinned!,
              ),
            if (question.changed) ...<Widget>[
              const SizedBox(height: 12),
              const Text(
                'There is no "continue anyway" here. If you rebuilt this server '
                'yourself, drop the pin deliberately -- "Forget pinned host key" '
                'in the server\'s menu on the list screen -- and connect again. '
                'That asks the first-contact question from scratch, with the key '
                'in front of you.',
              ),
            ],
          ],
        ),
      ),
      actions: question.changed
          ? <Widget>[
              FilledButton(
                onPressed: () =>
                    Navigator.of(dialogContext).pop(HostKeyDecision.refuse),
                child: const Text('Do not connect'),
              ),
            ]
          : <Widget>[
              TextButton(
                onPressed: () =>
                    Navigator.of(dialogContext).pop(HostKeyDecision.refuse),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () =>
                    Navigator.of(dialogContext).pop(HostKeyDecision.trustOnce),
                child: const Text('Just this once'),
              ),
              FilledButton(
                onPressed: () =>
                    Navigator.of(dialogContext).pop(HostKeyDecision.trust),
                child: const Text('Trust and remember'),
              ),
            ],
    ),
  );
  return answer ?? HostKeyDecision.refuse;
}

/// Confirms dropping a pin, which is the only way back to a first-contact
/// question for a server whose key changed.
///
/// Deliberately not reachable from the refusal dialog: two taps in the same
/// place, one of which is "I know, connect anyway", is the arrangement this
/// whole path exists to avoid.
Future<bool> confirmForgetHostKey(
  BuildContext context,
  ServerProfile server,
) async {
  final bool? dropped = await showDialog<bool>(
    context: context,
    builder: (BuildContext dialogContext) => AlertDialog(
      title: Text('Forget the host key for ${server.label}?'),
      content: Text(
        'This device will stop recognising the machine at ${server.sshTarget} '
        'and will ask about its key the next time it connects, exactly as if it '
        'had never seen it.\n\n'
        'Do this when you rebuilt or restored the server yourself, and nothing '
        'else: a key that changed on its own is the one case a pin exists to '
        'catch, and dropping the pin throws away the evidence.',
      ),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: const Text('Keep it'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: const Text('Forget'),
        ),
      ],
    ),
  );
  return dropped ?? false;
}

class _KeyFacts extends StatelessWidget {
  const _KeyFacts({required this.heading, required this.hostKey});

  final String heading;
  final SshHostKey hostKey;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(heading, style: text.labelLarge),
          Text(hostKey.algorithm, style: text.bodySmall),
          Row(
            children: <Widget>[
              Expanded(
                // Selectable and monospaced: this is compared character by
                // character against what the machine or the provider console
                // reports, and that is the only check anybody can actually do.
                child: SelectableText(
                  hostKey.fingerprint,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              IconButton(
                tooltip: 'Copy fingerprint',
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () => unawaited(
                  copyValue(context, hostKey.fingerprint, what: 'Fingerprint'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
