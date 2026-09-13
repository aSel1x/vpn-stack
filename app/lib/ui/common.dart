import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Small pieces every screen needs. Nothing here knows about a server.

/// Text shown exactly as it arrived.
///
/// Selectable and monospaced on purpose: a failure in this app is usually a
/// vpnctl sentence or a line of shell output, and it is diagnosed by pasting it
/// somewhere. Summarising it into "an error occurred" throws away the only part
/// that says what happened.
class FailureText extends StatelessWidget {
  const FailureText(this.text, {super.key, this.tone = FailureTone.error});

  final String text;
  final FailureTone tone;

  @override
  Widget build(BuildContext context) {
    final ColorScheme colors = Theme.of(context).colorScheme;
    final bool warn = tone == FailureTone.warning;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        // Not surfaceContainerHighest: a SectionCard already uses that, and a
        // warning drawn in the card's own colour is a warning nobody sees.
        color: warn ? colors.secondaryContainer : colors.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: SelectableText(
        text,
        style: TextStyle(
          fontFamily: 'monospace',
          fontFamilyFallback: const <String>['Menlo', 'Consolas', 'DejaVu Sans Mono'],
          fontSize: 12,
          height: 1.4,
          color: warn ? colors.onSecondaryContainer : colors.onErrorContainer,
        ),
      ),
    );
  }
}

enum FailureTone { error, warning }

/// A titled block. Used instead of a bare [Card] so every screen indents and
/// spaces the same way without each one restating the padding.
class SectionCard extends StatelessWidget {
  const SectionCard({
    super.key,
    required this.title,
    required this.children,
    this.trailing,
    this.subtitle,
  });

  final String title;
  final String? subtitle;
  final Widget? trailing;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      margin: const EdgeInsets.fromLTRB(12, 6, 12, 6),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                Expanded(child: Text(title, style: text.titleMedium)),
                if (trailing != null) trailing!,
              ],
            ),
            if (subtitle != null) ...<Widget>[
              const SizedBox(height: 4),
              Text(subtitle!, style: text.bodySmall),
            ],
            const SizedBox(height: 10),
            ...children,
          ],
        ),
      ),
    );
  }
}

/// Puts [value] on the clipboard and says so.
///
/// The snackbar is not decoration: several of these values are indistinguishable
/// from each other at a glance (two base64 blobs, two passwords), so "it copied"
/// is the only feedback that a tap on the right row did anything.
Future<void> copyValue(
  BuildContext context,
  String value, {
  required String what,
}) async {
  await Clipboard.setData(ClipboardData(text: value));
  if (!context.mounted) {
    return;
  }
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text('$what copied'), duration: const Duration(seconds: 2)),
  );
}

/// A spinner sized to sit inside a button or a list tile.
class InlineSpinner extends StatelessWidget {
  const InlineSpinner({super.key, this.size = 16});

  final double size;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: const CircularProgressIndicator(strokeWidth: 2),
    );
  }
}
