import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../control/control.dart';
import 'common.dart';
import 'ports.dart';

/// Rendering one [ShareItem], by its shape and only by its shape.
///
/// This is the file that has to be right. A [ShareUri] gets a QR code and a
/// copy action, a [ShareFile] gets a save action, [ShareFields] get a labelled
/// table to type in. The server decided which of the three an item is and
/// `control/` refuses a payload that is more than one of them; this widget does
/// not second-guess either, and has no "show it as a URI" fallback.
///
/// That rule has a scar behind it. DNSTT-over-SSH has no import format at all
/// -- no scheme, nothing to scan -- and its settings were once crammed into a
/// `uri`. Every layer downstream treated them as one, producing a QR code no
/// client could read and a tappable link that imported nothing, and it failed
/// silently in the hands of whoever was sent it.
///
/// The switch is over a sealed type, so a fourth shape breaks the build here
/// instead of being rendered as whichever of the three it resembles.
class ShareItemView extends StatelessWidget {
  const ShareItemView({super.key, required this.item});

  final ShareItem item;

  @override
  Widget build(BuildContext context) {
    return switch (item) {
      final ShareUri uri => _UriItem(item: uri),
      final ShareFile file => _FileItem(item: file),
      final ShareFields fields => _FieldsItem(item: fields),
    };
  }
}

class _UriItem extends StatelessWidget {
  const _UriItem({required this.item});

  final ShareUri item;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: item.label,
      subtitle: 'Scan it, or paste it into a client that imports links.',
      children: <Widget>[
        Center(child: _Qr(item: item)),
        const SizedBox(height: 12),
        SelectableText(
          item.uri,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.tonalIcon(
            onPressed: () => copyValue(context, item.uri, what: item.label),
            icon: const Icon(Icons.copy, size: 18),
            label: const Text('Copy link'),
          ),
        ),
      ],
    );
  }
}

class _Qr extends StatelessWidget {
  const _Qr({required this.item});

  final ShareUri item;

  @override
  Widget build(BuildContext context) {
    if (item.qrPng == null) {
      // No encoder is bundled, deliberately: vpnctl renders the QR itself and
      // ships it as png_b64, so there is one implementation of what gets
      // encoded and the app cannot disagree with the CLI about it. An item that
      // arrived without one is shown as missing rather than as an empty white
      // square somebody would keep trying to scan.
      return Container(
        width: 220,
        height: 220,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          border: Border.all(color: Theme.of(context).colorScheme.outline),
          borderRadius: BorderRadius.circular(8),
        ),
        child: const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'No QR code: the server sent this link without one.\n'
            'Copy the text below instead.',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }
    return Container(
      // White, in both themes. The PNG is black modules on white, and a dark
      // surface showing through anything transparent in it is a QR code that
      // will not scan.
      color: const Color(0xFFFFFFFF),
      padding: const EdgeInsets.all(8),
      child: Image.memory(
        item.qrPng!,
        width: 220,
        height: 220,
        // Nearest-neighbour: the PNG is roughly one pixel per QR module, and
        // smoothing it on the way up turns a scannable code into a grey blur.
        filterQuality: FilterQuality.none,
        isAntiAlias: false,
        fit: BoxFit.contain,
        errorBuilder: (BuildContext context, Object error, StackTrace? stack) =>
            FailureText('the QR image did not decode: $error'),
      ),
    );
  }
}

class _FileItem extends StatefulWidget {
  const _FileItem({required this.item});

  final ShareFile item;

  @override
  State<_FileItem> createState() => _FileItemState();
}

class _FileItemState extends State<_FileItem> {
  String? _saved;
  String? _error;
  bool _saving = false;

  Future<void> _save() async {
    final ShareFile item = widget.item;
    final FileSaver saver = context.read<FileSaver>();
    setState(() {
      _saving = true;
      _error = null;
      _saved = null;
    });
    try {
      final String where = await saver.save(item.filename, item.content);
      if (!mounted) {
        return;
      }
      setState(() => _saved = where);
    } catch (e) {
      if (!mounted) {
        return;
      }
      setState(() => _error = describeError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final ShareFile item = widget.item;
    return SectionCard(
      title: item.label,
      subtitle: 'A file to import. There is no link and no QR code for it.',
      children: <Widget>[
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.description_outlined),
          title: Text(item.filename),
          subtitle: Text('${item.content.length} bytes'),
        ),
        // The .p12 ikev2 exports has an EMPTY password -- an unprotected
        // private key. Whoever ends up holding the file has VPN access, which
        // is why the CLI's own sharing is single-use and short-lived, and why
        // this says so before somebody mails one to themselves.
        const SizedBox(height: 4),
        const Text(
          'This file is the credential. It has no password of its own: anyone '
          'who gets a copy can connect as this user.',
        ),
        const SizedBox(height: 10),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.tonalIcon(
            onPressed: _saving ? null : _save,
            icon: _saving
                ? const InlineSpinner()
                : const Icon(Icons.save_alt, size: 18),
            label: const Text('Save'),
          ),
        ),
        if (_saved != null) ...<Widget>[
          const SizedBox(height: 10),
          Text('Saved to $_saved'),
        ],
        if (_error != null) ...<Widget>[
          const SizedBox(height: 10),
          FailureText(_error!),
        ],
      ],
    );
  }
}

class _FieldsItem extends StatelessWidget {
  const _FieldsItem({required this.item});

  final ShareFields item;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: item.label,
      // No QR, no link, and no apology for it: there is no import format for
      // these, so a code to scan could only encode something nothing reads.
      subtitle: 'Settings to enter by hand. There is no import format for '
          'these, so there is nothing to scan.',
      children: <Widget>[
        for (final ShareField field in item.fields)
          _FieldRow(field: field, label: item.label),
      ],
    );
  }
}

class _FieldRow extends StatelessWidget {
  const _FieldRow({required this.field, required this.label});

  final ShareField field;
  final String label;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 130,
            child: Text(field.setting, style: text.labelLarge),
          ),
          Expanded(
            child: SelectableText(
              field.value,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
          IconButton(
            tooltip: 'Copy ${field.setting}',
            icon: const Icon(Icons.copy, size: 18),
            onPressed: () => copyValue(
              context,
              field.value,
              what: '$label ${field.setting}',
            ),
          ),
        ],
      ),
    );
  }
}
