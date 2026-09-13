import 'package:flutter/material.dart';

import 'ports.dart';

/// Entering an SSH credential, and saying plainly what happens to it.
///
/// The wording is the point, and it has to match [CredentialVault] rather than
/// the reassurance somebody would rather give. This app asks for a root
/// password or a private key -- the most dangerous thing anybody will type into
/// it -- and what actually happens is: never written to disk, never sent
/// anywhere but this server, held in memory for as long as the app runs because
/// every command after provisioning is another SSH session, and dropped on quit
/// or on "Forget SSH credential". The copy below says that. It used to say the
/// credential was used once and then forgotten, which was false in the one
/// direction that matters.
class CredentialPicker extends StatefulWidget {
  const CredentialPicker({
    super.key,
    required this.onChanged,
    this.autofocus = false,
  });

  /// Called with the credential, or null while it is incomplete -- so a caller
  /// can disable its button on exactly the same condition the form is showing.
  final ValueChanged<SshCredential?> onChanged;

  final bool autofocus;

  @override
  State<CredentialPicker> createState() => _CredentialPickerState();
}

enum _Kind { password, key }

class _CredentialPickerState extends State<CredentialPicker> {
  _Kind _kind = _Kind.password;
  final TextEditingController _password = TextEditingController();
  final TextEditingController _pem = TextEditingController();
  final TextEditingController _passphrase = TextEditingController();
  bool _reveal = false;

  @override
  void initState() {
    super.initState();
    for (final TextEditingController c in <TextEditingController>[
      _password,
      _pem,
      _passphrase,
    ]) {
      c.addListener(_publish);
    }
  }

  @override
  void dispose() {
    _password.dispose();
    _pem.dispose();
    _passphrase.dispose();
    super.dispose();
  }

  void _publish() => widget.onChanged(value);

  /// Null until there is something usable. An empty passphrase is legitimate --
  /// most keys have none -- so only the key material itself is required.
  SshCredential? get value {
    switch (_kind) {
      case _Kind.password:
        final String p = _password.text;
        return p.isEmpty ? null : SshPassword(p);
      case _Kind.key:
        final String pem = _pem.text.trim();
        if (!pem.startsWith('-----BEGIN')) {
          // Not validation theatre: the single most common way to get this
          // wrong is pasting the .pub half, and the failure that produces is an
          // authentication refusal three layers away that says nothing about
          // which file you picked.
          return null;
        }
        final String phrase = _passphrase.text;
        return SshPrivateKey(pem, passphrase: phrase.isEmpty ? null : phrase);
    }
  }

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        SegmentedButton<_Kind>(
          segments: const <ButtonSegment<_Kind>>[
            ButtonSegment<_Kind>(value: _Kind.password, label: Text('Password')),
            ButtonSegment<_Kind>(value: _Kind.key, label: Text('Private key')),
          ],
          selected: <_Kind>{_kind},
          onSelectionChanged: (Set<_Kind> selection) {
            setState(() => _kind = selection.first);
            _publish();
          },
        ),
        const SizedBox(height: 12),
        if (_kind == _Kind.password)
          TextField(
            controller: _password,
            autofocus: widget.autofocus,
            obscureText: !_reveal,
            decoration: InputDecoration(
              labelText: 'SSH password',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                tooltip: _reveal ? 'Hide' : 'Show',
                icon: Icon(_reveal ? Icons.visibility_off : Icons.visibility),
                onPressed: () => setState(() => _reveal = !_reveal),
              ),
            ),
          )
        else ...<Widget>[
          TextField(
            controller: _pem,
            autofocus: widget.autofocus,
            minLines: 4,
            maxLines: 8,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: const InputDecoration(
              labelText: 'Private key (PEM)',
              helperText: 'The private half, beginning -----BEGIN. Not the .pub.',
              border: OutlineInputBorder(),
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _passphrase,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Key passphrase (leave empty if there is none)',
              border: OutlineInputBorder(),
            ),
          ),
        ],
        const SizedBox(height: 10),
        Text(
          'Used to open SSH sessions to this server and nothing else. It is '
          'never written to disk and never sent anywhere else. The app keeps it '
          'in memory while it runs, because every command it sends — listing '
          'users, exporting a profile — is another SSH session; it is forgotten '
          'when the app quits, or when you pick "Forget SSH credential" on the '
          'server.',
          style: text.bodySmall,
        ),
      ],
    );
  }
}

/// Asks for a credential in a dialog, for a server that already exists.
///
/// Returns null if it was dismissed. Callers must treat that as "do nothing",
/// not as "try anyway".
Future<SshCredential?> askForCredential(
  BuildContext context,
  ServerProfile server,
) {
  return showDialog<SshCredential>(
    context: context,
    builder: (BuildContext dialogContext) {
      SshCredential? entered;
      return StatefulBuilder(
        builder: (BuildContext context, StateSetter setDialogState) {
          return AlertDialog(
            title: Text('SSH to ${server.target}'),
            // No fixed width: a dialog wider than the phone it is on overflows,
            // and the content sizes itself perfectly well.
            content: SingleChildScrollView(
              child: CredentialPicker(
                autofocus: true,
                onChanged: (SshCredential? credential) =>
                    setDialogState(() => entered = credential),
              ),
            ),
            actions: <Widget>[
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: entered == null
                    ? null
                    : () => Navigator.of(dialogContext).pop(entered),
                child: const Text('Connect'),
              ),
            ],
          );
        },
      );
    },
  );
}
