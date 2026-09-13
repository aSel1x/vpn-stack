import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'common.dart';
import 'credential_form.dart';
import 'models.dart';
import 'ports.dart';
import 'provision_screen.dart';
import 'server_detail_screen.dart';

/// Adding a server: where it is, how to reach it, and what happens next.
///
/// Two ways out, because they are genuinely different jobs. "Provision" takes a
/// bare VPS and installs everything. "Add only" is for a box that is already
/// running vpn-stack -- the CLI installed it, or this app did on another
/// device -- and running provisioning against one of those would be at best a
/// long no-op.
class AddServerScreen extends StatefulWidget {
  const AddServerScreen({super.key});

  @override
  State<AddServerScreen> createState() => _AddServerScreenState();
}

class _AddServerScreenState extends State<AddServerScreen> {
  final TextEditingController _label = TextEditingController();
  final TextEditingController _host = TextEditingController();
  final TextEditingController _user = TextEditingController(text: 'root');
  final TextEditingController _port = TextEditingController(text: '22');
  SshCredential? _credential;
  String? _error;

  @override
  void initState() {
    super.initState();
    for (final TextEditingController c in <TextEditingController>[
      _label,
      _host,
      _user,
      _port,
    ]) {
      c.addListener(() => setState(() {}));
    }
  }

  @override
  void dispose() {
    _label.dispose();
    _host.dispose();
    _user.dispose();
    _port.dispose();
    super.dispose();
  }

  String get _hostValue => _host.text.trim();

  int? get _portValue => int.tryParse(_port.text.trim());

  bool get _addressOk =>
      _hostValue.isNotEmpty &&
      _user.text.trim().isNotEmpty &&
      _portValue != null &&
      _portValue! > 0 &&
      _portValue! < 65536;

  ServerProfile _build() {
    final String label = _label.text.trim();
    return ServerProfile(
      // Time-based, because it only has to be unique within this app and
      // pulling in a uuid package for four digits of entropy is not worth a
      // dependency nobody can resolve on this machine.
      id: 'srv-${DateTime.now().microsecondsSinceEpoch}',
      label: label.isEmpty ? _hostValue : label,
      host: _hostValue,
      sshUser: _user.text.trim(),
      sshPort: _portValue ?? 22,
    );
  }

  Future<void> _addOnly() async {
    final ServersModel servers = context.read<ServersModel>();
    final CredentialVault vault = context.read<CredentialVault>();
    final ServerProfile server = _build().copyWith(
      // Claimed, not observed. The detail screen's first call to vpnctl is what
      // actually decides whether this box is serving; marking it provisioned
      // here only stops the app from offering to install over the top of it.
      provisionedAt: DateTime.now().toUtc(),
    );
    final SshCredential? credential = _credential;
    if (credential != null) {
      vault.remember(server.id, credential);
    }
    await servers.add(server);
    if (!mounted) {
      return;
    }
    final String? failure = servers.error;
    if (failure != null) {
      setState(() => _error = failure);
      return;
    }
    if (credential == null) {
      // Nothing to open a session with. Back to the list, where tapping the
      // server asks for one.
      Navigator.of(context).pop();
      return;
    }
    await Navigator.of(context).pushReplacement<void, void>(
      MaterialPageRoute<void>(
        builder: (_) =>
            ServerDetailScreen(server: server, credential: credential),
      ),
    );
  }

  Future<void> _provision() async {
    final ServersModel servers = context.read<ServersModel>();
    final CredentialVault vault = context.read<CredentialVault>();
    final SshCredential? credential = _credential;
    if (credential == null) {
      return;
    }
    final ServerProfile server = _build();
    vault.remember(server.id, credential);
    await servers.add(server);
    if (!mounted) {
      return;
    }
    final String? failure = servers.error;
    if (failure != null) {
      setState(() => _error = failure);
      return;
    }
    await Navigator.of(context).pushReplacement<void, void>(
      MaterialPageRoute<void>(
        builder: (_) => ProvisionScreen(server: server, credential: credential),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Add server')),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 32),
        children: <Widget>[
          SectionCard(
            title: 'Where it is',
            children: <Widget>[
              TextField(
                controller: _host,
                autofocus: true,
                keyboardType: TextInputType.url,
                autocorrect: false,
                decoration: const InputDecoration(
                  labelText: 'Host or IP',
                  border: OutlineInputBorder(),
                  // Named because it is a real failure: a box reached through a
                  // jump host is not reached at the address its client profiles
                  // have to carry.
                  helperText: 'The address clients will connect to.',
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: <Widget>[
                  Expanded(
                    flex: 2,
                    child: TextField(
                      controller: _user,
                      autocorrect: false,
                      decoration: const InputDecoration(
                        labelText: 'SSH user',
                        border: OutlineInputBorder(),
                        helperText: 'Needs root: every step wants it.',
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: TextField(
                      controller: _port,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(
                        labelText: 'SSH port',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _label,
                decoration: const InputDecoration(
                  labelText: 'Name (optional)',
                  border: OutlineInputBorder(),
                  helperText: 'Shown in the list and in the OS VPN settings.',
                ),
              ),
            ],
          ),
          SectionCard(
            title: 'How to log in',
            // It said "Used once, to provision. Not stored." Half of that was
            // true and the wrong half was the headline: the credential is never
            // written to disk, and it is reused for every vpnctl call after
            // provisioning -- opening the server, listing users, exporting a
            // profile -- because each one is another SSH session. Making the
            // old copy true would mean asking for a root password before every
            // status refresh, which is worse in every direction; so the copy
            // changed instead. CredentialVault is what holds it, and what
            // "Forget SSH credential" empties.
            subtitle: 'Kept in memory while the app runs, and used for every '
                'command this app sends to the server. Never written to disk.',
            children: <Widget>[
              CredentialPicker(
                onChanged: (SshCredential? credential) =>
                    setState(() => _credential = credential),
              ),
            ],
          ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: FailureText(_error!),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 6, 12, 6),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: <Widget>[
                FilledButton(
                  onPressed:
                      _addressOk && _credential != null ? _provision : null,
                  child: const Text('Provision this server'),
                ),
                const SizedBox(height: 8),
                Text(
                  'Installs Docker, clones the repository, generates the '
                  'keyring and brings the protocols up. Safe to run on a bare '
                  'VPS; do not run it on a box that is already serving.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 20),
                OutlinedButton(
                  onPressed: _addressOk ? _addOnly : null,
                  child: const Text('Add only, it already runs vpn-stack'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
