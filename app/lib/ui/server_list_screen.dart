import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'add_server_screen.dart';
import 'common.dart';
import 'credential_form.dart';
import 'host_key_prompt.dart';
import 'models.dart';
import 'ports.dart';
import 'server_detail_screen.dart';

/// The configured servers. The first screen, and on a fresh install an empty
/// one with a single button on it.
class ServerListScreen extends StatelessWidget {
  const ServerListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final ServersModel servers = context.watch<ServersModel>();
    final TunnelModel tunnel = context.watch<TunnelModel>();

    return Scaffold(
      appBar: AppBar(title: const Text('Servers')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _add(context),
        icon: const Icon(Icons.add),
        label: const Text('Add server'),
      ),
      body: Builder(
        builder: (BuildContext context) {
          if (servers.loading) {
            return const Center(child: CircularProgressIndicator());
          }
          final String? error = servers.error;
          return ListView(
            padding: const EdgeInsets.only(bottom: 96),
            children: <Widget>[
              if (error != null)
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: FailureText(error),
                ),
              if (servers.servers.isEmpty)
                const _Empty()
              else
                for (final ServerProfile server in servers.servers)
                  _ServerTile(server: server, tunnel: tunnel),
            ],
          );
        },
      ),
    );
  }

  Future<void> _add(BuildContext context) async {
    await Navigator.of(context).push<void>(
      MaterialPageRoute<void>(builder: (_) => const AddServerScreen()),
    );
  }
}

class _Empty extends StatelessWidget {
  const _Empty();

  @override
  Widget build(BuildContext context) {
    return const Padding(
      padding: EdgeInsets.fromLTRB(24, 64, 24, 24),
      child: Column(
        children: <Widget>[
          Text('No servers yet.', textAlign: TextAlign.center),
          SizedBox(height: 8),
          Text(
            'Add one to provision a bare VPS, or to manage a server that is '
            'already running vpn-stack.',
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

class _ServerTile extends StatelessWidget {
  const _ServerTile({required this.server, required this.tunnel});

  final ServerProfile server;
  final TunnelModel tunnel;

  @override
  Widget build(BuildContext context) {
    final bool up = tunnel.isUpFor(server.id);
    final bool connecting = tunnel.isBusyFor(server.id);
    final bool failed = tunnel.isFailedFor(server.id);
    // Shown, not just held. The credential is kept in memory for as long as
    // the app runs -- every vpnctl call needs it -- so the person who typed a
    // root password into this app is entitled to see that it is still here and
    // to drop it. A "Forget SSH credential" that silently does nothing on a
    // server holding none is the same lie in the other direction.
    final bool held = context.watch<CredentialVault>().holds(server.id);

    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      margin: const EdgeInsets.fromLTRB(12, 6, 12, 6),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)),
      ),
      child: ListTile(
        leading: Icon(
          up ? Icons.shield : Icons.dns_outlined,
          color: up ? Theme.of(context).colorScheme.primary : null,
        ),
        title: Text(server.label),
        subtitle: Text(
          <String>[
            server.target,
            if (!server.provisioned) 'not provisioned',
            if (held) 'SSH credential held',
            // Shown for the same reason the credential is: a pin is a promise
            // this device made about which machine it will talk to, and a
            // promise nobody can see is one nobody can withdraw.
            if (server.pinned) 'host key pinned',
            if (connecting) 'connecting',
            if (up) 'connected',
            if (failed) 'last connection attempt failed',
          ].join(' · '),
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (String choice) => _onMenu(context, choice),
          itemBuilder: (BuildContext context) => <PopupMenuEntry<String>>[
            if (held)
              const PopupMenuItem<String>(
                value: 'forget-credential',
                child: Text('Forget SSH credential'),
              ),
            // The only way back to a first-contact question. A changed host key
            // is refused where it is noticed, with no accept button, so
            // re-pinning a box you rebuilt yourself happens here instead --
            // deliberately, on the list screen, not one tap from the warning.
            if (server.pinned)
              const PopupMenuItem<String>(
                value: 'forget-host-key',
                child: Text('Forget pinned host key'),
              ),
            const PopupMenuItem<String>(
              value: 'remove',
              child: Text('Remove from this app'),
            ),
          ],
        ),
        onTap: () => openServer(context, server),
      ),
    );
  }

  Future<void> _onMenu(BuildContext context, String choice) async {
    final ServersModel servers = context.read<ServersModel>();
    final CredentialVault vault = context.read<CredentialVault>();
    // Read before the dialog, not after: every use of `context` past an await
    // is a use of a context that may be gone.
    final TunnelModel tunnel = context.read<TunnelModel>();
    final ScaffoldMessengerState messenger = ScaffoldMessenger.of(context);
    if (choice == 'forget-credential') {
      vault.forget(server.id);
      return;
    }
    if (choice == 'forget-host-key') {
      if (await confirmForgetHostKey(context, server)) {
        await servers.forgetHostKey(server.id);
      }
      return;
    }
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext dialogContext) => AlertDialog(
        title: Text('Remove ${server.label}?'),
        // Said precisely, because the opposite mistake is expensive: somebody
        // who thinks this tears the server down will not tear it down.
        content: const Text(
          'This removes the server from this app only. Nothing is uninstalled, '
          'no user is deleted and no key is destroyed on the server -- it keeps '
          'serving, and adding it again gets everything back.\n\n'
          'The host key this device pinned goes with the record, so adding the '
          'server again asks about its key from scratch.\n\n'
          'This device\'s VPN profile goes too, along with the configuration it '
          'would start from -- so the server stops appearing in the system\'s '
          'VPN settings and cannot be switched on from there. That still '
          'revokes nothing: the credentials it carried stay valid until '
          '`vpn user rm` deletes the user on the server.',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed ?? false) {
      // Before the app's own record goes, because afterwards there is nothing
      // left that names this server: the system VPN profile and the stored
      // configuration behind it are this device's copy of the credential, and
      // leaving them is how a removed server keeps a row under the system's
      // VPN settings that still connects.
      //
      // It cannot veto the removal -- the person asked for the server to go,
      // and a tunnel layer that could not tidy up is not a reason to keep the
      // record -- but what it could not remove has to be said, because what
      // survives is a credential.
      final String? left = await tunnel.forgetProfile(server.id);
      vault.forget(server.id);
      await servers.remove(server.id);
      if (left != null) {
        messenger.showSnackBar(
          SnackBar(content: Text(left), duration: const Duration(seconds: 10)),
        );
      }
    }
  }
}

/// Opens a server, asking for the SSH credential if this run of the app does
/// not have one.
///
/// Shared with the provisioning screen's "Open server" button, so both paths go
/// through the same credential rule instead of one of them quietly not having
/// one.
Future<void> openServer(BuildContext context, ServerProfile server) async {
  final CredentialVault vault = context.read<CredentialVault>();
  SshCredential? credential = vault.of(server.id);
  if (credential == null) {
    credential = await askForCredential(context, server);
    if (credential == null) {
      return;
    }
    vault.remember(server.id, credential);
  }
  final SshCredential resolved = credential;
  if (!context.mounted) {
    return;
  }
  await Navigator.of(context).push<void>(
    MaterialPageRoute<void>(
      builder: (_) => ServerDetailScreen(server: server, credential: resolved),
    ),
  );
}
