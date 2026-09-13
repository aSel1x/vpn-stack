import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../control/control.dart';
import '../tunnel/tunnel.dart';
import 'common.dart';
import 'connect_button.dart';
import 'host_key_prompt.dart';
import 'models.dart';
import 'ports.dart';
import 'user_share_screen.dart';

/// One server: what it is running, who has access, and whether this device is
/// connected to it.
class ServerDetailScreen extends StatelessWidget {
  const ServerDetailScreen({
    super.key,
    required this.server,
    required this.credential,
  });

  final ServerProfile server;
  final SshCredential credential;

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<ServerSession>(
      create: (BuildContext context) {
        final ServerSession session = ServerSession(
          // The one route to a connection: serverAccessFor reads the pinned
          // host key and wires the question. Every vpnctl call this screen
          // makes runs on the connection it opens, and before it existed they
          // all connected to whatever answered.
          access: serverAccessFor(
            context,
            server: server,
            credential: credential,
          ),
        );
        unawaited(session.refresh());
        return session;
      },
      child: const _DetailBody(),
    );
  }
}

class _DetailBody extends StatefulWidget {
  const _DetailBody();

  @override
  State<_DetailBody> createState() => _DetailBodyState();
}

class _DetailBodyState extends State<_DetailBody> {
  /// Whose credentials this device would connect with. Null until somebody
  /// picks, because there is no sensible default: the users on a server are
  /// people, and guessing which one is holding the phone is how two devices end
  /// up sharing one identity.
  String? _connectAs;

  @override
  Widget build(BuildContext context) {
    final ServerSession session = context.watch<ServerSession>();
    final ServerProfile server = session.server;

    return Scaffold(
      appBar: AppBar(
        title: Text(server.label),
        actions: <Widget>[
          IconButton(
            tooltip: 'Refresh',
            onPressed: session.busy ? null : () => unawaited(session.refresh()),
            icon: const Icon(Icons.refresh),
          ),
        ],
        bottom: session.busy
            ? const PreferredSize(
                preferredSize: Size.fromHeight(2),
                child: LinearProgressIndicator(minHeight: 2),
              )
            : null,
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: session.busy ? null : () => _addUser(context, session),
        icon: const Icon(Icons.person_add_alt),
        label: const Text('Add user'),
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 96),
        children: <Widget>[
          if (session.error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: FailureText(session.error!),
            ),
          if (session.notice != null)
            Padding(
              padding: const EdgeInsets.all(12),
              // Warning, not error: the command worked. Something it reported
              // on the way is unfinished, and `apply` only warns about these.
              child: FailureText(session.notice!, tone: FailureTone.warning),
            ),
          _ConnectCard(
            session: session,
            connectAs: _connectAs,
            onPick: (String? user) {
              setState(() => _connectAs = user);
              if (user != null) {
                unawaited(session.loadShare(user));
              }
            },
          ),
          _StatusCard(session: session),
          _UsersCard(session: session),
          _ProtocolsCard(session: session),
        ],
      ),
    );
  }

  Future<void> _addUser(BuildContext context, ServerSession session) {
    // The session is passed in, not read from a provider: showDialog pushes its
    // own route, which is a sibling of this screen's, so the
    // ChangeNotifierProvider that built this session is not above the dialog.
    return showDialog<void>(
      context: context,
      builder: (BuildContext dialogContext) => _AddUserDialog(session: session),
    );
  }
}

/// Add a user, and stay open until the SERVER has accepted the name.
///
/// The rule lives in `vpnctl/users_store.py` (`validate_name`), and it is the
/// server's alone: app/README.md says this app asks questions and renders
/// answers rather than reimplementing what the server already decides. This
/// dialog used to hold a copy of the regex, and the copy had already drifted --
/// it accepted `.hidden`, `_svc` and `-x`, which the server refuses because the
/// first character must be alphanumeric. The form said the name was fine, the
/// dialog closed, the name was lost, and a red banner appeared on the screen
/// behind it. So the answer comes from the server and lands next to the field
/// that produced it, with the text still there to correct.
///
/// The one check left here is a courtesy and cannot be authoritative. Its
/// safety property is that it is strictly WEAKER than the server's rule: it
/// only refuses to send an empty name, which the server refuses too, so no name
/// vpnctl would accept can be stopped by this form. Anything stronger -- a
/// character set, a length -- is the drift above, waiting to happen again.
class _AddUserDialog extends StatefulWidget {
  const _AddUserDialog({required this.session});

  final ServerSession session;

  @override
  State<_AddUserDialog> createState() => _AddUserDialogState();
}

class _AddUserDialogState extends State<_AddUserDialog> {
  final TextEditingController _name = TextEditingController();
  bool _submitting = false;

  /// What the server said when it refused. Verbatim: its sentence names the
  /// rule and the reason for it -- the IKEv2 user and password lists are
  /// space-separated, so a space hands one person another's password -- and no
  /// wording invented here could say that without becoming a second copy of
  /// the rule.
  String? _refusal;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  bool get _sendable => !_submitting && _name.text.trim().isNotEmpty;

  Future<void> _submit() async {
    if (widget.session.busy) {
      // Nothing ran. Said plainly rather than reported as a refusal: an apply
      // holding the session is not a bad name.
      setState(() => _refusal =
          'Another command is still running on this server. Nothing was sent; '
          'wait for it to finish and press Add again.');
      return;
    }
    setState(() {
      _submitting = true;
      _refusal = null;
    });
    final bool created = await widget.session.addUser(_name.text.trim());
    if (!mounted) {
      return;
    }
    if (created) {
      Navigator.of(context).pop();
      return;
    }
    final String? said = widget.session.error;
    setState(() {
      _submitting = false;
      _refusal = said == null || said.isEmpty
          ? 'The server refused and said nothing. Nothing was created.'
          : said;
    });
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Add user'),
      // Scrolls: the server's refusal is several lines and a phone keyboard
      // takes half the screen, and an overflowing dialog hides the message it
      // exists to show.
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            TextField(
              controller: _name,
              autofocus: true,
              autocorrect: false,
              enabled: !_submitting,
              onChanged: (String _) => setState(() {}),
              onSubmitted: (String _) {
                if (_sendable) {
                  unawaited(_submit());
                }
              },
              decoration: const InputDecoration(
                labelText: 'Name',
                border: OutlineInputBorder(),
                // Deliberately not the character rule. A hint that restates it
                // is the copy that drifted; the server states it, in its own
                // words, at the moment it matters.
                helperText: 'One word, no spaces.',
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'Creates credentials for every enabled protocol at once, then '
              'renders and converges. It takes a moment.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            if (_refusal != null) ...<Widget>[
              const SizedBox(height: 12),
              FailureText(_refusal!),
            ],
          ],
        ),
      ),
      actions: <Widget>[
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _sendable ? () => unawaited(_submit()) : null,
          child: _submitting ? const InlineSpinner() : const Text('Add'),
        ),
      ],
    );
  }
}

class _ConnectCard extends StatelessWidget {
  const _ConnectCard({
    required this.session,
    required this.connectAs,
    required this.onPick,
  });

  final ServerSession session;
  final String? connectAs;
  final ValueChanged<String?> onPick;

  @override
  Widget build(BuildContext context) {
    final List<VpnUser> enabled =
        session.users.where((VpnUser u) => u.enabled).toList();
    final String? user = connectAs;
    final ShareBundle? bundle = user == null ? null : session.bundleFor(user);
    final String? bundleError =
        user == null ? null : session.bundleErrorFor(user);
    final bool loading = user != null && session.isLoadingBundle(user);

    final List<String> uris = bundle?.importUris ?? const <String>[];
    final TunnelProfile? profile = (user == null || uris.isEmpty)
        ? null
        : TunnelProfile(
            id: session.server.id,
            label: '${session.server.label} ($user)',
            host: session.server.host,
            importUris: uris,
          );

    return SectionCard(
      title: 'This device',
      children: <Widget>[
        if (enabled.isEmpty)
          const Text('No enabled users yet. Add one to connect.')
        else
          // DropdownButton, not DropdownButtonFormField: the FormField's
          // selected-value parameter was renamed between Flutter releases and
          // this repository cannot run the analyzer to find out which name the
          // runner has. The plain one has always been `value`.
          Row(
            children: <Widget>[
              const Text('Connect as'),
              const SizedBox(width: 12),
              Expanded(
                child: DropdownButton<String>(
                  value: user,
                  isExpanded: true,
                  hint: const Text('pick a user'),
                  items: <DropdownMenuItem<String>>[
                    for (final VpnUser u in enabled)
                      DropdownMenuItem<String>(
                        value: u.name,
                        child: Text(u.name),
                      ),
                  ],
                  onChanged: session.busy ? null : onPick,
                ),
              ),
            ],
          ),
        const SizedBox(height: 12),
        if (loading)
          const Row(
            children: <Widget>[
              InlineSpinner(),
              SizedBox(width: 10),
              Expanded(child: Text('Fetching this user’s profiles.')),
            ],
          )
        else if (bundleError != null)
          FailureText(bundleError)
        else
          ConnectButton(
            profile: profile,
            unavailableReason: _why(user, bundle, uris),
          ),
      ],
    );
  }

  String? _why(String? user, ShareBundle? bundle, List<String> uris) {
    if (user == null) {
      return 'Pick a user first. The tunnel is brought up with that '
          'person’s credentials.';
    }
    if (bundle == null) {
      return 'Their profiles have not been fetched yet.';
    }
    if (uris.isEmpty) {
      // The honest statement of what this app can and cannot carry. sing-box
      // takes the link-shaped protocols; an IKEv2 bundle is a file the
      // operating system imports and DNSTT is settings for an SSH client, and
      // neither is something this button could bring up.
      return 'Nothing here is a link the tunnel engine can import. This server '
          'is only offering file or settings profiles for $user, which are '
          'imported by hand -- see their share page.';
    }
    return null;
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.session});

  final ServerSession session;

  @override
  Widget build(BuildContext context) {
    final ServerStatus? status = session.status;
    if (status == null) {
      return SectionCard(
        title: 'Server',
        children: <Widget>[
          Text(
            session.busy
                ? 'Asking the server what it is running.'
                : 'No answer from the server yet.',
          ),
        ],
      );
    }
    return SectionCard(
      title: 'Server',
      subtitle: '${session.server.target}  ·  ${status.stateDir}',
      children: <Widget>[
        if (!status.isServer)
          // Every mutating command will refuse, and each one would refuse for a
          // reason it never states. Said once, here.
          const FailureText(
            'The state directory is not there, so this box is not a vpn-stack '
            'server: every command that changes anything will refuse. Restore '
            'a backup, or provision it.',
          ),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: <Widget>[
            for (final String name in status.enabled) Chip(label: Text(name)),
            if (status.enabled.isEmpty)
              const Chip(label: Text('no protocols enabled')),
          ],
        ),
        const SizedBox(height: 10),
        Text('${status.usersEnabled} of ${status.users} users enabled'),
        Text(
          status.rendered == null
              ? 'nothing applied yet'
              : 'config ${status.rendered}',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        Text(
          status.ikev2Running ? 'ikev2 container up' : 'ikev2 container down',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        if (status.revokePending.isNotEmpty) ...<Widget>[
          const SizedBox(height: 10),
          // Not cosmetic: a pending revocation means somebody's certificate is
          // still working after they were removed or disabled.
          FailureText(
            'Revocations the server has not been able to run: '
            '${status.revokePending.join(', ')}. Until they run, those '
            'certificates still connect. They are retried on the next apply '
            'with the ikev2 container up.',
          ),
        ],
      ],
    );
  }
}

class _UsersCard extends StatelessWidget {
  const _UsersCard({required this.session});

  final ServerSession session;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: 'Users',
      children: <Widget>[
        if (session.users.isEmpty)
          const Text('Nobody yet.')
        else
          for (final VpnUser user in session.users)
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                user.enabled ? Icons.person : Icons.person_off_outlined,
              ),
              title: Text(user.name),
              subtitle: Text(
                <String>[
                  user.enabled ? 'enabled' : 'disabled',
                  if (user.ikev2Provisioned) 'ikev2 certificate',
                  'added ${user.createdAt}',
                ].join(' · '),
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: <Widget>[
                  IconButton(
                    tooltip: 'Share',
                    icon: const Icon(Icons.qr_code_2),
                    onPressed: session.busy
                        ? null
                        : () => _openShare(context, user.name),
                  ),
                  PopupMenuButton<String>(
                    enabled: !session.busy,
                    onSelected: (String choice) =>
                        _onMenu(context, user, choice),
                    itemBuilder: (BuildContext context) =>
                        <PopupMenuEntry<String>>[
                      PopupMenuItem<String>(
                        value: 'toggle',
                        child: Text(user.enabled ? 'Disable' : 'Enable'),
                      ),
                      const PopupMenuItem<String>(
                        value: 'remove',
                        child: Text('Remove'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
      ],
    );
  }

  void _openShare(BuildContext context, String user) {
    unawaited(
      Navigator.of(context).push<void>(
        MaterialPageRoute<void>(
          builder: (_) => ChangeNotifierProvider<ServerSession>.value(
            // The same session, not a second one: a connection per screen is
            // how a phone ends up holding four of them.
            value: session,
            child: UserShareScreen(user: user),
          ),
        ),
      ),
    );
  }

  Future<void> _onMenu(
    BuildContext context,
    VpnUser user,
    String choice,
  ) async {
    if (choice == 'toggle') {
      if (!user.enabled) {
        final bool? go = await confirm(
          context,
          title: 'Enable ${user.name}?',
          // Straight from the CLI's hard-won notes, and it surprises people:
          // re-enabling issues a new certificate and the old profile stops
          // working.
          body: 'IKEv2 issues a brand-new certificate on enable. Any profile '
              'this person already has stops working and has to be exported '
              'and sent again.',
          confirmLabel: 'Enable',
        );
        if (!(go ?? false)) {
          return;
        }
      }
      await session.setUserEnabled(user.name, enabled: !user.enabled);
      return;
    }
    final bool? go = await confirm(
      context,
      title: 'Remove ${user.name}?',
      body: 'Permanent. Their credentials for every protocol are deleted and '
          'their IKEv2 certificate is revoked. There is no undo, and a new '
          'user of the same name gets entirely new credentials.',
      confirmLabel: 'Remove',
    );
    if (go ?? false) {
      await session.removeUser(user.name);
    }
  }
}

class _ProtocolsCard extends StatelessWidget {
  const _ProtocolsCard({required this.session});

  final ServerSession session;

  @override
  Widget build(BuildContext context) {
    if (session.protocols.isEmpty) {
      return const SizedBox.shrink();
    }
    return SectionCard(
      title: 'Protocols',
      children: <Widget>[
        for (final ProtocolEntry protocol in session.protocols)
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            value: protocol.enabled,
            onChanged: session.busy
                ? null
                : (bool on) => _toggle(context, protocol, on),
            title: Text('${protocol.name}  ${protocol.ports.join(' ')}'),
            subtitle: Text(
              protocol.enabled || protocol.notes.isEmpty
                  ? protocol.summary
                  : '${protocol.summary}\n(${protocol.notes})',
            ),
            isThreeLine: !protocol.enabled && protocol.notes.isNotEmpty,
          ),
      ],
    );
  }

  Future<void> _toggle(
    BuildContext context,
    ProtocolEntry protocol,
    bool on,
  ) async {
    final bool? go = await confirm(
      context,
      title: on
          ? 'Turn on ${protocol.name}?'
          : 'Turn off ${protocol.name}?',
      body: on
          // dnstt mints its Noise keypair by building a Go image the first
          // time, which is around 800MB of download on the server. Worth
          // saying before somebody taps it on a metered VPS.
          ? 'The server renders, validates and converges. Turning on a '
              'protocol for the first time can take several minutes if it has '
              'to build an image.'
          : 'It stops serving immediately and every session on it drops. '
              'Turning it back on restores the same credentials -- nothing is '
              'destroyed.',
      confirmLabel: on ? 'Turn on' : 'Turn off',
    );
    if (!(go ?? false)) {
      return;
    }
    await session.setProtocol(protocol.name, enabled: on);
  }
}

/// A yes/no dialog. Returns null when it was dismissed, which callers must read
/// as "do nothing" rather than as "no, but proceed".
Future<bool?> confirm(
  BuildContext context, {
  required String title,
  required String body,
  required String confirmLabel,
}) {
  return showDialog<bool>(
    context: context,
    builder: (BuildContext dialogContext) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
}
