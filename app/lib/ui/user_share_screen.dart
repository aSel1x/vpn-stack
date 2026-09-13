import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../control/control.dart';
import 'common.dart';
import 'models.dart';
import 'share_view.dart';

/// Everything one user can be handed, grouped by protocol.
///
/// The protocols are listed in the order the server sent them, which is the
/// registry's order. Nothing is filtered: `per_user` says whether a protocol
/// issues a distinct credential per person and it must not gate sharing --
/// filtering on it once made this screen's equivalent return nothing at all for
/// dnstt, silently.
class UserShareScreen extends StatefulWidget {
  const UserShareScreen({super.key, required this.user});

  final String user;

  @override
  State<UserShareScreen> createState() => _UserShareScreenState();
}

class _UserShareScreenState extends State<UserShareScreen> {
  @override
  void initState() {
    super.initState();
    // After the frame, because this reads a provider above us and starts work
    // that calls notifyListeners.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) {
        return;
      }
      unawaited(context.read<ServerSession>().loadShare(widget.user));
    });
  }

  @override
  Widget build(BuildContext context) {
    final ServerSession session = context.watch<ServerSession>();
    final ShareBundle? bundle = session.bundleFor(widget.user);
    final String? error = session.bundleErrorFor(widget.user);
    final bool loading = session.isLoadingBundle(widget.user);

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.user),
        actions: <Widget>[
          IconButton(
            tooltip: 'Re-export',
            onPressed: loading
                ? null
                : () => unawaited(
                      session.loadShare(widget.user, force: true),
                    ),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 32),
        children: <Widget>[
          // Said once, at the top, because everything below it is a working
          // credential and people forward these.
          const SectionCard(
            title: 'These are credentials',
            children: <Widget>[
              Text(
                'Anything on this page lets whoever holds it connect as this '
                'user. Send it over something you trust, and remove the user '
                'if it goes astray.',
              ),
            ],
          ),
          if (loading)
            const Padding(
              padding: EdgeInsets.all(32),
              child: Center(child: CircularProgressIndicator()),
            ),
          if (error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              // One unreadable item costs the whole page, and that is the
              // chosen trade. `control/` refuses a share item that carries no
              // shape or two of them instead of rendering a fourth "malformed"
              // kind, because the only thing this screen could do with one is
              // guess which of uri/filename/fields it meant -- the guess that
              // shipped a QR code nothing could scan. The refusal names the
              // item and the reason, Re-export retries, and `./vpn user export`
              // still works meanwhile; a page that rendered around the bad item
              // would look complete instead.
              child: FailureText(error),
            ),
          if (bundle != null) ...<Widget>[
            if (bundle.failed.isNotEmpty)
              Padding(
                padding: const EdgeInsets.all(12),
                // The server reports a failed export separately rather than
                // returning ok with no files, and so does this: a share page
                // that is silently missing the one profile somebody asked for
                // is how that class of bug stays invisible.
                child: FailureText(
                  'The server could not export: ${bundle.failed.join(', ')}. '
                  'Those profiles are missing from this page. For ikev2 the '
                  'usual cause is the container being down.',
                ),
              ),
            for (final MapEntry<String, List<ShareItem>> group
                in bundle.byProtocol.entries)
              _ProtocolGroup(protocol: group.key, items: group.value),
            if (bundle.byProtocol.isEmpty && bundle.failed.isEmpty)
              const Padding(
                padding: EdgeInsets.all(12),
                child: Text(
                  'The server returned no profiles for this user. Either no '
                  'protocol is enabled, or this user has no credential for the '
                  'ones that are.',
                ),
              ),
          ],
        ],
      ),
    );
  }
}

class _ProtocolGroup extends StatelessWidget {
  const _ProtocolGroup({required this.protocol, required this.items});

  final String protocol;
  final List<ShareItem> items;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 18, 16, 2),
          child: Text(
            protocol,
            style: Theme.of(context).textTheme.titleSmall,
          ),
        ),
        if (items.isEmpty)
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 4, 16, 4),
            child: Text('nothing to hand over for this protocol'),
          )
        else
          for (final ShareItem item in items) ShareItemView(item: item),
      ],
    );
  }
}
