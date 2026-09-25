import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../tunnel/tunnel.dart';
import 'common.dart';
import 'models.dart';

/// Connect, and the four states it can be in.
///
/// There is no fifth state and no optimistic one: what is drawn here comes from
/// [TunnelController] and nothing else. On Android and iOS that is
/// `SingboxTunnel`, which refuses to report connected without evidence a tun
/// exists; on the three desktop targets it is `UnimplementedTunnel`, and
/// pressing this shows the failure that platform's missing helper produces.
/// Either way the button reports what the engine reported, which is why this
/// file has no idea which engine it is talking to.
class ConnectButton extends StatelessWidget {
  const ConnectButton({
    super.key,
    required this.profile,
    this.unavailableReason,
  });

  /// Null when there is nothing to connect with. [unavailableReason] then says
  /// why, because a permanently greyed button with no explanation is the same
  /// as a broken one.
  final TunnelProfile? profile;
  final String? unavailableReason;

  @override
  Widget build(BuildContext context) {
    final TunnelModel tunnel = context.watch<TunnelModel>();
    final TunnelProfile? target = profile;

    if (target == null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          const FilledButton(onPressed: null, child: Text('Connect')),
          if (unavailableReason != null) ...<Widget>[
            const SizedBox(height: 8),
            Text(unavailableReason!, style: Theme.of(context).textTheme.bodySmall),
          ],
        ],
      );
    }

    final TunnelStatus status = tunnel.status;
    final bool mine = status.profileId == target.id;
    final bool busy = mine && status.isBusy;
    final bool up = mine && status.isUp;
    final bool failed = mine && status.stage == TunnelStage.failed;
    // Another tunnel is up. Said out loud rather than silently offering
    // Connect: on every platform this app targets, bringing a second tunnel up
    // takes the first one down, and somebody should know that before tapping.
    final bool elsewhere = !mine && status.isUp;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Row(
          children: <Widget>[
            if (up)
              FilledButton.tonalIcon(
                onPressed: () => unawaited(tunnel.disconnect()),
                icon: const Icon(Icons.link_off, size: 18),
                label: const Text('Disconnect'),
              )
            else
              FilledButton.icon(
                onPressed:
                    busy ? null : () => unawaited(tunnel.connect(target)),
                icon: busy
                    ? const InlineSpinner()
                    : Icon(failed ? Icons.refresh : Icons.link, size: 18),
                label: Text(
                  busy
                      ? 'Connecting'
                      : failed
                          ? 'Try again'
                          : 'Connect',
                ),
              ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                _stateLine(status, mine: mine, elsewhere: elsewhere),
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ],
        ),
        if (failed && status.message != null) ...<Widget>[
          const SizedBox(height: 12),
          // Verbatim. This string is the whole diagnosis: which platform, and
          // which artifact is missing.
          FailureText(status.message!),
        ],
      ],
    );
  }

  String _stateLine(
    TunnelStatus status, {
    required bool mine,
    required bool elsewhere,
  }) {
    if (elsewhere) {
      return 'Another server is connected. Connecting here takes that one down.';
    }
    if (!mine) {
      return 'Not connected.';
    }
    switch (status.stage) {
      case TunnelStage.disconnected:
        return 'Not connected.';
      case TunnelStage.connecting:
        return 'Bringing the tunnel up.';
      case TunnelStage.connected:
        return 'Connected. Traffic is going through this server.';
      case TunnelStage.failed:
        return 'The tunnel did not come up.';
    }
  }
}
