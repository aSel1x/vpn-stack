import 'dart:io';

import 'package:flutter/material.dart';
import 'package:singbox_tunnel/singbox_tunnel.dart';

import 'config/config.dart';
import 'package:provider/provider.dart';

import 'transport/dartssh2_transport.dart';
import 'tunnel/unimplemented_tunnel.dart';
import 'ui/app.dart';
import 'ui/missing_backend.dart';
import 'ui/models.dart';
import 'ui/ports.dart';
import 'ui/server_store.dart';

/// The composition root, and the only file that names an implementation.
///
/// Every screen below here depends on the interfaces in `ui/ports.dart` and on
/// `TunnelController`, never on a concrete class. That is what makes the
/// placeholders swappable: when `lib/control/` and `lib/provision/` grow the
/// objects the UI calls, and when a real tunnel engine exists, the change is
/// three lines here and nothing else.
void main() {
  WidgetsFlutterBinding.ensureInitialized();

  final ServerStore store = SecureServerStore();

  // The engine. Android only for now: singbox_tunnel implements VpnService and
  // libbox, and there is no iOS or desktop half yet -- iOS needs
  // Libbox.xcframework and each desktop needs a privileged helper, because a TUN
  // device is not something an unprivileged process opens.
  //
  // Everywhere else this stays the stub, which reports failure naming the
  // platform and the missing artifact and never reports connected. A stub that
  // showed "Connected" would be indistinguishable from a working app, and
  // somebody would route their traffic through it believing that.
  //
  // The builder is where the two halves meet: singbox_tunnel deliberately does
  // not know the configuration format -- importing lib/config/ from the package
  // would be the app -> package -> app cycle -- so the app supplies it, and
  // lib/config/ stays the single definition of what a share URI becomes.
  final TunnelController tunnel = Platform.isAndroid
      ? SingboxTunnel((TunnelProfile profile) => encodeSingBoxConfig(
            buildSingBoxConfig(
              outbound: selectOutbound(
                profile.importUris,
                // Never silently accept any certificate. The config layer
                // refuses to pick this for the caller, and the caller is here.
                // Since share() started publishing `spki`, a current Hysteria2
                // link is pinned by public key and this argument does not come
                // into it; a link issued before that will fail the handshake,
                // which is the honest outcome. The alternative -- anyCertificate
                // -- turns "this certificate" into "some TLS", and an app that
                // does that quietly is worse than one that fails loudly.
                hysteria2Trust: Hysteria2Trust.systemRoots,
              ),
            ),
          ))
      : UnimplementedTunnel();

  runApp(
    MultiProvider(
      // No explicit element type: SingleChildWidget reaches provider.dart
      // through a re-export, and inference does not need it named.
      providers: [
        // SSH itself. control/ and provision/ are complete and take their
        // transport injected, so this one object is what stands between this
        // app and a real server.
        //
        // It carries one obligation that is not optional:
        // `SshConnector.connect` is handed a HostKeyPolicy and applies it
        // during the key exchange, before authentication -- dartssh2 accepts
        // any host key when `onVerifyHostKey` is not supplied, and this app
        // asks for a root password on its second screen. `ui/access.dart`
        // decides the policy; honouring it is `transport/`'s half.
        //
        // `MissingSshTransport` stays in the tree as the honest fallback for a
        // platform where this one cannot run, and nothing wires it.
        Provider<SshTransport>.value(value: const Dartssh2Transport()),
        Provider<FileSaver>.value(value: const MissingFileSaver()),
        ChangeNotifierProvider<ServersModel>(
          create: (_) => ServersModel(store)..load(),
        ),
        ChangeNotifierProvider<CredentialVault>(
          create: (_) => CredentialVault(),
        ),
        ChangeNotifierProvider<TunnelModel>(
          create: (_) => TunnelModel(tunnel),
        ),
      ],
      child: const VpnStackApp(),
    ),
  );
}
