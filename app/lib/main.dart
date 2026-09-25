import 'dart:io';

import 'package:flutter/material.dart';
import 'package:singbox_tunnel/singbox_tunnel.dart';

import 'config/config.dart';
import 'package:provider/provider.dart';

import 'transport/dartssh2_transport.dart';
import 'tunnel/unimplemented_tunnel.dart';
import 'ui/app.dart';
import 'ui/file_saver.dart';
import 'ui/models.dart';
import 'ui/ports.dart';
import 'ui/server_store.dart';

/// The composition root, and the only file that names an implementation.
///
/// Every screen below here depends on the interfaces in `ui/ports.dart` and on
/// `TunnelController`, never on a concrete class. That is what makes each of
/// them swappable: a second tunnel engine, or an SSH library that is not
/// dartssh2, is a change to the three lines below and to nothing else.
void main() {
  WidgetsFlutterBinding.ensureInitialized();

  final ServerStore store = SecureServerStore();

  // Android and iOS. The two share the Dart contract and nothing else: Android
  // runs sing-box in the app process behind a VpnService, iOS runs it in a
  // separate packet-tunnel extension the app starts through
  // NETunnelProviderManager, against the target committed in app/ios/. Both
  // refuse to report connected without evidence a tun exists.
  //
  // What an iOS BUILD still needs is a signature, and no line here can supply
  // it: a Network Extension entitlement requires a paid Apple membership, and
  // App Store Review Guideline 5.4 admits VPN apps only from a developer
  // enrolled as an organization. CI produces an unsigned .ipa that installs
  // nowhere. That gates shipping, not wiring -- an unwired platform would fail
  // per connect attempt instead of once, at the build.
  //
  // Everywhere else this is the stub, which reports failure naming the platform
  // and the missing artifact and never reports connected. macOS, Windows and
  // Linux each need a privileged process to open a TUN device, which is not a
  // plugin. A stub that showed "Connected" would be indistinguishable from a
  // working app, and somebody would route their traffic through it believing
  // that.
  //
  // The builder is where the two halves meet: singbox_tunnel deliberately does
  // not know the configuration format -- importing lib/config/ from the package
  // would be the app -> package -> app cycle -- so the app supplies it, and
  // lib/config/ stays the single definition of what a share URI becomes.
  final TunnelController tunnel = Platform.isAndroid || Platform.isIOS
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
        // decides the policy; honouring it is `transport/`'s half, and
        // `openVerified` re-checks the key the transport settled on rather than
        // trusting it to have obeyed.
        //
        // `MissingSshTransport` stays in the tree as the honest fallback for a
        // platform where this one cannot run, and nothing wires it.
        Provider<SshTransport>.value(value: const Dartssh2Transport()),
        // Only where a file can actually leave the device. share_plus shares
        // files on Android, iOS, macOS and Windows 10 1803+; on Linux its own
        // implementation throws for a file share, so Linux gets no saver and
        // ShareItemView draws no Share button at all. A saver that threw would
        // instead put a button on every IKEv2 bundle and fail on press, and
        // those three bundles are the entire reason IKEv2 is in this stack.
        if (!Platform.isLinux)
          Provider<FileSaver>.value(value: const ShareSheetFileSaver()),
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
