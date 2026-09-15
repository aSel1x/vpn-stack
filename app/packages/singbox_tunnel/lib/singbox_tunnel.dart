/// sing-box on Android, behind the app's tunnel interface.
///
/// One import for the composition root:
///
/// ```dart
/// import 'package:singbox_tunnel/singbox_tunnel.dart';
///
/// final TunnelController tunnel = SingboxTunnel(buildConfigForProfile);
/// ```
///
/// The interface is re-exported from here because it lives in this package now
/// -- see the header of `tunnel_api.dart` for why it had to move rather than be
/// depended upon.
library;

export 'src/singbox_tunnel.dart' show SingBoxConfigBuilder, SingboxTunnel;
export 'tunnel_api.dart';
