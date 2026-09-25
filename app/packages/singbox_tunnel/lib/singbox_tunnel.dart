/// sing-box on Android and iOS, behind the app's tunnel interface.
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

// Exported because it is a parameter of SingboxTunnel's constructor: the
// wording of a failure is per-platform (see platform_text.dart) and the
// default is read from defaultTargetPlatform, which a test cannot move. A
// type a caller cannot name is a parameter a caller cannot pass.
export 'src/platform_text.dart' show TunnelPlatformText;
export 'src/singbox_tunnel.dart' show SingBoxConfigBuilder, SingboxTunnel;
export 'tunnel_api.dart';
