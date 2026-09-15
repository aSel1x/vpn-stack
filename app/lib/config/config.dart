/// Turning a share URI into a sing-box client configuration.
///
/// The server hands out URIs; no tunnel engine imports one. sing-box's core
/// has no URI parser -- every GUI client writes its own -- so somebody has to
/// do it, and it is the same job on five platforms. Doing it once, in Dart,
/// is why this layer exists.
///
/// Everything here is pure: no `dart:io`, no platform channel, no clock. The
/// output is a `Map<String, Object?>` that `jsonEncode` turns into the bytes
/// an engine is started with.
library;

export 'errors.dart';
export 'hysteria2.dart';
export 'outbound.dart';
export 'parse.dart';
export 'share_uri.dart';
export 'singbox_config.dart';
export 'vless_reality.dart';
