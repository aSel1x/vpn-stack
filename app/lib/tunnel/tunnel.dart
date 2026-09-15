// The tunnel interface, which now lives in the package that implements it.
//
// It had to move. `singbox_tunnel` cannot depend on the app -- app ->
// singbox_tunnel -> app is a cycle pub refuses -- and Dart has no structural
// typing, so a class can only implement a type it can import. While this file
// held its own copy, `SingboxTunnel` satisfied a DIFFERENT `TunnelController`
// and the analyzer rejected it: two definitions of one interface, and 1,800
// lines of plugin wired to no call site while every test stayed green.
//
// Kept as a re-export rather than deleted so `import 'tunnel.dart'` keeps
// working from the screens and from unimplemented_tunnel.dart.
export 'package:singbox_tunnel/tunnel_api.dart';
