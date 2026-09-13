/// The app's view of one server: `vpnctl … --json` over an injected SSH
/// session, and the typed answers it gives back.
///
/// `json.dart` is deliberately NOT re-exported. Its readers are named for what
/// they read (`readString`, `readBool`) and belong to whoever is writing a
/// model; pulling them into every importer's top-level scope is how a UI file
/// ends up with three `readString`s and no idea which one it called.
library;

export 'errors.dart';
export 'models.dart';
export 'shell.dart';
export 'ssh_session.dart';
export 'vpnctl.dart';
