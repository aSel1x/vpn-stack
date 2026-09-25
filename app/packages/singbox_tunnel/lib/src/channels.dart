// The wire between Dart and the platform side, in one place.
//
// One pair of names for Android and iOS: the contract is the same on both, and
// so is the controller above it. All three sides restate these strings; they are
// here so a rename is one edit and a grep, not a silent no-op on a channel
// nobody is listening to.

/// Commands: `prepare`, `requestPermission`, `start`, `stop`, `status`.
const String commandChannelName = 'io.github.asel1x/singbox_tunnel/commands';

/// Status events, one map per change. Replayed on listen by the platform side
/// as well as by BaseTunnelController, because a screen built while the tunnel
/// is already up must not render as disconnected.
const String statusChannelName = 'io.github.asel1x/singbox_tunnel/status';

/// The `stage` values the platform may send. Anything else is a failure, not a
/// neutral state: a status this build cannot read is a status it cannot claim
/// is connected.
const String stageDisconnected = 'disconnected';
const String stageConnecting = 'connecting';
const String stageConnected = 'connected';
const String stageFailed = 'failed';
