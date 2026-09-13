/// Everything the provisioning sequence needs to know about one target.
class ProvisionConfig {
  const ProvisionConfig({
    required this.host,
    this.sshPort = 22,
    this.repoUrl = 'https://github.com/aSel1x/vpn-stack.git',
    this.repoRef = 'main',
    this.repoPath = '/opt/vpn-stack',
    this.hostScript = 'scripts/provision-host.sh',
    this.stateDir = '/etc/vpn-stack',
    this.vpnctl = '/usr/local/bin/vpnctl',
    this.deadmanSeconds = 180,
    this.deadmanPidFile = '/run/vpn-stack.deadman',
    this.proveTimeout = const Duration(seconds: 20),
    this.proveAttempts = 3,
    this.proveGap = const Duration(seconds: 2),
    this.readinessTimeout = const Duration(minutes: 8),
    this.pollInterval = const Duration(seconds: 2),
  });

  /// The address clients will connect to, written into `VPN_SERVER_HOST`.
  /// install.sh derives it from the ssh target; here it is explicit, because a
  /// server reached through a jump host or a tunnel is not reached at the
  /// address its profiles have to carry.
  final String host;

  /// The port *we* reach sshd on, and therefore the one the firewall step opens.
  /// install.sh hardcodes 22; allowing 22 on a box whose sshd listens on 2222
  /// is precisely the lockout the deadman exists to survive.
  final int sshPort;

  /// The repository is public, so the server clones it with no credential and
  /// the app ships no copy of the tree.
  final String repoUrl;
  final String repoRef;
  final String repoPath;

  /// The server-local half, as a script in the checkout, repo-relative.
  ///
  /// Two stages, called separately: `base <host>` (docker, apt packages, uv,
  /// /etc/vpn-stack, sysctls, /dev/ppp, the boot unit) and `code <repo-path>`
  /// (uv sync, the vpnctl shim, the keyring). The firewall proof runs between
  /// them, which is the whole reason it is two.
  ///
  /// A path rather than a copy of that shell in Dart -- two definitions of how
  /// a host is prepared drift, and the drift only shows up on a fresh box.
  final String hostScript;

  final String stateDir;
  final String vpnctl;

  /// How long the deadman waits before disabling ufw unconditionally.
  final int deadmanSeconds;
  final String deadmanPidFile;

  /// A locked-out server DROPs rather than rejects, so the prover hangs instead
  /// of failing. Without a timeout the step waits forever while the deadman
  /// quietly fires behind it and the UI shows nothing.
  final Duration proveTimeout;

  /// More than one attempt because the cost is asymmetric: a false failure
  /// costs a re-run, while a false success disarms the safety net on a box that
  /// can no longer be reached.
  final int proveAttempts;
  final Duration proveGap;

  /// `vpnctl apply` already waits for ports, but it *warns* and returns ok when
  /// they never bind, and its ceiling is 240s. The first ipsec run also builds
  /// the NSS database and issues the CA on whatever small VPS this is, so the
  /// app waits again, longer, and fails instead of warning.
  final Duration readinessTimeout;
  final Duration pollInterval;

  String get hostScriptPath => '$repoPath/$hostScript';
}
