// The one route from a server profile to an open SSH connection.
//
// Before this existed the UI reached a connection five different ways --
// `_addOnly`, `openServer`, the provisioning screen, the detail screen's
// session, and every vpnctl call underneath it -- and not one of them carried a
// host key policy. dartssh2 accepts ANY host key unless it is told not to, so
// the default outcome was a root password handed to whatever answered on port
// 22.
//
// So: the connector and the policy are created together, in one place, and
// neither is reachable afterwards. Callers get `open`, `provisioner` and the
// profile -- never the connector. There is no constructor that takes a
// connector without a policy and no getter that hands one back, so a sixth
// call path cannot be written without deleting code here on purpose, which is
// the point.

import '../provision/config.dart';
import '../provision/provisioner.dart';
import '../provision/ssh.dart';
import 'ports.dart';

/// One server, one credential, one host key policy, and the only two ways to
/// use them.
class ServerAccess {
  ServerAccess._({
    required this.server,
    required SshConnector connector,
    required HostKeyPolicy hostKeys,
  })  : _connector = connector,
        _hostKeys = hostKeys;

  /// The only way to build one: a credential, the pin this device already
  /// holds (null the first time), and somebody to ask when there is no pin.
  ///
  /// [prompt] must put the question in front of a human. A prompt that answers
  /// by itself is `StrictHostKeyChecking=no` wearing a callback, and the
  /// wrapper below is the guard against the other half of that mistake: a
  /// CHANGED key is never accepted here no matter what the prompt returns.
  factory ServerAccess.trustOnFirstUse({
    required SshTransport transport,
    required ServerProfile server,
    required SshCredential credential,
    required HostKeyPrompt prompt,
    required HostKeyRecorder remember,
  }) {
    return ServerAccess._(
      server: server,
      connector: transport.connectorFor(server, credential),
      hostKeys: HostKeyPolicy.ask(
        target: server.sshTarget,
        pinned: server.hostKey,
        prompt: (HostKeyQuestion question) => _answer(prompt, question),
        remember: remember,
      ),
    );
  }

  /// The profile this access was built for, including the pin it was built
  /// with. Screens read the label and the host off it.
  final ServerProfile server;

  final SshConnector _connector;

  /// One policy for the whole object, so the answer given to the primary
  /// connection is the answer the firewall step's prover gets too. A policy per
  /// connection would ask twice in one run, and the second question is the one
  /// people learn to tap through.
  final HostKeyPolicy _hostKeys;

  /// A connection whose host key somebody approved, and no other kind.
  ///
  /// [openVerified] is what re-checks the key the transport actually settled on
  /// against the policy, because a connector that ignores the policy has
  /// already sent the credential and a doc comment cannot stop it.
  Future<SshConnection> open() => openVerified(_connector, _hostKeys);

  /// The provisioning runner, wired to this same connector and this same
  /// policy.
  ///
  /// Built here rather than by the caller so the connector never leaves this
  /// object: `Provisioner` takes both halves, and handing them out separately
  /// is the shape that let a `connect()` with no policy exist in the first
  /// place. Every connection it opens goes through `ProvisionContext.openPrimary`
  /// and `runFirewallStep`, both of which call [openVerified].
  Provisioner provisioner() => Provisioner(
        config: ProvisionConfig(host: server.host, sshPort: server.sshPort),
        connector: _connector,
        hostKeys: _hostKeys,
      );
}

/// Asks, and then refuses anyway when the key changed.
///
/// The policy has no notion of "changed" -- it asks the same way whether the
/// pin is null or different -- so this is where the two questions stop being
/// the same question. A changed host key on a box holding VPN credentials is
/// either a rebuild or somebody in the middle, and "accept and continue" must
/// not be one tap away from the second. The prompt is still called, because the
/// person is entitled to read the explanation; its answer is not.
Future<HostKeyDecision> _answer(
  HostKeyPrompt ask,
  HostKeyQuestion question,
) async {
  final HostKeyDecision decision = await ask(question);
  if (question.changed) {
    return HostKeyDecision.refuse;
  }
  return decision;
}
