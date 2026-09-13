// The programs themselves: what is in them, and what a value put into one can
// and cannot do.
//
// Two separate jobs here, and both exist because of a bug that shipped.
//
// The first is quoting. `@HOST@` comes from the "Host or IP" field, which is
// validated for non-emptiness and a port range and nothing else, and it used to
// be substituted into `bash "@SCRIPT@" "@HOST@" "@PATH@"` by a raw replaceAll.
// A double quote broke out of the argument and ran commands; a `$` did the
// quieter and worse thing, expanding on the server so that VPN_SERVER_HOST in
// /etc/vpn-stack/.env held the wrong address and every VLESS and Hysteria2 URI
// issued afterwards carried it, with nothing anywhere saying so.
//
// The second is that the layer calls a script it does not own. The fake answers
// `provision-host.sh` with `ok`, which is exactly as true as the script being
// there -- and it was not there. So one test reads the repository instead of
// the fake.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/shell.dart';
import 'package:vpn_stack_app/provision/commands.dart';
import 'package:vpn_stack_app/provision/config.dart';

const ProvisionConfig plain = ProvisionConfig(host: '203.0.113.7');

/// Values that mean something to a shell. None of them contains a quote
/// character, so `shellQuote` wraps each one whole and the assertions below can
/// talk about where that wrapped form appears.
const List<String> shellish = <String>[
  r'vpn.$HOSTNAME.example',
  'a`whoami`b',
  'host with space',
  'x; touch /tmp/pwned',
  'y && id',
  r'$(id -u)',
];

/// The repository root, found rather than assumed.
///
/// `flutter test` runs with the package directory as its working directory, but
/// nothing here should depend on how many levels up the root is.
Directory repoRoot() {
  Directory dir = Directory.current;
  for (int i = 0; i < 6; i++) {
    if (Directory('${dir.path}/scripts').existsSync() &&
        Directory('${dir.path}/vpnctl').existsSync()) {
      return dir;
    }
    dir = dir.parent;
  }
  throw StateError(
    'could not find the repository root above ${Directory.current.path}',
  );
}

void main() {
  group('the script the app calls', () {
    // This is the assertion the suite did not have. Every provisioning test was
    // green while `scripts/provision-host.sh` did not exist, because the fake
    // answers anything containing that name with `ok` -- so the one thing the
    // app cannot check for itself (does the other half exist?) was the one
    // thing the fake was asserting for it.
    test('exists in this repository', () {
      final File script = File('${repoRoot().path}/${plain.hostScript}');
      expect(
        script.existsSync(),
        isTrue,
        reason: '${plain.hostScript} is what the host step runs on the server, '
            'out of the checkout the clone step makes. A provisioning run '
            'against a tree without it fails on the host step with exit 127.',
      );
      expect(script.lengthSync(), greaterThan(0));
    });

    test('is named from the checkout it is cloned into', () {
      expect(plain.hostScriptPath, '${plain.repoPath}/${plain.hostScript}');
      expect(
        hostBaseCommand(plain).text,
        contains('/opt/vpn-stack/scripts/provision-host.sh'),
      );
    });

    test('is called with the two stages it actually defines', () {
      // The path existing is half the seam; the arguments are the other half.
      // The script takes `base <host>` and `code <repo-path>` -- handed its
      // host and path positionally it answers "unknown stage" and exits 2, and
      // the fake would still say `ok`.
      expect(hostBaseCommand(plain).text, contains('\nstage=base\n'));
      expect(hostBaseCommand(plain).text, contains('\narg=203.0.113.7\n'));
      expect(hostCodeCommand(plain).text, contains('\nstage=code\n'));
      expect(hostCodeCommand(plain).text, contains('\narg=/opt/vpn-stack\n'));
      expect(hostBaseCommand(plain).text, contains(r'bash "$script" "$stage" "$arg"'));

      final String script =
          File('${repoRoot().path}/${plain.hostScript}').readAsStringSync();
      for (final String stage in <String>['base', 'code']) {
        expect(
          script,
          contains('provision-host.sh $stage '),
          reason: 'the app calls `provision-host.sh $stage`, and that stage has '
              'to be one the script documents and accepts. If the stage names '
              'changed, this side has to change with them -- an unknown stage '
              'exits 2 and the provisioning run stops on the host step.',
        );
      }
    });

    test('is checked for on the server too, so a stale tree says which file', () {
      // Same reason, one layer down: a checkout that predates the script has to
      // fail here, naming it, rather than two steps later on a missing vpnctl.
      expect(hostBaseCommand(plain).text, contains(r'[ -f "$script" ]'));
      expect(hostBaseCommand(plain).text, contains('exit 127'));
    });
  });

  group('values that mean something to a shell', () {
    test('a host with a double quote cannot break out of the command', () {
      const String host = r'1.2.3.4"; touch /tmp/pwned; echo "';
      final String program =
          hostBaseCommand(const ProvisionConfig(host: host)).text;

      // One assignment, single-quoted, and the script gets "$arg": whatever is
      // in there is one word and nothing in it is ever re-read as syntax.
      expect(program, contains("arg='" r'1.2.3.4"; touch /tmp/pwned; echo "' "'"));
      expect(program, contains(r'bash "$script" "$stage" "$arg"'));
      // The shape of the old bug, written the way the old template produced
      // it (Dart interpolation of the hostile value, not a shell variable).
      expect(program, isNot(contains('"$host"')));
    });

    test(r'a $ in the host reaches provision-host.sh unexpanded', () {
      // The second-order failure, and the one that would actually have bitten.
      // provision-host.sh writes this into VPN_SERVER_HOST, which every share
      // link is built from: expanded away on the server, the profiles point
      // somewhere else and the server looks perfectly healthy.
      const String host = r'vpn.$HOSTNAME.example';
      final String program =
          hostBaseCommand(const ProvisionConfig(host: host)).text;

      expect(program, contains("arg='" r'vpn.$HOSTNAME.example' "'"));
    });

    test('a host that is a shell expression is still one word', () {
      for (final String host in shellish) {
        final String program =
            hostBaseCommand(ProvisionConfig(host: host)).text;
        expect(program, contains('\narg=${shellQuote(host)}\n'), reason: host);
      }
    });
  });

  group('every program the layer sends', () {
    // One config, every value hostile, every builder. A template that grows a
    // `"@THING@"` fails here rather than on somebody's server.
    const ProvisionConfig nasty = ProvisionConfig(
      host: r'vpn.$HOSTNAME.example',
      repoPath: '/opt/vpn stack',
      repoUrl: r'https://example.invalid/$USER/repo.git',
      repoRef: 'branch with space',
      stateDir: '/etc/vpn stack',
      vpnctl: '/usr/local/bin/vpn ctl',
      deadmanPidFile: '/run/vpn stack.deadman',
    );

    List<RemoteProgram> everyProgram() => <RemoteProgram>[
          osReleaseCommand,
          whoamiCommand,
          provisionedProbeCommand(nasty),
          dockerPresentCommand,
          dockerVersionCommand,
          dockerComposeCommand,
          installDockerCommand(),
          cloneRepoCommand(nasty),
          hostBaseCommand(nasty),
          hostCodeCommand(nasty),
          vpnctlReadyCommand(nasty),
          applyCommand(nasty),
          protocolListCommand(nasty),
          smokeCommand(nasty),
          armDeadmanCommand(nasty),
          enableUfwCommand(nasty),
          disarmDeadmanCommand(nasty),
          portsBoundCommand(<String>['10443/tcp', '20443/udp']),
        ];

    test('never splices a value inside quotes', () {
      final List<String> values = <String>[
        nasty.host,
        nasty.repoPath,
        nasty.repoUrl,
        nasty.repoRef,
        nasty.stateDir,
        nasty.vpnctl,
        nasty.deadmanPidFile,
      ];
      for (final RemoteProgram program in everyProgram()) {
        for (final String value in values) {
          final String quoted = shellQuote(value);
          // A quoted word does not nest. Inside `"..."` the single quotes are
          // literal and the `$` expands anyway; inside `sh -c '...'` it ends
          // the body. So a filled placeholder must stand alone as a word.
          expect(program.text, isNot(contains('"$quoted')), reason: program.text);
          expect(program.text, isNot(contains('$quoted"')), reason: program.text);
        }
      }
    });

    test('leaves no placeholder behind', () {
      for (final RemoteProgram program in everyProgram()) {
        expect(program.text, isNot(matches(RegExp(r'@[A-Z0-9_]+@'))));
        expect(program.text.trim(), isNotEmpty);
      }
    });

    test('quotes each port spec on its own, so the loop still splits', () {
      // The one placeholder that is deliberately several words: quoting the
      // joined string would hand `for spec in` a single item called
      // "10443/tcp 20443/udp".
      final String program =
          portsBoundCommand(<String>['10443/tcp', '20443/udp']).text;
      expect(program, contains('for spec in 10443/tcp 20443/udp; do'));
    });
  });
}
