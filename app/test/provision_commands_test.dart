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

    test('the clone refuses a ref that does not contain it', () {
      // `main` did not contain it -- provision-host.sh is a pure addition -- so
      // a provision against a branch cloned perfectly and then died on the host
      // stage at exit 127, on a box whose apt and git had already been touched.
      // The clone is where that is knowable, so the clone is where it is said.
      final String program = cloneRepoCommand(plain).text;
      expect(program, contains(r'[ -f "$repo/$script" ]'));
      expect(program, contains(r'ref $ref has none'));
      expect(program, contains(r'containing $script'));
      // Both halves have to be IN the message, not merely in the program: the
      // sentence a person reads has to name which ref and which file.
      expect(program, contains('script=scripts/provision-host.sh'));
      expect(program, contains('ref=v0.2.0'));
    });
  });

  group('the ref the app provisions from', () {
    test('is a tag, not a branch', () {
      // A branch means an app-provisioned server executes whatever was on it at
      // that instant, unpinned and unsigned -- CLAUDE.md says so in as many
      // words. A tag makes it a reviewed tree, and bumping this constant is how
      // the app adopts a new one.
      expect(plain.repoRef, 'v0.2.0');
      expect(plain.repoRef, isNot('main'));
      expect(cloneRepoCommand(plain).text, contains('ref=v0.2.0'));
    });
  });

  group('every vpnctl invocation takes the lock', () {
    // app/README.md: "a call that skips the lock is a bug even on the run where
    // it works". vpnctl holds no lock of its own, so this is the whole of the
    // multi-operator story, and provisioning ran three calls outside it while
    // control/vpnctl.dart put every one of its own inside.
    List<RemoteProgram> vpnctlPrograms() => <RemoteProgram>[
          vpnctlReadyCommand(plain),
          applyCommand(plain),
        ];

    test('under the same lock at the same path', () {
      for (final RemoteProgram program in vpnctlPrograms()) {
        expect(program.text, contains('/run/vpn-stack.lock'), reason: program.text);
        expect(
          program.text,
          contains('flock -w 300 -E 75 /run/vpn-stack.lock'),
          reason: program.text,
        );
      }
    });

    test('bounded, and with a status vpnctl itself cannot produce', () {
      // `./vpn` blocks for ever; a phone with nothing on screen is
      // indistinguishable from a crash. EX_TEMPFAIL is what makes "somebody
      // else is mid-apply" different from 1 (a refusal), 2 (argparse or the
      // guard) and 127 (a missing shim).
      for (final RemoteProgram program in vpnctlPrograms()) {
        expect(program.text, contains('-w 300'), reason: program.text);
        expect(program.text, contains('-E 75'), reason: program.text);
      }
    });

    test('carrying the handshake for the day vpnctl locks itself', () {
      // install.sh and deploy.sh already set it. flock(1) inside flock(1) on
      // the same path from a child process opens a second file description and
      // blocks for ever, and an outer `-w` does not bound a child's wait -- so
      // the call site that omits this is the one that deadlocks that day.
      for (final RemoteProgram program in vpnctlPrograms()) {
        expect(program.text, contains('VPN_STACK_LOCK_HELD=1'),
            reason: program.text);
      }
    });

    test('and provision-host.sh is NOT wrapped, because it locks internally', () {
      // Its `code` stage runs `flock /run/vpn-stack.lock vpnctl bootstrap`
      // itself. An outer flock on the same path would hang this on a healthy
      // box, which is the deadlock the handshake above exists for.
      expect(hostBaseCommand(plain).text, isNot(contains('flock')));
      expect(hostCodeCommand(plain).text, isNot(contains('flock')));
    });
  });

  group('the deadman', () {
    test('reaps a predecessor rather than writing over its pid', () {
      // The failing proof leaves its deadman armed on purpose and says to wait
      // and retry. Somebody who retries inside the timeout arrives with an
      // earlier timer still sleeping and its pid still in the file: run A armed
      // 100, run B writes 200 over it, and whichever the disarm reads, the other
      // wakes at its own T+180 and disables ufw -- possibly after this reported
      // success. Measured against dash with a stubbed ufw: without the reap the
      // first timer is still sleeping after the disarm.
      final String program = armDeadmanCommand(plain).text;
      expect(program, contains(r'kill -0 -"$old"'));
      expect(program, contains(r'rm -f "$pidfile"'));
      // Clearing the file also closes a read race: the wait loop only tests that
      // it is non-empty, so a stale pid in it satisfies the loop and `armed=`
      // would report the old timer instead of the new one.
      expect(
        program.indexOf(r'rm -f "$pidfile"'),
        lessThan(program.indexOf('setsid')),
      );
      // Refused rather than signalled: a pid the previous run left behind may
      // have been recycled, and this step is about to change the firewall on the
      // box it would be signalling into.
      expect(program, contains('still armed (process group'));
      expect(program, isNot(contains(r'kill -TERM')));
    });

    test('says nothing a shell would expand in its own message', () {
      // The refusal text goes through `echo "..."`, where backticks and $(...)
      // run on the server -- and it names a pid, so it is built by
      // interpolation. Nothing in it may be syntax.
      final String program = armDeadmanCommand(plain).text;
      final RegExp echoed = RegExp(r'echo "([^"]*)" >&2');
      for (final RegExpMatch m in echoed.allMatches(program)) {
        expect(m.group(1), isNot(contains('`')), reason: m.group(1));
        expect(m.group(1), isNot(contains(r'$(')), reason: m.group(1));
      }
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
      hostScript: 'scripts/provision host.sh',
      stateDir: '/etc/vpn stack',
      vpnctl: '/usr/local/bin/vpn ctl',
      lockPath: '/run/vpn stack.lock',
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
        nasty.hostScript,
        nasty.stateDir,
        nasty.vpnctl,
        nasty.lockPath,
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
