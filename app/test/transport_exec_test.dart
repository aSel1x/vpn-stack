// The half of the SSH transport that can be checked without a server.
//
// A real key exchange cannot be tested here and is not faked: a fake thorough
// enough to answer a handshake would only be asserting itself. What is testable
// is everything the transport decides on its own -- how an argv becomes the one
// string SSH carries, how two streams and an exit status become a
// CommandResult, what a deadline says when it fires, and that closing twice
// closes once.

import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/ssh_session.dart';
import 'package:vpn_stack_app/transport/errors.dart';
import 'package:vpn_stack_app/transport/exec.dart';

const String target = 'root@203.0.113.7:22';

void main() {
  group('sshExecLine', () {
    test('quotes every element, because SSH carries one string', () {
      // The failure this is about: `./vpn` shipped the unquoted version and a
      // name with a space became two arguments, which misaligns the
      // space-separated IKEv2 user and password lists one layer down.
      expect(
        sshExecLine(<String>['vpnctl', '--json', 'user', 'add', 'two words']),
        "vpnctl --json user add 'two words'",
      );
    });

    test('an sh -c program survives as a single argument', () {
      final String line = sshExecLine(<String>[
        'sh',
        '-c',
        "set -eu\necho 'hi there'\n",
      ]);
      expect(line, startsWith('sh -c '));
      // One quoted word after `sh -c`: a program that arrived as three
      // arguments would run `set` and nothing else.
      expect(line, contains(r"'set -eu"));
      expect(line, contains(r"echo '\''hi there'\''"));
    });
  });

  group('sshCommandResult', () {
    test('keeps the streams apart', () {
      // stdout is the `--json` payload and stderr is everything vpnctl says to
      // a human. One byte of stderr merged in and the parse fails on a server
      // that did nothing wrong.
      final CommandResult result = sshCommandResult(
        exitCode: 0,
        stdout: utf8.encode('{"schema":1,"ok":true}'),
        stderr: utf8.encode('note: rendered-1 promoted\n'),
        target: target,
      );
      expect(result.stdout, '{"schema":1,"ok":true}');
      expect(result.stderr, 'note: rendered-1 promoted\n');
      expect(result.stdout, isNot(contains('note:')));
      expect(result.exitCode, 0);
    });

    test('a non-zero exit is a result, not an exception', () {
      // vpnctl exits 1 with a JSON body of its own, and the caller is entitled
      // to read it.
      final CommandResult result = sshCommandResult(
        exitCode: 1,
        stdout: utf8.encode('{"schema":1,"ok":false,"error":"no such user"}'),
        stderr: <int>[],
        target: target,
      );
      expect(result.exitCode, 1);
      expect(result.stdout, contains('no such user'));
    });

    test('undecodable output does not become a decode failure', () {
      // A truncated base64 bundle must not replace the reason a command failed
      // with a complaint about its own bytes.
      final CommandResult result = sshCommandResult(
        exitCode: 0,
        stdout: <int>[0xff, 0xfe, 0x41],
        stderr: <int>[],
        target: target,
      );
      expect(result.stdout, endsWith('A'));
    });

    test('no exit status is a failure, never an invented zero', () {
      expect(
        () => sshCommandResult(
          exitCode: null,
          stdout: <int>[],
          stderr: <int>[],
          target: target,
          signalName: 'KILL',
        ),
        throwsA(
          isA<SshNoExitStatus>().having(
            (SshNoExitStatus e) => e.message,
            'message',
            allOf(contains('SIGKILL'), contains(target)),
          ),
        ),
      );
    });
  });

  group('sshCommandSummary', () {
    test('one line, short enough for a phone', () {
      const String program = 'set -eu\nufw allow 22/tcp\nufw --force enable\n';
      expect(sshCommandSummary(program), 'set -eu');
      expect(sshCommandSummary('x' * 200), hasLength(93));
      expect(sshCommandSummary('x' * 200), endsWith('...'));
    });
  });

  group('withSshDeadline', () {
    test('says which phase ran out', () async {
      // "The connection failed" does not distinguish an unreachable box from a
      // slow one from a command still running, and a spinner that never ends is
      // indistinguishable from a crash.
      final Completer<void> never = Completer<void>();
      await expectLater(
        withSshDeadline(
          never.future,
          limit: const Duration(milliseconds: 10),
          phase: 'the TCP connection',
          target: target,
        ),
        throwsA(
          isA<SshDeadlineExceeded>().having(
            (SshDeadlineExceeded e) => e.message,
            'message',
            allOf(contains('the TCP connection'), contains(target)),
          ),
        ),
      );
    });

    test('a fast answer passes straight through', () async {
      final String value = await withSshDeadline(
        Future<String>.value('ok'),
        limit: const Duration(seconds: 30),
        phase: 'the TCP connection',
        target: target,
      );
      expect(value, 'ok');
    });
  });

  group('CloseOnce', () {
    test('closing twice closes once', () async {
      // close() is called from finally blocks, from _closeQuietly and again
      // from closePrimary: twice is ordinary, and a second close of a
      // descriptor that may by then belong to something else is not.
      int calls = 0;
      final CloseOnce lifetime = CloseOnce();
      Future<void> shutdown() async {
        calls++;
      }

      expect(lifetime.isClosed, isFalse);
      await lifetime.close(shutdown);
      await lifetime.close(shutdown);
      expect(calls, 1);
      expect(lifetime.isClosed, isTrue);
    });

    test('a failing shutdown is not retried', () async {
      int calls = 0;
      final CloseOnce lifetime = CloseOnce();
      Future<void> boom() async {
        calls++;
        throw StateError('socket already gone');
      }

      await expectLater(lifetime.close(boom), throwsStateError);
      await expectLater(lifetime.close(boom), throwsStateError);
      expect(calls, 1);
    });

    test('isClosed flips before the close finishes', () async {
      // A command started during the close would be running on a connection
      // that is already going away, so the session has to refuse from the first
      // call rather than from the completion.
      final Completer<void> slow = Completer<void>();
      final CloseOnce lifetime = CloseOnce();
      final Future<void> closing = lifetime.close(() => slow.future);
      expect(lifetime.isClosed, isTrue);
      slow.complete();
      await closing;
    });
  });

  group('nextSshTransportId', () {
    test('never repeats, so a fresh connection is provably fresh', () {
      // The firewall step refuses a prover whose id matches the connection it
      // already holds: a multiplexed channel rides an established conntrack
      // entry, which survives a firewall that rejects every new connection.
      final String first = nextSshTransportId('203.0.113.7', 22);
      final String second = nextSshTransportId('203.0.113.7', 22);
      expect(first, isNot(second));
      expect(first, contains('203.0.113.7:22'));
      expect(second, contains('203.0.113.7:22'));
    });
  });
}
