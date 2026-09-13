// SSH carries a command STRING, not an argument vector, so somewhere the vector
// has to become one. This is that somewhere, and it is the only place in the
// app allowed to do it: `./vpn` shipped the unquoted version and one argument
// containing a space silently became two -- which, one layer down, misaligns
// the space-separated IKEv2 user and password lists.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/control/shell.dart';

void main() {
  group('shellQuote', () {
    test('leaves inert words alone, so a command line stays readable', () {
      for (final String word in <String>[
        'vpnctl',
        '/usr/local/bin/vpnctl',
        '--json',
        '--show-secrets',
        'user',
        'guest.phone',
        'vless-reality',
        '10443/tcp',
        '203.0.113.10',
        'root@203.0.113.10',
      ]) {
        expect(shellQuote(word), word, reason: '$word should not need quoting');
      }
    });

    test('quotes anything the remote shell would touch', () {
      expect(shellQuote('two words'), "'two words'");
      expect(shellQuote(''), "''");
      expect(shellQuote('*'), "'*'");
      expect(shellQuote('~'), "'~'");
      expect(shellQuote(r'$HOME'), r"'$HOME'");
      expect(shellQuote('a;rm -rf /'), "'a;rm -rf /'");
      expect(shellQuote('a\nb'), "'a\nb'");
      expect(shellQuote('back\\slash'), "'back\\slash'");
    });

    test('a single quote is closed, escaped and reopened', () {
      // The only way to get one through a single-quoted string, and the case a
      // naive quoter gets wrong by producing something the shell still parses.
      expect(shellQuote("it's"), r"'it'\''s'");
      expect(shellQuote("'"), r"''\'''");
    });
  });

  group('shellCommand', () {
    test('joins a vector into exactly one command', () {
      expect(
        shellCommand(<String>['vpnctl', '--json', 'user', 'add', 'kate']),
        'vpnctl --json user add kate',
      );
    });

    test('an argument with a space survives as one argument', () {
      expect(
        shellCommand(<String>['vpnctl', 'user', 'add', 'two words']),
        "vpnctl user add 'two words'",
      );
    });

    test('nothing an argument contains can start a second command', () {
      final String line = shellCommand(<String>[
        'vpnctl',
        'user',
        'rm',
        r'x; touch /tmp/pwned; echo $(whoami)',
      ]);
      expect(line, startsWith('vpnctl user rm '));
      expect(line.substring('vpnctl user rm '.length), startsWith("'"));
      expect(line, endsWith("'"));
    });
  });
}
