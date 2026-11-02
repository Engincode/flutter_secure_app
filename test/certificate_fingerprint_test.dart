import 'package:crypto/crypto.dart';
import 'package:flutter_secure_app/src/certificate_fingerprint.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('fingerprintMatches', () {
    final der = List<int>.generate(64, (i) => i);
    final hash = sha256.convert(der).toString().toUpperCase();

    test('matches a plain uppercase fingerprint', () {
      expect(fingerprintMatches(der, [hash]), isTrue);
    });

    test('ignores case, whitespace and colon separators', () {
      final pairs = <String>[
        for (var i = 0; i < hash.length; i += 2) hash.substring(i, i + 2),
      ];
      expect(fingerprintMatches(der, [pairs.join(':').toLowerCase()]), isTrue);
      expect(fingerprintMatches(der, [pairs.join(' ')]), isTrue);
    });

    test('rejects a different fingerprint', () {
      expect(fingerprintMatches(der, ['00' * 32]), isFalse);
      expect(fingerprintMatches(der, []), isFalse);
    });
  });
}
