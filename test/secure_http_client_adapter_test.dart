import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_app/flutter_secure_app.dart';

void main() {
  test('SecureHttpClientAdapter supports SPKI pinning configuration', () {
    final adapter = SecureHttpClientAdapter.getAdapter(
      allowedSpkiHashes: [
        '5A:C3:A8:D5:11:47:A5:72:0B:44:83:8B:D8:1A:30:A5:68:55:A6:DB:99:7E:59:75:A8:F5:F2:B5:12:F1:C9:92',
      ],
      bypassSpkiForLocalhost: true,
    );

    expect(adapter, isNotNull);
    expect(adapter.createHttpClient, isNotNull);
    expect(adapter.validateCertificate, isNotNull);
  });
}
