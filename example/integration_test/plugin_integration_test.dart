// This is a basic Flutter integration test.
//
// Since integration tests run in a full Flutter application, they can interact
// with the host side of a plugin implementation, unlike Dart unit tests.
//
// For more information about Flutter integration tests, please see
// https://flutter.dev/to/integration-testing

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:dio/dio.dart';

import 'package:flutter_secure_app/flutter_secure_app.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('FlutterSecureApp Integration Tests', () {
    late FlutterSecureApp plugin;

    setUp(() {
      plugin = FlutterSecureApp();
    });

    testWidgets('should initialize successfully without throwing exceptions', (
      WidgetTester tester,
    ) async {
      bool isExceptionThrown = false;
      SecureAppThreatType? detectedThreat;

      try {
        await plugin.init(
          isEnabled: true,
          isProdEnv: false,
          checkJailbreakOrHooking: false,
          checkEmulator: false,
          checkAppSignature: false,
          checkOfficialStore: false,
          checkDeviceBinding: false,
          checkDeviceIdSpoofing: false,
          validIosTeamIds: ['TEST_TEAM_ID'],
          validAndroidSignatures: ['TEST_SIGNATURE'],
          onThreatDetected: (SecureAppThreatType threatType) {
            detectedThreat = threatType;
          },
          onException: (error, stackTrace) {
            isExceptionThrown = true;
          },
        );
      } catch (e) {
        isExceptionThrown = true;
      }

      // We expect the init method to execute without throwing an exception
      expect(isExceptionThrown, false);

      // Since all threat checks are disabled (false) in this test scenario,
      // no threat should be detected and it should remain null.
      expect(detectedThreat, isNull);

      // plugin.isSafe should return a boolean
      expect(plugin.isSafe, isA<bool>());
    });

    testWidgets('should check jailbreak/hooking status', (
      WidgetTester tester,
    ) async {
      final isJailbrokenOrHooked = await plugin.checkJailbreakOrHookingStatus();

      // It can return true or false depending on the device status, we verify the type is bool
      expect(isJailbrokenOrHooked, isNotNull);
      expect(isJailbrokenOrHooked, isA<bool>());
    });

    testWidgets('should check debugger attached status', (
      WidgetTester tester,
    ) async {
      final isDebuggerAttached = await plugin.checkDebuggerAttachedStatus();

      // It can return true or false depending on the device status, we verify the type is bool
      expect(isDebuggerAttached, isNotNull);
      expect(isDebuggerAttached, isA<bool>());
    });

    testWidgets(
      'should configure Dio securely over SslPinningInterceptor and SecureHttpClientAdapter',
      (WidgetTester tester) async {
        final dio = Dio();

        // 1. SSL Pinning Interceptor test scenario
        dio.interceptors.add(
          SslPinningInterceptor(
            allowedFingerprints: [
              'TEST_FINGERPRINT_HASH_1',
              'TEST_FINGERPRINT_HASH_2',
            ],
            bypassForLocalhost: true,
          ),
        );

        // 2. Secure HTTP Client Adapter (Proxy bypass etc.) scenario
        dio.httpClientAdapter = SecureHttpClientAdapter.getAdapter();

        // Verify that the configurations are correctly added to Dio and initialized
        final hasSslPinningInterceptor = dio.interceptors.any(
          (interceptor) => interceptor is SslPinningInterceptor,
        );

        expect(
          hasSslPinningInterceptor,
          true,
          reason: 'SslPinningInterceptor was not added successfully',
        );
        expect(
          dio.httpClientAdapter,
          isNotNull,
          reason: 'SecureHttpClientAdapter is null',
        );
      },
    );
  });
}
