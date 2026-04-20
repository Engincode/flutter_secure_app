import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_app/flutter_secure_app_platform_interface.dart';
import 'package:flutter_secure_app/flutter_secure_app_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterSecureAppPlatform
    with MockPlatformInterfaceMixin
    implements FlutterSecureAppPlatform {
  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final FlutterSecureAppPlatform initialPlatform =
      FlutterSecureAppPlatform.instance;

  test('$MethodChannelFlutterSecureApp is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterSecureApp>());
  });
}
