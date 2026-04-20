import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_secure_app_method_channel.dart';

abstract class FlutterSecureAppPlatform extends PlatformInterface {
  /// Constructs a FlutterSecureAppPlatform.
  FlutterSecureAppPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterSecureAppPlatform _instance = MethodChannelFlutterSecureApp();

  /// The default instance of [FlutterSecureAppPlatform] to use.
  ///
  /// Defaults to [MethodChannelFlutterSecureApp].
  static FlutterSecureAppPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [FlutterSecureAppPlatform] when
  /// they register themselves.
  static set instance(FlutterSecureAppPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
