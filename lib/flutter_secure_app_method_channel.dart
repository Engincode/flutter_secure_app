import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_secure_app_platform_interface.dart';

/// An implementation of [FlutterSecureAppPlatform] that uses method channels.
class MethodChannelFlutterSecureApp extends FlutterSecureAppPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_secure_app');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>(
      'getPlatformVersion',
    );
    return version;
  }
}
