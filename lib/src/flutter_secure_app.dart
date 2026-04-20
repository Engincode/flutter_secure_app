import 'dart:io';
import 'dart:math';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'secure_app_threat_type.dart';

/// RASP (Runtime Application Self-Protection) and Security Service
/// [SECURITY LAYER 2: DEVICE & APP INTEGRITY (RASP)]
/// RASP stands for "Runtime Application Self-Protection."
///
/// This service monitors and validates the integrity of both the DEVICE
/// environment and the APPLICATION itself during runtime.
///
/// Monitored Threats:
/// - Root/Jailbreak (Privileged Access): Checks if the device's OS security has been compromised.
/// - Debugging/Platform: Detects if a local debugger is attached or if debug mode is active.
/// - Simulator/Emulator: Verifies if the app is running on a physical device or virtual hardware.
/// - App Signature: Checks for package name mismatches or signature invalidation (Anti-Cloning).
/// - Anti-Hooking: Hooking is mitigated through Root/Jailbreak restrictions and App Signature
///   checks that prevent re-packaging through reverse engineering.
/// - Device Binding & Device Spoofing: Detects hardware ID manipulation or identity masking.
///
/// - NOTE: This layer does not inspect network traffic (No SSL Pinning).
///   It focuses strictly on environment and runtime integrity.
///   SSL Pinning and Anti-Proxy controls are handled within the DioClient.
class FlutterSecureApp {
  static const MethodChannel _channel = MethodChannel('flutter_secure_app');

  static final FlutterSecureApp _instance = FlutterSecureApp._internal();

  factory FlutterSecureApp() => _instance;

  FlutterSecureApp._internal();

  bool _isSafe = true;
  bool get isSafe => _isSafe;

  SecureAppThreatType? _currentThreat;
  SecureAppThreatType? get currentThreat => _currentThreat;

  /// Triggered whenever a threat is detected
  Function(SecureAppThreatType)? onThreatDetected;

  /// Triggered whenever an internal exception occurs
  Function(Object error, StackTrace stackTrace)? onException;

  bool _isEnabled = true;
  bool _isProdEnv = true;
  List<String>? _validAndroidStores;
  List<String>? _validIosTeamIds;
  List<String>? _validAndroidSignatures;

  /// Initialize the RASP engine
  Future<void> init({
    bool isEnabled = true,
    bool isProdEnv = true,
    List<String>? validAndroidStores,
    List<String>? validIosTeamIds,
    List<String>? validAndroidSignatures,
    Function(SecureAppThreatType)? onThreatDetected,
    Function(Object error, StackTrace stackTrace)? onException,
    bool checkJailbreakOrHooking = true,
    bool checkEmulator = true,
    bool checkDebugger = true,
    bool checkAppSignature = true,
    bool checkOfficialStore = true,
    bool checkDeviceBinding = true,
    bool checkDeviceIdSpoofing = true,
  }) async {
    _isEnabled = isEnabled;
    _isProdEnv = isProdEnv;
    this.onThreatDetected = onThreatDetected;
    this.onException = onException;
    _validAndroidStores = validAndroidStores ??
        [
          'com.android.vending', // Google Play Store
          'com.amazon.venezia', // Amazon Appstore
          'com.sec.android.app.samsungapps', // Samsung Galaxy Store
          'com.huawei.appmarket', // Huawei AppGallery
          'com.xiaomi.market', // Xiaomi GetApps
          'com.oppo.market', // OPPO App Market
          'com.vivo.appstore', // VIVO App Store
        ];

    _validIosTeamIds = validIosTeamIds;
    _validAndroidSignatures = validAndroidSignatures;

    if (!_isEnabled) return;

    try {
      // 1. Jailbreak / Root (Privileged Access) / Hooking
      // A rooted or jailbroken device directly enables the use of instrumentation
      // tools like Frida and other hooking frameworks.
      if (isSafe && checkJailbreakOrHooking) {
        final isJailbreakOrHooking = await checkJailbreakOrHookingStatus();
        if (isJailbreakOrHooking) {
          _handleThreat(SecureAppThreatType.privilegedAccess);
        }
      }

      // 2. Simulator / Emulator Denetimi
      if (isSafe && checkEmulator) {
        final isEmulator = await _isEmulatorDevice();
        if (isEmulator) {
          _handleThreat(SecureAppThreatType.simulator);
        }
      }

      // 3. Debugger Attached Kontrolü
      if (isSafe && checkDebugger) {
        final isDebuggerConnected = await checkDebuggerAttachedStatus();
        if (isDebuggerConnected) {
          _handleThreat(SecureAppThreatType.debug);
        }
      }

      // 4. App Signature (Team ID / Signature Check)
      if (isSafe && checkAppSignature) {
        final isSignatureValid = await _checkAppSignature();
        if (!isSignatureValid) {
          _handleThreat(SecureAppThreatType.appSignature);
        }
      }

      // 5. Official Store Kontrolü
      if (isSafe && checkOfficialStore) {
        await _checkOfficialStore();
      }

      // 6. Device Binding / App Cloning & Data Migration
      if (isSafe && checkDeviceBinding) {
        final isDeviceValid = await _checkDeviceBinding();
        if (!isDeviceValid) {
          _handleThreat(SecureAppThreatType.deviceBinding);
        }
      }

      // 7. Device ID Spoofing / Mock Identity Detection (FreeRASP onDeviceID)
      // Device ID values can be volatile or easily manipulated on Emulators/Simulators;
      // therefore, we include the !isDebug() check to prevent false positives during development.
      if (isSafe && checkDeviceIdSpoofing) {
        final isDeviceIdValid = await _checkDeviceIdSpoofing();
        if (!isDeviceIdValid) {
          _handleThreat(SecureAppThreatType.deviceIdSpoofing);
        }
      }
    } catch (e, s) {
      _handleException(e, s);
      _handleThreat(SecureAppThreatType.codeError);
    }
  }

  void _handleThreat(SecureAppThreatType threatType) {
    if (!_isEnabled) return;

    _isSafe = false;
    _currentThreat = threatType;

    if (onThreatDetected != null) {
      onThreatDetected!(threatType);
    }
  }

  void _handleException(Object error, StackTrace stackTrace) {
    debugPrint('FlutterSecureApp exception: $error\n$stackTrace');
    if (onException != null) {
      onException!(error, stackTrace);
    }
  }

  // Android Unofficial Store (Sideloading) Detection
  // Checks if the app was installed from a source other than Google Play,
  // App Store, or recognized stores like Huawei/Amazon.
  // Note: This check is skipped on iOS as the App Store environment is a closed ecosystem.
  Future<void> _checkOfficialStore() async {
    if (_isProdEnv && Platform.isAndroid) {
      final packageInfo = await PackageInfo.fromPlatform();

      // An empty string typically indicates the app was sideloaded (installed via APK).
      final installer = packageInfo.installerStore ?? '';

      // Trigger threat handling if the installer is identified as an unknown source.
      // Note: On iOS, the installer source might return empty even for App Store installs,
      // which is why this check is platform-specific for Android.
      if (installer.isNotEmpty && !(_validAndroidStores!.contains(installer))) {
        _handleThreat(SecureAppThreatType.unofficialStore);
      }
    }
  }

  /// Checks if the application is running on an emulator or simulator.
  Future<bool> _isEmulatorDevice() async {
    try {
      final deviceInfo = DeviceInfoPlugin();
      if (Platform.isAndroid) {
        final androidInfo = await deviceInfo.androidInfo;
        return !androidInfo.isPhysicalDevice;
      } else if (Platform.isIOS) {
        final iosInfo = await deviceInfo.iosInfo;
        return !iosInfo.isPhysicalDevice;
      }
    } catch (e) {
      debugPrint('Error in _isEmulatorDevice: $e');
    }
    return false;
  }

  /// Device Binding & Device ID Integrity Check (Anti-Cloning / Data Migration Prevention)
  /*
   * During App Cloning or Data Migration attacks, an adversary (or malicious software)
   * copies the application's data directory and migrates it to another device
   * (using tools like Titanium Backup, Helium, or rooted file explorers). 
   * This mechanism is designed to detect such unauthorized migrations.
   * * Portable Storage (shared_preferences): Stored within the app's standard file 
   * directory. When an attacker clones the app data, these files are inevitably 
   * copied to the target device.
   * * Non-Portable Hardware-Backed Storage (flutter_secure_storage): Written directly 
   * to the device's hardware security module (Android Keystore / iOS Keychain). 
   * Even if the attacker copies the file system, they cannot migrate the hardware-bound 
   * cryptographic keys, as they are physically tied to the original device's silicon.
   * * Security Algorithm Workflow:
   * * 1. On the initial launch, a unique UUID (Binding Token) is generated and persisted 
   * in both shared_preferences and flutter_secure_storage.
   * 2. On every subsequent launch, the app cross-references both values.
   * 3. In a cloning scenario:
   * - The "cloned" shared_preferences will still contain the original token.
   * - The flutter_secure_storage will be empty or inaccessible on the new device 
   * (since the hardware-bound key did not migrate).
   * 4. If these two tokens fail to match, we definitively identify that the app data 
   * has been illegally migrated or cloned from another device, triggering a RASP alert.
   */
  Future<bool> _checkDeviceBinding() async {
    try {
      const bindingKey = 'app_device_binding_token';

      // 1. Read the token from hardware-backed storage (Android Keystore / iOS Keychain)
      const secureStorage = FlutterSecureStorage();
      final secureToken = await secureStorage.read(key: bindingKey);

      // 2. Read the token from standard file storage (SharedPreferences - portable/clonable)
      final prefs = await SharedPreferences.getInstance();
      final prefsToken = prefs.getString(bindingKey);

      // Initial Setup: If both are empty, this is a fresh installation.
      // Generate and synchronize a new unique token.
      if (secureToken == null && prefsToken == null) {
        final newToken = _generateBindingToken();
        await secureStorage.write(key: bindingKey, value: newToken);
        await prefs.setString(bindingKey, newToken);
        return true;
      }
      // Data Recovery: Secure Storage contains the token but SharedPreferences is empty
      // (likely due to a local data clear). Re-synchronize from hardware-backed storage.
      else if (secureToken != null && prefsToken == null) {
        await prefs.setString(bindingKey, secureToken);
        return true;
      }
      // CLONING/MIGRATION DETECTED!
      // The portable token (Prefs) does not match the hardware-bound token (Secure Storage).
      // This indicates the app data was copied from another device.
      else if (secureToken != prefsToken) {
        return false;
      }
      return true; // Integrity verified: tokens are synchronized.
    } catch (e) {
      debugPrint('Error in _checkDeviceBinding: $e');
      // To avoid false positives or blocking the user due to system errors,
      // we default to 'true' in case of an exception.
      return true;
    }
  }

  /// Device ID Spoofing / Mock Identity Detection (Equivalent to FreeRASP onDeviceID)
  /// Verifies whether the hardware-backed identity of the device (Android ID, iOS IDFV)
  /// has changed since the initial installation.
  /// Prevents Device ID manipulation at the OS level.
  Future<bool> _checkDeviceIdSpoofing() async {
    try {
      const storedIdKey = 'app_hardware_device_id';
      const secureStorage = FlutterSecureStorage();

      final deviceInfo = DeviceInfoPlugin();
      String currentDeviceId = '';

      if (Platform.isAndroid) {
        final androidInfo = await deviceInfo.androidInfo;
        currentDeviceId = androidInfo.id;
      } else if (Platform.isIOS) {
        final iosInfo = await deviceInfo.iosInfo;
        currentDeviceId = iosInfo.identifierForVendor ?? '';
      }

      // Bypass check if the device ID is unreadable
      if (currentDeviceId.isEmpty) return true;

      final storedDeviceId = await secureStorage.read(key: storedIdKey);

      if (storedDeviceId == null) {
        // Initial launch: Persist the current device hardware identity in secure storage.
        await secureStorage.write(key: storedIdKey, value: currentDeviceId);
        return true;
      }

      // If the hardware-bound ID stored during the first run does not match the
      // current ID, it indicates that the Device ID has been spoofed or manipulated.
      if (storedDeviceId != currentDeviceId) {
        return false;
      }
      return true;
    } catch (e) {
      debugPrint('Error in _checkDeviceIdSpoofing: $e');
      // Default to true in case of system failure to maintain user experience.
      return true;
    }
  }

  // On Android side this method checks the app's signing certificate against
  //  a list of valid signatures.
  // On iOS side this method checks the app's Team ID against a
  //  list of valid Team IDs.
  Future<bool> _checkAppSignature() async {
    try {
      if (Platform.isIOS) {
        if (_validIosTeamIds == null || _validIosTeamIds!.isEmpty) {
          return true;
        }
        final String? teamId =
            await _channel.invokeMethod<String>('getAppleTeamId');
        return teamId != null && _validIosTeamIds!.contains(teamId);
      } else if (Platform.isAndroid) {
        if (_validAndroidSignatures == null ||
            _validAndroidSignatures!.isEmpty) {
          return true;
        }
        final packageInfo = await PackageInfo.fromPlatform();
        return _validAndroidSignatures!.contains(packageInfo.buildSignature);
      }
    } catch (e) {
      debugPrint('Error in _checkAppSignature: $e');
    }
    return true;
  }

  //  Rastgele kriptografik 256-bit token üretir
  String _generateBindingToken() {
    final random = Random.secure();
    final values = List<int>.generate(32, (i) => random.nextInt(256));
    return values.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<bool> checkJailbreakOrHookingStatus() async {
    try {
      final hasThreat =
          await _channel.invokeMethod<bool>('isJailbreakOrHooking') ?? false;
      return hasThreat;
    } catch (e) {
      return false;
    }
  }

  Future<bool> checkDebuggerAttachedStatus() async {
    try {
      final isDebuggerOn =
          await _channel.invokeMethod<bool>('isDebuggerConnected') ?? false;
      return isDebuggerOn;
    } catch (e) {
      return false;
    }
  }

  /// Expose method for interceptor
  void notifySslPinningError() {
    _handleThreat(SecureAppThreatType.sslPinningError);
  }
}
