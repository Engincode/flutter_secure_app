import Flutter
import UIKit
import Security

public class FlutterSecureAppPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_secure_app", binaryMessenger: registrar.messenger())
    let instance = FlutterSecureAppPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getAppleTeamId":
      result(self.getAppleTeamId())

    case "isDebuggerConnected":
      result(self.isDebuggerAttached())

    case "isJailbreakOrHooking":
      result(self.isJailbreak())

    default:
      result(FlutterMethodNotImplemented)
    }
  }

  // 1️⃣ APP SIGNATURE – TEAM ID (bundleSeedID)
  private func getAppleTeamId() -> String? {
    // STEP 1: Create a search query to locate the specific item in the Keychain.
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,  // We are looking for a generic password type.
      kSecAttrAccount as String: "bundleSeedID",      // The unique key name for our search.
      kSecAttrService as String: "",                  // Service identifier (left empty).
      kSecReturnAttributes as String: true,           // Return all attributes (including Access Group) instead of just data.
    ]

    var item: CFTypeRef?
    // Check the Keychain for an entry matching the defined query.
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    // STEP 2: If the record already exists, extract the Team ID.
    if status == errSecSuccess,
      let existingItem = item as? [String: Any],
      // kSecAttrAccessGroup returns a String in the format: "TEAMID.com.bundle.id"
      let accessGroup = existingItem[kSecAttrAccessGroup as String] as? String
    {
      // Extract the prefix before the first dot (The actual Apple Team ID).
      return accessGroup.components(separatedBy: ".").first
    }

    // STEP 3: If no record is found (first run), add a dummy record to the Keychain.
    if status == errSecItemNotFound {
      let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "bundleSeedID",
        kSecAttrService as String: "",
        kSecValueData as String: Data("x".utf8),  // The value doesn't matter; "x" is used as a placeholder.
      ]

      // Add data to Keychain. During this process, iOS automatically seals it with the app's Team ID.
      let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

      // STEP 4: If insertion was successful, re-read the newly created item.
      if addStatus == errSecSuccess {
        var newItem: CFTypeRef?
        let checkStatus = SecItemCopyMatching(query as CFDictionary, &newItem)

        if checkStatus == errSecSuccess,
          let newDict = newItem as? [String: Any],
          let newAccessGroup = newDict[kSecAttrAccessGroup as String] as? String
        {
          // Retrieve the Access Group which now contains the system-stamped Team ID.
          return newAccessGroup.components(separatedBy: ".").first
        }
      }
    }

    // Returns nil if any error occurs (Access denied, system error, etc.).
    return nil
  }

  // 2️⃣ JAILBREAK / HOOKING DETECTION
  private func isJailbreak() -> Bool {
    // STEP 1: Simulator Check
    // Simulators often report root-like privileges by default. 
    // We bypass this check on simulators to avoid interruptions during development.
    #if targetEnvironment(simulator)
      return false
    #else
      let fm = FileManager.default

      // STEP 2: Known Jailbreak File and Directory Paths
      // These paths are typically present on a jailbroken device (Package managers or core binaries).
      let paths = [
        // --- PACKAGE MANAGERS & STORES ---
        "/Applications/Cydia.app",  // Legacy jailbreak app store.
        "/Applications/Sileo.app",  // Modern package manager for Odyssey/Taurine/Dopamine.
        "/Applications/Zebra.app",  // Popular alternative package manager.
        "/Applications/FlyJB.app",  // A tool used to bypass jailbreak detection itself.

        // --- HOOKING & TWEAK LIBRARIES ---
        "/Library/MobileSubstrate/MobileSubstrate.dylib",  // Primary library for code injection (Legacy).
        "/usr/lib/libsubstitute.dylib",  // Modern hooking engine used in recent jailbreaks.

        // --- SYSTEM ENTRY POINTS (ROOTLESS & ROOTFUL) ---
        "/var/jb",  // Virtual root for iOS 15+ Rootless jailbreaks (Critical check).
        "/bin/bash",  // Unix shell access, typically restricted on stock iOS.
        "/usr/sbin/sshd",  // SSH server allowing remote terminal access.
        "/etc/apt",  // Config directory for Debian-based Advanced Package Tool.

        // --- DATABASE & CACHE DIRECTORIES ---
        "/private/var/lib/apt/",  // System folder for package and tweak metadata.
        "/private/var/lib/cydia",  // Cydia installation and list repository.

        // --- TOOL-SPECIFIC ARTIFACTS ---
        "/.bootstrapped_electra",  // File created during Electra jailbreak bootstrap.
        "/.mount_rw",              // Evidence that the Read-Only root partition was remounted as Writable.
        "/.installed_unc0ver",     // Marker indicating a successful unc0ver installation.
      ]

      // If any of these paths exist, the device is considered compromised.
      for path in paths where fm.fileExists(atPath: path) {
        return true
      }

      // STEP 3: Write Permission Test (Sandbox Escape Check)
      // Standard iOS apps are restricted to their own Sandbox directory.
      // Writing to "/private/" is strictly forbidden. If successful, it proves a Sandbox escape.
      do {
        let testPath = "/private/jb.txt"
        // Attempt to write data to a restricted directory
        try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
        // If execution reaches here, the file was written successfully.
        // Clean up and return true for jailbreak detection.
        try fm.removeItem(atPath: testPath)
        return true
      } catch {
        // Exception thrown: Writing denied by iOS security.
        // This is the expected behavior for non-jailbroken devices.
      }

      return false
    #endif
  }

  // 3️⃣ DEBUGGER DETECTION (Release only)
  private func isDebuggerAttached() -> Bool {
    #if DEBUG
      return false
    #else
      var info = kinfo_proc()
      var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
      var size = MemoryLayout<kinfo_proc>.stride

      // Uses sysctl to check the P_TRACED flag in the process structure.
      if sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 {
        return (info.kp_proc.p_flag & P_TRACED) != 0
      }

      return false
    #endif
  }
}
