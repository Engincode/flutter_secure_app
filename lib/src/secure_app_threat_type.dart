enum SecureAppThreatType {
  privilegedAccess, // Root / Jailbreak / Hooking
  simulator, // Emulator / Simulator
  debug, // Debugger Attached
  appSignature, // Tampered Signature / Unmatched Team ID
  unofficialStore, // Sideloaded (Android)
  deviceBinding, // App Cloning / Data Migration
  deviceIdSpoofing, // Device ID Manipulated
  sslPinningError, // MITM Attack detected
  codeError // Unexpected internal error
}
