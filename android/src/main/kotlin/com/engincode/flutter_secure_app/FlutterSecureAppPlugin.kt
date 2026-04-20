package com.engincode.flutter_secure_app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File

class FlutterSecureAppPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_secure_app")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "isJailbreakOrHooking" -> result.success(isJailbreakOrHooking())
                "isDebuggerConnected" -> result.success(isDebuggerConnected())
                "isTampered" -> result.success(isTampered())
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("SECURITY_FATAL", "Native error: ${e.message}", null)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    // ---------------------------------------------
    //      1) STRONG DEBUGGER / ANTI-DEBUG
    // ---------------------------------------------
    private fun isDebuggerConnected(): Boolean {
        // Checks if a debugger is attached via the standard Android Debug library
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return true
        
        // Checks if 'debuggable=true' is set in the AndroidManifest.xml.
        // This should always be 0 (false) in production/release builds.        
        if ((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) return true
        
        return false
    }

    // ---------------------------------------------
    //   2) GENERAL SECURITY CONTROL CENTER   
    // ---------------------------------------------
    private fun isJailbreakOrHooking(): Boolean {
        // Simple Root check (File paths and Build tags)
        if (checkRootSimple()) return true

        // Check if the process is being traced (Debugger/PTRACE check)
        if (isTracerPidActive()) return true

        // Search for Frida artifacts in the memory map
        if (detectFridaByMaps()) return true

        // Search for 'memfd' traces used by modern Frida versions
        if (detectFridaMemfd()) return true

        // Search for 'memfd' traces used by modern Frida versions
        if (detectXposed()) return true

        // Check if the application signature has been altered (Re-signing check)
        if (isTampered()) return true

        return false
    }

    // ---- Root Detection (Fast Method) ----
    private fun checkRootSimple(): Boolean {
        // Check if the device firmware is signed with 'test-keys' 
        // (common in custom/rooted ROMs or developer builds)        
        val buildTags = Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) return true

        // Check for the presence of the 'su' (superuser) binary in common system directories
        val paths = arrayOf(
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su",
            "/magisk/.core/bin/su", "/system/app/Superuser.apk"
        )

        // Return true if any known superuser binary path is found
        for (path in paths) {
            if (File(path).exists()) return true
        }

        return false
    }

    // ---- TracerPid Detection ----
    // In the Linux kernel, if a process is being traced by another process (like a debugger),
    // the TracerPid value in /proc/self/status will be greater than 0.
    private fun isTracerPidActive(): Boolean {
        return try {
            val file = File("/proc/self/status")
            if (!file.exists()) return false
            
            file.bufferedReader().use { reader ->
                reader.lineSequence().any { line ->
                    if (line.startsWith("TracerPid:")) {
                        val pid = line.substringAfter(":").trim().toIntOrNull() ?: 0
                        pid > 0 
                    } else false
                }
            }
        } catch (_: Exception) { false }
    }

    // ---------------------------------------------
    //      3) FRIDA DETECTION (/proc/self/maps)
    // ---------------------------------------------
    // Scans the application's memory maps to identify any loaded libraries 
    // or agents associated with the Frida dynamic instrumentation toolkit.
    private fun detectFridaByMaps(): Boolean {
        return try {
            val file = File("/proc/self/maps")
            if (!file.exists()) return false

            file.bufferedReader().use { reader ->
                reader.lineSequence().any { line ->
                    line.contains("frida") ||
                    line.contains("gum-js-loop") ||
                    line.contains("libfrida") ||
                    line.contains("frida-agent")
                }
            }
        } catch (_: Exception) { false }
    }

    // Modern Frida versions use "memfd" (anonymous memory files) to avoid leaving traces on the disk.
    private fun detectFridaMemfd(): Boolean {
        return try {
            val file = File("/proc/self/maps")
            if (!file.exists()) return false

            file.bufferedReader().use { reader ->
                reader.lineSequence().any { line ->
                   line.contains("memfd:frida-agent", ignoreCase = true) ||
                   line.contains("memfd:gum-js-loop", ignoreCase = true) ||
                   line.contains("memfd:frida", ignoreCase = true)
                }
            }
        } catch (_: Exception) { false }
    }

    // ---------------------------------------------
    //      4) XPOSED / LSPOSED / EDXPOSED DETECTION
    // ---------------------------------------------
    // Detects hooking frameworks by checking for the presence of specific 
    // Java classes injected into the runtime memory.
    private fun detectXposed(): Boolean {
        try {
            val xposedClasses = arrayOf(
                "de.robv.android.xposed.XposedBridge", 
                "org.lsposed.lspatch.core.AppEnv",      
                "de.robv.android.xposed.XposedHelpers",
                "org.lsposed.hiddenapibypass.HiddenApiBypass"
            )
            for (cls in xposedClasses) {
                try {
                    // If any of these classes can be loaded, the framework is active on the device.
                    Class.forName(cls)
                    return true
                } catch (_: Throwable) {}
            }
        } catch (_: Exception) {}
        return false
    }
    
    // ---------------------------------------------
    //      5) TAMPER DETECTION (SIGNATURE CHECK)
    // ---------------------------------------------
    // Verifies if the APK signature has been removed or invalidated.
    // Note: This check only confirms existence. For robust security, 
    // you should compare the SHA-256 hash of the signature against a hardcoded trusted value.
    private fun isTampered(): Boolean {
        return try {
            val pm = context.packageManager
            val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    ?.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
            }
            sigs == null || sigs.isEmpty()
        } catch (_: Exception) { 
            true 
        }
    }
}
