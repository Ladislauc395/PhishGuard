package com.example.phishguard_app

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "phishguard/native"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "hasOverlayPermission" -> result.success(
                        Build.VERSION.SDK_INT < Build.VERSION_CODES.M ||
                        Settings.canDrawOverlays(this)
                    )
                    "requestOverlayPermission" -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                            !Settings.canDrawOverlays(this)) {
                            startActivity(Intent(
                                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                Uri.parse("package:$packageName")))
                        }
                        result.success(true)
                    }
                    "hasSmsPermission" -> result.success(
                        ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                            == PackageManager.PERMISSION_GRANTED
                    )
                    "requestSmsPermission" -> {
                        ActivityCompat.requestPermissions(this,
                            arrayOf(Manifest.permission.RECEIVE_SMS,
                                    Manifest.permission.READ_SMS), 1001)
                        result.success(true)
                    }
                    "enableSmsReceiver" -> {
                        val enable = call.argument<Boolean>("enable") ?: false
                        toggleReceiver(enable)
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun toggleReceiver(enable: Boolean) {
        val pm = packageManager
        val component = ComponentName(this, SmsReceiver::class.java)
        val newState = if (enable)
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        else
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        pm.setComponentEnabledSetting(component, newState, PackageManager.DONT_KILL_APP)
    }
}