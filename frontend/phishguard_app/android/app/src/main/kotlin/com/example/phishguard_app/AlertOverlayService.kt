package com.example.phishguard_app
import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.os.IBinder
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView

class AlertOverlayService : Service() {
    private var windowManager: WindowManager? = null
    private var overlayView: View? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val sender = intent?.getStringExtra("sender") ?: ""
        val body = intent?.getStringExtra("body") ?: ""
        val score = intent?.getIntExtra("score", 0) ?: 0
        val verdict = intent?.getStringExtra("verdict") ?: ""

        showOverlay(sender, body, score, verdict)
        return START_NOT_STICKY
    }

    private fun showOverlay(sender: String, body: String, score: Int, verdict: String) {
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        overlayView = LayoutInflater.from(this).inflate(R.layout.alert_overlay, null)

        overlayView?.findViewById<TextView>(R.id.tvSender)?.text = "De: $sender"
        overlayView?.findViewById<TextView>(R.id.tvBody)?.text = body
        overlayView?.findViewById<TextView>(R.id.tvScore)?.text = "Risco: $score/100 — $verdict"
        overlayView?.findViewById<Button>(R.id.btnDismiss)?.setOnClickListener { stopSelf() }

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        else WindowManager.LayoutParams.TYPE_PHONE

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT,
        )
        params.gravity = Gravity.TOP
        windowManager?.addView(overlayView, params)
    }

    override fun onDestroy() {
        super.onDestroy()
        overlayView?.let { windowManager?.removeView(it) }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
