package com.example.phishguard_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class SmsReceiver : BroadcastReceiver() {

    companion object {
        // AJUSTE: use IP da sua máquina na rede Wi-Fi do telemóvel
        private const val BACKEND_URL = "http://10.227.135.68:8000/analyze/sms"
        private const val TAG = "PhishGuardSMS"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val body = messages.joinToString("") { it.messageBody ?: "" }
        val sender = messages.firstOrNull()?.originatingAddress ?: "unknown"

        Log.d(TAG, "SMS recebido de $sender: $body")
        analyzeSms(context, sender, body)
    }

    private fun analyzeSms(context: Context, sender: String, body: String) {
        val client = OkHttpClient()
        val json = JSONObject().apply {
            put("body", body)
            put("phone_number", sender)
        }
        val req = Request.Builder()
            .url(BACKEND_URL)
            .post(json.toString().toRequestBody("application/json".toMediaType()))
            .build()

        client.newCall(req).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                Log.e(TAG, "Falha ao analisar SMS", e)
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    val respBody = it.body?.string() ?: return
                    val j = JSONObject(respBody)
                    val score = j.optInt("score", 0)
                    val verdict = j.optString("verdict", "")
                    Log.d(TAG, "Score=$score Verdict=$verdict")

                    if (score > 60) {
                        showOverlayAlert(context, sender, body, score, verdict)
                    }
                }
            }
        })
    }

    private fun showOverlayAlert(ctx: Context, sender: String, body: String, score: Int, verdict: String) {
        val i = Intent(ctx, AlertOverlayService::class.java).apply {
            putExtra("sender", sender)
            putExtra("body", body)
            putExtra("score", score)
            putExtra("verdict", verdict)
        }
        ctx.startService(i)
    }
}
