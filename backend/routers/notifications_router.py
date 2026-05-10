"""
backend/routers/notifications_router.py
────────────────────────────────────────
Endpoints WebSocket para notificações em tempo real.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.services.notification_manager import notification_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Endpoint WebSocket para receber notificações em tempo real.
    
    O cliente Flutter deve conectar-se a:
        ws://<backend_ip>:8000/notifications/ws
    
    Formato das mensagens recebidas (JSON):
    {
        "type": "phishing_detected",
        "title": "⚠️ Phishing Detectado!",
        "body": "Email de ...",
        "data": {...},
        "timestamp": "2024-01-15T10:30:00"
    }
    """
    await notification_manager.connect(websocket)
    try:
        # Manter a conexão viva e escutar eventuais mensagens do cliente
        while True:
            # Receber mensagem do cliente (ping/pong ou comandos)
            data = await websocket.receive_text()
            
            # Processar comandos do cliente se necessário
            if data == "ping":
                await websocket.send_text("pong")
            elif data.startswith("{"):
                # Tentar processar como JSON para comandos futuros
                import json
                try:
                    cmd = json.loads(data)
                    cmd_type = cmd.get("type")
                    if cmd_type == "get_pending":
                        # Enviar notificações pendentes
                        for notif in notification_manager._pending_notifications[-20:]:
                            await websocket.send_json(notif)
                except:
                    pass
                    
    except WebSocketDisconnect:
        notification_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Erro no WebSocket: {e}")
        notification_manager.disconnect(websocket)
        