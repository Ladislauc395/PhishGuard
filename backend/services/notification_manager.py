"""
backend/services/notification_manager.py
─────────────────────────────────────────
Gestor de notificações em tempo real via WebSocket.

Este módulo permite:
- Enviar notificações push para o cliente Flutter
- Notificar quando phishing é detectado
- Manter histórico de notificações para clientes que conectam tarde
"""

import asyncio
import json
import logging
from typing import Dict, List, Set, Optional
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Gerencia conexões WebSocket e envia notificações em tempo real.
    
    Características:
    - Suporta múltiplos clientes simultaneamente
    - Guarda histórico das últimas 100 notificações
    - Quando um cliente conecta, recebe notificações pendentes
    - Reconexão automática do lado do cliente
    """
    
    def __init__(self):
        self._active_connections: Set[WebSocket] = set()
        self._pending_notifications: List[Dict] = []
        self._max_pending = 100
    
    async def connect(self, websocket: WebSocket):
        """Aceita uma nova conexão WebSocket."""
        await websocket.accept()
        self._active_connections.add(websocket)
        logger.info(f"🔌 Cliente conectado. Total: {len(self._active_connections)}")
        
        # Enviar notificações pendentes (últimas 10 para não sobrecarregar)
        pending_to_send = self._pending_notifications[-10:]
        for notif in pending_to_send:
            try:
                await websocket.send_json(notif)
                logger.debug(f"Notificação pendente enviada para novo cliente")
            except Exception as e:
                logger.warning(f"Falha ao enviar notificação pendente: {e}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove uma conexão WebSocket."""
        self._active_connections.discard(websocket)
        logger.info(f"🔌 Cliente desconectado. Total: {len(self._active_connections)}")
    
    async def send_notification(self, notification: Dict) -> int:
        """
        Envia notificação para todos os clientes conectados.
        
        Args:
            notification: Dicionário com os dados da notificação
            
        Returns:
            Número de clientes que receberam a notificação
        """
        # Adicionar timestamp
        notification["timestamp"] = datetime.now().isoformat()
        notification["id"] = id(notification)  # ID único para deduplicação
        
        # Guardar no histórico
        self._pending_notifications.append(notification)
        if len(self._pending_notifications) > self._max_pending:
            self._pending_notifications = self._pending_notifications[-self._max_pending:]
        
        if not self._active_connections:
            logger.info(f"📱 Notificação guardada (sem clientes): {notification.get('title')}")
            return 0
        
        # Enviar para todos os clientes conectados
        disconnected = []
        sent_count = 0
        
        for websocket in self._active_connections:
            try:
                await websocket.send_json(notification)
                sent_count += 1
                logger.debug(f"📱 Notificação enviada: {notification.get('title')}")
            except Exception as e:
                disconnected.append(websocket)
                logger.warning(f"Falha ao enviar notificação: {e}")
        
        # Limpar conexões mortas
        for ws in disconnected:
            self.disconnect(ws)
        
        if sent_count > 0:
            logger.info(f"📱 Notificação '{notification.get('title')}' enviada para {sent_count} cliente(s)")
        
        return sent_count
    
    async def notify_phishing_detected(
        self,
        email_data: Dict,
        score: int,
        verdict: str,
        reasons: List[str]
    ) -> int:
        """
        Envia notificação específica de phishing detectado.
        
        Args:
            email_data: Dados do email (com 'email' e opcionalmente 'analysis')
            score: Score de phishing (0-100)
            verdict: "SEGURO", "SUSPEITO", ou "NÃO SEGURO"
            reasons: Lista de motivos da detecção
        
        Returns:
            Número de clientes notificados
        """
        email_info = email_data.get("email", email_data)
        
        # Determinar nível de severidade
        if score >= 80:
            title = "🔴 PHISHING CRÍTICO!"
            priority = "critical"
        elif score >= 60:
            title = "⚠️ Phishing Detectado!"
            priority = "high"
        elif score >= 30:
            title = "⚠️ Email Suspeito"
            priority = "medium"
        else:
            return 0  # Não notificar para emails seguros
        
        # Construir notificação
        notification = {
            "type": "phishing_detected",
            "priority": priority,
            "title": title,
            "body": f"De: {email_info.get('sender', 'desconhecido')[:60]}",
            "subtitle": f"Score: {score} - {verdict}",
            "data": {
                "email_id": email_info.get("id"),
                "score": score,
                "verdict": verdict,
                "reasons": reasons[:5],  # Primeiros 5 motivos
                "sender": email_info.get("sender"),
                "subject": email_info.get("subject", "(sem assunto)")[:100],
                "date": email_info.get("date"),
            },
            "action_required": score >= 70,
            "actions": [
                {"label": "Ver Email", "action": "view_email"},
                {"label": "Bloquear", "action": "block_email"} if score >= 60 else None,
            ] if score >= 60 else None,
        }
        
        # Remover ações None
        if notification.get("actions"):
            notification["actions"] = [a for a in notification["actions"] if a is not None]
        
        return await self.send_notification(notification)
    
    async def notify_scan_completed(
        self,
        scanned: int,
        threats_found: int,
        blocked: int
    ) -> int:
        """Notifica que um scan de Gmail foi concluído."""
        notification = {
            "type": "scan_completed",
            "title": "📬 Scan de Emails Concluído",
            "body": f"Analisados: {scanned} | Ameaças: {threats_found} | Bloqueados: {blocked}",
            "data": {
                "scanned": scanned,
                "threats_found": threats_found,
                "blocked": blocked,
            },
        }
        return await self.send_notification(notification)
    
    async def notify_sms_phishing(
        self,
        sender: str,
        body: str,
        score: int
    ) -> int:
        """Notifica que um SMS de phishing foi detectado."""
        notification = {
            "type": "sms_phishing_detected",
            "title": "📱 SMS de Phishing Detectado!",
            "body": f"Remetente: {sender[:30]} | Score: {score}",
            "data": {
                "sender": sender,
                "body_preview": body[:100],
                "score": score,
            },
            "action_required": score >= 70,
        }
        return await self.send_notification(notification)
    
    def get_connection_count(self) -> int:
        """Retorna o número de clientes conectados."""
        return len(self._active_connections)
    
    def get_pending_count(self) -> int:
        """Retorna o número de notificações pendentes."""
        return len(self._pending_notifications)


# Instância única global
notification_manager = NotificationManager()
