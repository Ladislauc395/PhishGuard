"""Pacote de modelos SQLModel do PhishGuard."""

from backend.models.analysis import Analysis
from backend.models.brand import BrandProfile
from backend.models.email import Email
from backend.models.sms import SMS
from backend.models.user import User

__all__ = ["Analysis", "BrandProfile", "Email", "SMS", "User"]
