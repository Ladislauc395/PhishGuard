"""Endpoints de autenticação — JWT local + Google OAuth2."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator
from sqlmodel import Session, select

from backend.core.config import settings
from backend.core.database import get_session
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# ─── Segurança ────────────────────────────────────────────────────

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h


# ─── Schemas ──────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Nome deve ter pelo menos 2 caracteres")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password deve ter pelo menos 8 caracteres")
        if not any(c.isupper() for c in v):
            raise ValueError("Password deve conter pelo menos uma letra maiúscula")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password deve conter pelo menos um número")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserOut(BaseModel):
    id: int
    name: str
    email: str
    avatar_url: Optional[str] = None
    provider: str  # "local" | "google"

    model_config = {"from_attributes": True}


class GoogleAuthRequest(BaseModel):
    id_token: str  # Token vindo do Google Sign-In no cliente


# ─── Helpers ──────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return pwd_ctx.hash(password)


def _verify(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def _create_token(user_id: int) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "exp": expire},
        settings.SECRET_KEY,
        algorithm=ALGORITHM,
    )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = session.get(User, int(user_id))
    if user is None:
        raise credentials_exc
    return user


# ─── Endpoints ────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest,
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Regista um novo utilizador com email + password."""
    try:
        existing = session.exec(select(User).where(User.email == body.email)).first()
        if existing:
            raise HTTPException(status_code=409, detail="Email já registado")

        user = User(
            name=body.name.strip(),
            email=body.email.strip().lower(),
            hashed_password=_hash(body.password),
            provider="local",
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        token = _create_token(user.id)
        return TokenResponse(access_token=token, user=UserOut.model_validate(user))
    except HTTPException:
        raise
    except Exception as exc:
        session.rollback()
        logger.exception("Erro ao registar utilizador: %s", exc)
        raise HTTPException(status_code=500, detail=f"Erro interno: {exc}") from exc


@router.post("/token", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Login com email + password (OAuth2 form padrão)."""
    user = session.exec(select(User).where(User.email == form.username)).first()
    if not user or not user.hashed_password or not _verify(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = _create_token(user.id)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.post("/google", response_model=TokenResponse)
async def google_login(
    body: GoogleAuthRequest,
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Autentica via Google ID Token (enviado pelo cliente Flutter)."""
    # Verifica token junto ao Google
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": body.id_token},
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Google token inválido")

    info = resp.json()

    # Verifica audience apenas se GOOGLE_CLIENT_ID estiver configurado.
    # Se estiver vazio (dev/test), aceita qualquer token válido do Google.
    if settings.GOOGLE_CLIENT_ID:
        token_aud = info.get("aud", "")
        valid_audiences = [a.strip() for a in settings.GOOGLE_CLIENT_ID.split(",") if a.strip()]
        if token_aud not in valid_audiences:
            logger.warning("Google token aud=%s nao aceite. Validos: %s", token_aud, valid_audiences)
            raise HTTPException(status_code=401, detail="Token nao pertence a esta aplicacao")

    google_id = info["sub"]
    email = info.get("email", "")
    name = info.get("name", email.split("@")[0])
    avatar = info.get("picture")

    # Upsert: encontra por google_id ou por email
    user = session.exec(
        select(User).where(User.google_id == google_id)
    ).first()

    if not user:
        user = session.exec(select(User).where(User.email == email)).first()

    if user:
        # Actualiza dados do Google
        user.google_id = google_id
        user.avatar_url = avatar or user.avatar_url
        user.provider = "google"
    else:
        user = User(
            name=name,
            email=email,
            google_id=google_id,
            avatar_url=avatar,
            provider="google",
        )
        session.add(user)

    session.commit()
    session.refresh(user)

    token = _create_token(user.id)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> UserOut:
    """Devolve o utilizador autenticado."""
    return UserOut.model_validate(current_user)

