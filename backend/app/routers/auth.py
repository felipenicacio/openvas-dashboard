from fastapi import APIRouter, HTTPException, status
from ..models.schemas import LoginRequest, TokenResponse
from ..auth import create_token
from ..config import get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


@router.post("/token", response_model=TokenResponse)
async def login(body: LoginRequest):
    if body.username != settings.app_username or body.password != settings.app_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas.",
        )
    return TokenResponse(access_token=create_token(body.username))
