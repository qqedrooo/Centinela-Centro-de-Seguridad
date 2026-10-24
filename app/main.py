import base64
import csv
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import sqlite3
import threading
import time
from io import StringIO
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "data" / "security_scanner.db"))
APP_SECRET = os.getenv("APP_SECRET", "")
FERNET_KEY = os.getenv("FERNET_KEY", "")
APP_ENV = os.getenv("APP_ENV", "development").lower()
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true" if APP_ENV == "production" else "false").lower() == "true"
ALLOWED_HOSTS = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if host.strip()]
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").lower()
AUTHORIZED_CIDRS = [
    ipaddress.ip_network(value.strip(), strict=False)
    for value in os.getenv("AUTHORIZED_CIDRS", "").split(",")
    if value.strip()
]
if len(APP_SECRET) < 32:
    raise RuntimeError("APP_SECRET must contain at least 32 characters")
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SECURE=true es obligatorio en producción")
if not AUTHORIZED_CIDRS:
    raise RuntimeError("AUTHORIZED_CIDRS debe definir la allowlist de redes autorizadas")
try:
    CIPHER = Fernet(FERNET_KEY.encode())
except Exception as exc:
    raise RuntimeError("FERNET_KEY must be a valid Fernet key") from exc

app = FastAPI(
    title="Escáner de Seguridad Autorizado",
    description="API defensiva para auditar únicamente redes y activos con autorización explícita.",
    version="1.0.0",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SCHEDULER_STOP = threading.Event()


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path not in {"/docs", "/openapi.json", "/redoc"}:
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            return Response("Solicitud CSRF no válida", status_code=403, media_type="application/json")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    )
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT,
                display_name TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS scopes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                cidr TEXT NOT NULL,
                label TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                UNIQUE(user_id, cidr),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                scope_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(scope_id) REFERENCES scopes(id)
            );
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                is_open INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
            );
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                scope_id INTEGER NOT NULL,
                interval_minutes INTEGER NOT NULL,
                ports TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                next_run_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(scope_id) REFERENCES scopes(id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                scan_id INTEGER,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "display_name" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
        if "role" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'auditor'")
        scope_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scopes)")}
        if "status" not in scope_columns:
            connection.execute("ALTER TABLE scopes ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        if ADMIN_EMAIL:
            connection.execute("UPDATE users SET role='admin' WHERE email=?", (ADMIN_EMAIL,))
        connection.execute(
            """CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY,
                theme TEXT NOT NULL DEFAULT 'light',
                notifications INTEGER NOT NULL DEFAULT 1,
                compact_mode INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )"""
        )


init_db()


def scheduled_scan_worker() -> None:
    while not SCHEDULER_STOP.wait(30):
        try:
            with db() as connection:
                due = connection.execute(
                    """SELECT scan_schedules.*, scopes.cidr, scopes.status
                       FROM scan_schedules JOIN scopes ON scopes.id=scan_schedules.scope_id
                       WHERE scan_schedules.enabled=1 AND scan_schedules.next_run_at<=?""",
                    (now(),),
                ).fetchall()
            for schedule in due:
                network = ipaddress.ip_network(schedule["cidr"])
                if schedule["status"] != "approved" or not is_authorized_network(network):
                    continue
                ports = [int(port) for port in schedule["ports"].split(",") if port]
                execute_scan(schedule["user_id"], schedule["scope_id"], ports, 300)
                next_run = (datetime.now(timezone.utc) + timedelta(minutes=schedule["interval_minutes"])).isoformat()
                with db() as connection:
                    connection.execute("UPDATE scan_schedules SET next_run_at=? WHERE id=?", (next_run, schedule["id"]))
        except (OSError, sqlite3.Error, ValueError):
            continue


@app.on_event("startup")
def start_scheduler() -> None:
    threading.Thread(target=scheduled_scan_worker, name="centinela-scheduler", daemon=True).start()


@app.on_event("shutdown")
def stop_scheduler() -> None:
    SCHEDULER_STOP.set()


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=8)


class RecoveryRequest(BaseModel):
    email: EmailStr


class ResetRequest(BaseModel):
    token: str = Field(min_length=32)
    password: str = Field(min_length=12, max_length=128)


class ScopeRequest(BaseModel):
    cidr: str
    label: str = Field(min_length=1, max_length=80)


class ScanRequest(BaseModel):
    scope_id: int
    ports: list[int] = Field(default=[22, 80, 443, 8080], max_length=16)
    timeout_ms: int = Field(default=300, ge=100, le=2000)


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class ProfileRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=60)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=12, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class SettingsRequest(BaseModel):
    theme: str = Field(default="light", pattern="^(light|dark|system)$")
    notifications: bool = True
    compact_mode: bool = False


class ScheduleRequest(BaseModel):
    scope_id: int
    interval_minutes: int = Field(ge=60, le=10080)
    ports: list[int] = Field(default=[22, 80, 443], max_length=16)
    enabled: bool = True


class RoleRequest(BaseModel):
    role: str = Field(pattern="^(admin|auditor|viewer)$")


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        _, salt_text, digest_text = stored.split("$")
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def digest(value: str) -> str:
    return hmac.new(APP_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def encrypt_secret(value: str) -> str:
    return "enc:" + CIPHER.encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    if not value.startswith("enc:"):
        return value
    return CIPHER.decrypt(value[4:].encode()).decode()


def is_authorized_network(network: ipaddress._BaseNetwork) -> bool:
    return any(network.subnet_of(allowed) for allowed in AUTHORIZED_CIDRS)


def is_safe_scan_address(address: ipaddress._BaseAddress) -> bool:
    return not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified)


def audit(user_id: int | None, action: str, details: str) -> None:
    with db() as connection:
        connection.execute(
            "INSERT INTO audit_log(user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (user_id, action, details[:500], now()),
        )


def require_role(*roles: str):
    def dependency(user: sqlite3.Row = Depends(current_user)) -> sqlite3.Row:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="No tienes permisos para esta operación")
        return user
    return dependency


def current_user(session: str | None = Cookie(default=None)) -> sqlite3.Row:
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Se requiere iniciar sesión")
    with db() as connection:
        row = connection.execute(
            """SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token_hash=? AND sessions.expires_at>?""",
            (digest(session), now()),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="La sesión no es válida o ha expirado")
    return row


def set_session(response: Response, user_id: int) -> None:
    token = secrets.token_urlsafe(48)
    with db() as connection:
        connection.execute(
            "INSERT INTO sessions VALUES (?, ?, ?)",
            (digest(token), user_id, (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()),
        )
    response.set_cookie(
        "session", token, httponly=True, secure=COOKIE_SECURE, samesite="strict",
        max_age=43200, path="/",
    )


@app.get("/security/csrf")
def csrf_token(response: Response):
    token = secrets.token_urlsafe(32)
    response.set_cookie("csrf_token", token, httponly=False, secure=COOKIE_SECURE, samesite="strict", max_age=43200, path="/")
    return {"csrf_token": token}


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Centinela | Centro de seguridad</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
:root{--ink:#172033;--muted:#718096;--line:#e7edf5;--blue:#356ae6;--cyan:#16b9b2;--bg:#f6f8fc;--card:#fff;--danger:#d94b65;--shadow:0 18px 45px #2b416b12}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px "DM Sans",sans-serif}
h1,h2,h3,strong{font-family:"Space Grotesk",sans-serif}h1{font-size:30px;margin:0 0 8px}h2{font-size:18px;margin:0 0 5px}h3{font-size:14px;margin:0 0 4px}
.hidden{display:none!important}.view{animation:fade .2s ease}.app{display:flex;min-height:100vh}.side{width:245px;background:#101a31;color:#b9c5dd;padding:28px 18px;flex-shrink:0}
.brand{display:flex;gap:10px;align-items:center;color:#fff;font-size:20px;margin:0 12px 44px}.brandmark{background:linear-gradient(135deg,#5f86ff,#16c8be);width:33px;height:33px;border-radius:10px;display:grid;place-items:center;color:#fff;font-weight:bold}
.nav{display:grid;gap:7px}.nav button{background:transparent;color:#aab8d2;text-align:left;padding:12px 14px;border:0;border-radius:9px;font:inherit;cursor:pointer}.nav button.active,.nav button:hover{background:#243354;color:#fff}
.side-note{position:absolute;bottom:25px;width:205px;padding:13px;border:1px solid #334261;border-radius:10px;font-size:12px;line-height:1.5;color:#9dacC6}
.content{width:min(1180px,100%);padding:28px 38px}.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px}.eyebrow{color:var(--blue);font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:1px}
.avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:#dce7ff;color:var(--blue);font-weight:700}.userbox{display:flex;align-items:center;gap:10px}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0}.stat,.card{background:var(--card);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}.stat{padding:19px}.stat-head{display:flex;justify-content:space-between;color:var(--muted);font-size:12px}.stat-value{font:700 27px "Space Grotesk";margin:13px 0 2px}.stat-icon{padding:8px;border-radius:9px;background:#e9f0ff;color:var(--blue)}
.layout{display:grid;grid-template-columns:1.35fr 1fr;gap:18px}.card{padding:22px}.card-head{display:flex;justify-content:space-between;align-items:start;margin-bottom:18px}.muted,small{color:var(--muted)}.badge{border-radius:99px;padding:5px 9px;font-size:11px;font-weight:700;background:#e5faf5;color:#138b75}
input,button,select{font:inherit}input,select{width:100%;padding:12px 13px;border:1px solid #d7e0ed;border-radius:9px;margin:6px 0 12px;outline:none;background:#fff;color:var(--ink)}input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 3px #356ae61a}
button.primary{width:100%;padding:12px;border:0;border-radius:9px;color:#fff;background:linear-gradient(100deg,#356ae6,#5a82ed);font-weight:700;cursor:pointer}button.primary:hover{filter:brightness(1.06)}button.link{border:0;background:transparent;color:var(--blue);cursor:pointer;padding:0}
.notice{padding:12px 15px;border-radius:10px;background:#eaf2ff;color:#315393;margin-bottom:18px}.error{background:#fff0f2;color:#ad3047}.success{background:#e9faf5;color:#147c69}
.auth-shell{min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 20% 20%,#dce8ff,transparent 35%),var(--bg)}.auth-card{width:min(930px,94%);display:grid;grid-template-columns:1fr 1fr;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 25px 70px #20396824}.auth-art{padding:55px;background:linear-gradient(145deg,#142243,#315ec7);color:#fff}.auth-art h1{font-size:38px;margin-top:80px}.auth-form{padding:42px}.tabs{display:flex;gap:20px;border-bottom:1px solid var(--line);margin-bottom:22px}.tab{padding:10px 0;border:0;background:none;color:var(--muted);cursor:pointer}.tab.active{color:var(--blue);border-bottom:2px solid var(--blue);font-weight:700}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 7px;border-bottom:1px solid var(--line);font-size:13px}th{color:var(--muted);font-size:11px;text-transform:uppercase}.open{color:#109276;font-weight:700}.closed{color:var(--muted)}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #ffffff66;border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;vertical-align:-2px}@keyframes spin{to{transform:rotate(360deg)}}
.profile-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.profile-box{padding:15px;border-radius:11px;background:#f8faff;border:1px solid var(--line)}.switch{display:flex;align-items:center;gap:10px;margin:13px 0;color:var(--ink)}.switch input{width:18px;margin:0}.dark-theme{--ink:#e8eefb;--muted:#9eacc5;--line:#2d3a55;--bg:#101a2e;--card:#17233b}.dark-theme .side{background:#0a1223}.dark-theme input,.dark-theme .profile-box{background:#111d33;color:var(--ink);border-color:#34445f}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
@media(max-width:800px){.side{display:none}.content{padding:22px 16px}.cards,.layout{grid-template-columns:1fr}.auth-card{grid-template-columns:1fr}.auth-art{display:none}}
@media(max-width:600px){.profile-grid{grid-template-columns:1fr}}
</style></head>
<body>
<div id="auth" class="auth-shell"><div class="auth-card"><div class="auth-art"><div class="brand"><span class="brandmark">✦</span>Centinela</div><h1>Protege lo que importa.</h1><p>Supervisa tu infraestructura con claridad, control y autorización.</p><p style="margin-top:50px;color:#bfd0ff">✓ Escaneos no destructivos<br>✓ Sesiones protegidas<br>✓ Auditoría de actividad</p></div><div class="auth-form">
<div class="tabs"><button class="tab active" data-tab="login">Iniciar sesión</button><button class="tab" data-tab="register">Crear cuenta</button></div>
<div id="auth-message" class="notice">Accede para gestionar tus alcances autorizados.</div>
<form id="login"><label>Correo electrónico</label><input name="email" type="email" placeholder="Escribe tu correo" required><label>Contraseña</label><input name="password" type="password" placeholder="Tu contraseña" required><label>Código MFA <span class="muted">(opcional)</span></label><input name="mfa_code" placeholder="Código de autenticación"><button class="primary">Entrar de forma segura</button></form>
<form id="register" class="hidden"><label>Correo electrónico</label><input name="email" type="email" placeholder="Escribe tu correo" required><label>Contraseña</label><input name="password" type="password" placeholder="12 caracteres como mínimo" minlength="12" required><button class="primary">Crear mi cuenta</button></form>
<p style="margin-top:20px"><button id="recover-link" class="link">¿Olvidaste tu contraseña?</button></p><form id="recover" class="hidden"><label>Correo electrónico</label><input name="email" type="email" required><button class="primary">Enviar instrucciones</button></form>
</div></div></div>
<div id="panel" class="app hidden"><aside class="side"><div class="brand"><span class="brandmark">✦</span>Centinela</div><nav class="nav"><button class="active" data-view="summary">▦ &nbsp; Resumen</button><button data-view="scopes">◈ &nbsp; Alcances</button><button data-view="scan">⌁ &nbsp; Nuevo escaneo</button><button data-view="results">◉ &nbsp; Resultados</button><button data-view="history">◷ &nbsp; Historial</button><button data-view="inventory">▤ &nbsp; Inventario</button><button data-view="alerts">⚠ &nbsp; Alertas</button><button data-view="schedules">⟳ &nbsp; Programación</button><button data-view="profile">◎ &nbsp; Mi perfil</button><button data-view="settings">⚙ &nbsp; Configuración</button><button id="admin-nav" class="hidden" data-view="admin">♜ &nbsp; Administración</button></nav><div class="side-note">Usa esta herramienta solo sobre activos propios o con autorización documentada.</div></aside>
<main class="content"><div class="topbar"><div><div class="eyebrow">Centro de seguridad</div><h1 id="page-title">Resumen de auditoría</h1><span id="page-subtitle" class="muted">Supervisa tu infraestructura de forma responsable.</span></div><div class="userbox"><div><strong id="user">Usuario</strong><br><small>Sesión protegida</small></div><div id="avatar" class="avatar">U</div><button id="logout" class="link">Salir</button></div></div>
<div id="message" class="notice">Todo listo para comenzar.</div><section id="view-summary" class="view"><div class="cards"><div class="stat"><div class="stat-head"><span>Estado del sistema</span><span class="stat-icon">✓</span></div><div class="stat-value" style="color:#159579">Protegido</div><small>Conexión segura activa</small></div><div class="stat"><div class="stat-head"><span>Alcances autorizados</span><span class="stat-icon">◈</span></div><div id="scope-count" class="stat-value">0</div><small>Redes bajo tu control</small></div><div class="stat"><div class="stat-head"><span>Último análisis</span><span class="stat-icon">◷</span></div><div id="last-scan" class="stat-value">—</div><small>Sin análisis todavía</small></div></div><div class="card"><div class="card-head"><div><h2>Bienvenido a tu centro de seguridad</h2><span class="muted">Selecciona una sección en el menú para trabajar sin distracciones.</span></div><span class="badge">Protegido</span></div><p class="muted">Comienza autorizando una red propia. Después podrás iniciar un escaneo no destructivo y consultar sus resultados.</p></div></section>
<section id="view-scopes" class="view hidden"><section class="card" id="scope-card"><div class="card-head"><div><h2>Autorizar una red</h2><span class="muted">Define dónde puede trabajar el escáner.</span></div><span class="badge">Controlado</span></div><form id="scope"><label>Nombre del alcance</label><input name="label" placeholder="Oficina principal" required><label>Bloque de red (CIDR)</label><input name="cidr" placeholder="192.168.1.0/24" required><small>Máximo 256 direcciones. Se normaliza automáticamente.</small><br><button class="primary" style="margin-top:15px">+ Guardar alcance</button></form></section></section>
<section id="view-scan" class="view hidden"><section class="card"><div class="card-head"><div><h2>Nuevo escaneo</h2><span class="muted">Comprobación TCP no destructiva.</span></div><span class="badge">Seguro</span></div><form id="scan"><label>ID del alcance</label><input name="scope_id" type="number" placeholder="Ej. 1" required><label>Puertos a comprobar</label><input name="ports" value="22,80,443,8080" required><small>Separados por comas. Solo usa puertos necesarios.</small><br><button class="primary" style="margin-top:15px">Iniciar escaneo</button></form></section></section>
<section id="view-results" class="view hidden"><section class="card" id="results-card"><div class="card-head"><div><h2>Resultados recientes</h2><span class="muted">La información se muestra solo en esta sesión.</span></div><span class="badge">Solo lectura</span></div><div id="results"><span class="muted">Aún no hay resultados. Autoriza una red y ejecuta un escaneo.</span></div></section></section>
<section id="view-history" class="view hidden"><section class="card"><div class="card-head"><div><h2>Historial de análisis</h2><span class="muted">Consulta ejecuciones anteriores y descarga reportes.</span></div><span class="badge">Persistente</span></div><div id="history"><span class="muted">Todavía no hay análisis registrados.</span></div></section></section>
<section id="view-inventory" class="view hidden"><section class="card"><div class="card-head"><div><h2>Inventario de servicios</h2><span class="muted">Servicios abiertos vistos en tus análisis autorizados.</span></div><span class="badge">Actualizado por análisis</span></div><div id="inventory"><span class="muted">Aún no hay dispositivos registrados.</span></div></section></section>
<section id="view-alerts" class="view hidden"><section class="card"><div class="card-head"><div><h2>Alertas de seguridad</h2><span class="muted">Revisa exposiciones detectadas y márcalas como atendidas.</span></div><span class="badge">Monitoreo</span></div><div id="alerts"><span class="muted">No hay alertas.</span></div></section></section>
<section id="view-schedules" class="view hidden"><section class="card"><div class="card-head"><div><h2>Escaneos programados</h2><span class="muted">Intervalos controlados sobre alcances aprobados.</span></div><span class="badge">Mínimo 60 min</span></div><form id="schedule"><label>ID del alcance aprobado</label><input name="scope_id" type="number" required><label>Intervalo en minutos</label><input name="interval_minutes" type="number" min="60" max="10080" value="60" required><label>Puertos</label><input name="ports" value="22,80,443" required><button class="primary">Programar análisis</button></form><div id="schedules" style="margin-top:20px"><span class="muted">No hay programaciones.</span></div></section></section>
<section class="view card hidden" id="view-profile" style="margin-top:18px"><div class="card-head"><div><h2>Mi perfil</h2><span class="muted">Administra tu identidad y seguridad.</span></div><span id="mfa-badge" class="badge">MFA pendiente</span></div><div class="profile-grid"><div class="profile-box"><h3>Información personal</h3><form id="profile-form"><label>Nombre visible</label><input id="display-name" name="display_name" required minlength="2" maxlength="60"><label>Correo electrónico</label><input id="profile-email" disabled><button class="primary">Guardar cambios</button></form></div><div class="profile-box"><h3>Seguridad de la cuenta</h3><p class="muted">Cambia tu contraseña regularmente y activa MFA para proteger el acceso.</p><button id="mfa-setup" class="primary">Configurar MFA</button><form id="password-form" style="margin-top:16px"><input name="current_password" type="password" placeholder="Contraseña actual" required><input name="new_password" type="password" placeholder="Nueva contraseña" minlength="12" required><button class="primary">Cambiar contraseña</button></form></div></div></section>
<section class="view card hidden" id="view-settings" style="margin-top:18px"><div class="card-head"><div><h2>Configuración de la aplicación</h2><span class="muted">Personaliza tu experiencia en Centinela.</span></div><span class="badge">Guardado en tu cuenta</span></div><form id="settings-form"><div class="profile-grid"><div class="profile-box"><h3>Apariencia</h3><label>Tema</label><select id="theme" name="theme"><option value="light">Claro</option><option value="dark">Oscuro</option><option value="system">Sistema</option></select><label class="switch"><input id="compact-mode" name="compact_mode" type="checkbox"> Modo compacto</label></div><div class="profile-box"><h3>Notificaciones</h3><p class="muted">Controla los avisos sobre análisis y actividad de la cuenta.</p><label class="switch"><input id="notifications" name="notifications" type="checkbox"> Activar notificaciones</label></div></div><button class="primary" style="margin-top:18px">Guardar configuración</button></form></section>
<section class="view card hidden" id="view-admin" style="margin-top:18px"><div class="card-head"><div><h2>Administración</h2><span class="muted">Aprueba alcances, gestiona roles y revisa actividad.</span></div><span class="badge">Solo administradores</span></div><h3>Solicitudes de alcance</h3><div id="admin-scopes"><span class="muted">Cargando solicitudes...</span></div><h3 style="margin-top:24px">Usuarios y permisos</h3><div id="admin-users"><span class="muted">Cargando usuarios...</span></div></section>
</main></div>
<script>
const $=s=>document.querySelector(s), msg=(text,error=false,target='#message')=>{$(target).textContent=text;$(target).className=error?'notice error':'notice '+(target==='#message'?'':'success')};
let csrfToken=''; fetch('/security/csrf',{credentials:'same-origin'}).then(r=>r.json()).then(d=>{csrfToken=d.csrf_token});
async function api(url,options={}){const headers={'Content-Type':'application/json',...(options.headers||{})};if(options.method&&options.method!=='GET'&&csrfToken)headers['X-CSRF-Token']=csrfToken;const r=await fetch(url,{credentials:'same-origin',...options,headers});let data={};try{data=await r.json()}catch{}if(!r.ok)throw Error(data.detail||'La operación no pudo completarse');return data}
const dataOf=form=>Object.fromEntries(new FormData(form)), setBusy=(form,busy)=>{const b=form.querySelector('button[type=submit],button:not(.link)');if(b){if(!b.dataset.text)b.dataset.text=b.innerHTML;b.disabled=busy;b.innerHTML=busy?'<span class="spinner"></span> Procesando...':b.dataset.text}};
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');$('#login').classList.toggle('hidden',t.dataset.tab!=='login');$('#register').classList.toggle('hidden',t.dataset.tab!=='register');$('#recover').classList.add('hidden')});
$('#recover-link').onclick=()=>{$('#login').classList.add('hidden');$('#register').classList.add('hidden');$('#recover').classList.remove('hidden');$('#auth-message').textContent='Te enviaremos instrucciones si la cuenta existe.'};
$('#register').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{let d=await api('/auth/register',{method:'POST',body:JSON.stringify(dataOf(e.target))});$('#auth-message').textContent=d.message+' Ya puedes iniciar sesión.';document.querySelector('[data-tab=login]').click()}catch(x){$('#auth-message').textContent=x.message;$('#auth-message').className='notice error'}finally{setBusy(e.target,false)}};
$('#login').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{await api('/auth/login',{method:'POST',body:JSON.stringify(dataOf(e.target))});$('#auth').classList.add('hidden');$('#panel').classList.remove('hidden');await loadProfile();await loadScopes();await loadHistory();await loadInventory();await loadAlerts();await loadSchedules()}catch(x){$('#auth-message').textContent=x.message;$('#auth-message').className='notice error'}finally{setBusy(e.target,false)}};
$('#recover').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{let d=await api('/auth/recover',{method:'POST',body:JSON.stringify(dataOf(e.target))});$('#auth-message').textContent=d.message;$('#auth-message').className='notice success'}catch(x){$('#auth-message').textContent=x.message;$('#auth-message').className='notice error'}finally{setBusy(e.target,false)}};
async function loadScopes(){try{let d=await api('/scopes');$('#scope-count').textContent=d.scopes.length;window.scopes=d.scopes}catch{}}
async function loadHistory(){try{let d=await api('/scans/history');$('#history').innerHTML=d.scans.length?'<table><tr><th>ID</th><th>Alcance</th><th>Estado</th><th>Fecha</th><th>Reporte</th></tr>'+d.scans.map(x=>`<tr><td>#${x.id}</td><td>${x.label} <small>${x.cidr}</small></td><td><span class="badge">${x.status}</span></td><td>${new Date(x.created_at).toLocaleString('es-ES')}</td><td><a href="/scans/${x.id}/report.csv" target="_blank">CSV</a></td></tr>`).join('')+'</table>':'<span class="muted">Todavía no hay análisis registrados.</span>'}catch(x){$('#history').textContent=x.message}}
async function loadInventory(){try{let d=await api('/inventory');$('#inventory').innerHTML=d.inventory.length?'<table><tr><th>Dirección</th><th>Puerto</th><th>Latencia</th><th>Último avistamiento</th></tr>'+d.inventory.map(x=>`<tr><td>${x.address}</td><td class="open">${x.port}</td><td>${x.latency_ms} ms</td><td>${new Date(x.last_seen).toLocaleString('es-ES')}</td></tr>`).join('')+'</table>':'<span class="muted">Aún no hay servicios registrados.</span>'}catch(x){$('#inventory').textContent=x.message}}
async function loadAlerts(){try{let d=await api('/alerts');$('#alerts').innerHTML=d.alerts.length?'<table><tr><th>Severidad</th><th>Alerta</th><th>Detalle</th><th>Acción</th></tr>'+d.alerts.map(x=>`<tr><td><span class="badge">${x.severity}</span></td><td>${x.title}</td><td>${x.details}</td><td>${x.acknowledged?'Atendida':`<button class="link ack" data-id="${x.id}">Marcar atendida</button>`}</td></tr>`).join('')+'</table>':'<span class="muted">No hay alertas.</span>';document.querySelectorAll('.ack').forEach(b=>b.onclick=async()=>{await api('/alerts/'+b.dataset.id+'/acknowledge',{method:'POST'});loadAlerts()})}catch(x){$('#alerts').textContent=x.message}}
async function loadSchedules(){try{let d=await api('/schedules');$('#schedules').innerHTML=d.schedules.length?'<table><tr><th>Alcance</th><th>Intervalo</th><th>Próxima ejecución</th></tr>'+d.schedules.map(x=>`<tr><td>${x.label}</td><td>${x.interval_minutes} min</td><td>${new Date(x.next_run_at).toLocaleString('es-ES')}</td></tr>`).join('')+'</table>':'<span class="muted">No hay programaciones.</span>'}catch(x){$('#schedules').textContent=x.message}}
async function loadAdmin(){try{let d=await api('/admin/scopes');$('#admin-scopes').innerHTML=d.scopes.length?'<table><tr><th>Alcance</th><th>Usuario</th><th>Estado</th><th>Acción</th></tr>'+d.scopes.map(x=>`<tr><td>${x.label}<br><small>${x.cidr}</small></td><td>${x.email}</td><td>${x.status}</td><td>${x.status==='pending'?`<button class="link approve" data-id="${x.id}">Aprobar</button>`:'✓ Aprobado'}</td></tr>`).join('')+'</table>':'<span class="muted">No hay solicitudes pendientes.</span>';document.querySelectorAll('.approve').forEach(b=>b.onclick=async()=>{await api('/admin/scopes/'+b.dataset.id+'/approve',{method:'POST'});loadAdmin()});let users=await api('/admin/users');$('#admin-users').innerHTML='<table><tr><th>Correo</th><th>Rol</th><th>Acción</th></tr>'+users.users.map(x=>`<tr><td>${x.email}</td><td>${x.role}</td><td><select class="role-select" data-id="${x.id}"><option ${x.role==='admin'?'selected':''}>admin</option><option ${x.role==='auditor'?'selected':''}>auditor</option><option ${x.role==='viewer'?'selected':''}>viewer</option></select></td></tr>`).join('')+'</table>';document.querySelectorAll('.role-select').forEach(s=>s.onchange=async()=>{await api('/admin/users/'+s.dataset.id+'/role',{method:'PATCH',body:JSON.stringify({role:s.value})});msg('Rol actualizado')})}catch(x){$('#admin-scopes').textContent=x.message}}
async function loadProfile(){let p=await api('/profile');$('#display-name').value=p.display_name;$('#profile-email').value=p.email;$('#user').textContent=p.display_name;$('#avatar').textContent=p.display_name[0].toUpperCase();$('#mfa-badge').textContent=p.mfa_enabled?'MFA activo':'MFA pendiente';$('#mfa-badge').style.background=p.mfa_enabled?'#e5faf5':'#fff3d6';$('#mfa-badge').style.color=p.mfa_enabled?'#138b75':'#a16a00';$('#theme').value=p.settings.theme;$('#notifications').checked=p.settings.notifications;$('#compact-mode').checked=p.settings.compact_mode;$('#admin-nav').classList.toggle('hidden',p.role!=='admin');if(p.role==='admin')loadAdmin();applyTheme(p.settings.theme)}
function applyTheme(theme){const dark=theme==='dark'||(theme==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.body.classList.toggle('dark-theme',dark)}
$('#scope').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{let d=await api('/scopes',{method:'POST',body:JSON.stringify(dataOf(e.target))});msg('Alcance guardado: '+d.cidr+'. Su ID es el siguiente disponible.');e.target.reset();await loadScopes()}catch(x){msg(x.message,true)}finally{setBusy(e.target,false)}};
$('#scan').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{let d=dataOf(e.target);d.scope_id=Number(d.scope_id);d.ports=d.ports.split(',').map(Number);let r=await api('/scans',{method:'POST',body:JSON.stringify(d)});$('#last-scan').textContent=new Date().toLocaleTimeString('es-ES',{hour:'2-digit',minute:'2-digit'});$('#results').innerHTML='<table><tr><th>Dirección</th><th>Puerto</th><th>Estado</th><th>Latencia</th></tr>'+r.results.map(x=>`<tr><td><strong>${x.address}</strong></td><td>${x.port}</td><td class="${x.open?'open':'closed'}">${x.open?'● Abierto':'○ Cerrado'}</td><td>${x.latency_ms} ms</td></tr>`).join('')+'</table>';await loadHistory();await loadInventory();await loadAlerts();msg('Escaneo completado correctamente.')}catch(x){msg(x.message,true)}finally{setBusy(e.target,false)}};
$('#schedule').onsubmit=async e=>{e.preventDefault();setBusy(e.target,true);try{let d=dataOf(e.target);d.scope_id=Number(d.scope_id);d.interval_minutes=Number(d.interval_minutes);d.ports=d.ports.split(',').map(Number);await api('/schedules',{method:'POST',body:JSON.stringify(d)});await loadSchedules();msg('Análisis programado correctamente.')}catch(x){msg(x.message,true)}finally{setBusy(e.target,false)}};
$('#profile-form').onsubmit=async e=>{e.preventDefault();try{let d=await api('/profile',{method:'PATCH',body:JSON.stringify(dataOf(e.target))});$('#user').textContent=d.display_name;$('#avatar').textContent=d.display_name[0].toUpperCase();msg(d.message)}catch(x){msg(x.message,true)}};
$('#password-form').onsubmit=async e=>{e.preventDefault();try{let d=await api('/profile/password',{method:'POST',body:JSON.stringify(dataOf(e.target))});msg(d.message);e.target.reset();setTimeout(()=>location.reload(),900)}catch(x){msg(x.message,true)}};
$('#settings-form').onsubmit=async e=>{e.preventDefault();try{let d=dataOf(e.target);d.notifications=$('#notifications').checked;d.compact_mode=$('#compact-mode').checked;let r=await api('/settings',{method:'PUT',body:JSON.stringify(d)});applyTheme(d.theme);msg(r.message)}catch(x){msg(x.message,true)}};
$('#mfa-setup').onclick=async()=>{try{let d=await api('/auth/mfa/setup',{method:'POST'});msg('MFA creado. Guarda este secreto en tu aplicación autenticadora: '+d.secret);$('#mfa-badge').textContent='MFA activo'}catch(x){msg(x.message,true)}};
function showView(name){document.querySelectorAll('.view').forEach(view=>view.classList.toggle('hidden',view.id!=='view-'+name));document.querySelectorAll('.nav button[data-view]').forEach(button=>button.classList.toggle('active',button.dataset.view===name));const titles={summary:['Resumen de auditoría','Supervisa tu infraestructura de forma responsable.'],scopes:['Alcances autorizados','Define las redes que puedes auditar.'],scan:['Nuevo escaneo','Realiza una comprobación TCP no destructiva.'],results:['Resultados recientes','Consulta la actividad de tus análisis.'],history:['Historial de análisis','Consulta ejecuciones anteriores y descarga reportes.'],inventory:['Inventario','Servicios abiertos detectados en tus análisis.'],alerts:['Alertas','Revisa exposiciones y riesgos detectados.'],schedules:['Programación','Configura análisis periódicos controlados.'],profile:['Mi perfil','Administra tu identidad y seguridad.'],settings:['Configuración','Personaliza tu experiencia en Centinela.'],admin:['Administración','Aprueba alcances y revisa la actividad del sistema.']};$('#page-title').textContent=titles[name][0];$('#page-subtitle').textContent=titles[name][1]}
document.querySelectorAll('.nav button[data-view]').forEach(button=>button.onclick=()=>{showView(button.dataset.view);window.scrollTo({top:0,behavior:'smooth'})});
$('#logout').onclick=async()=>{await api('/auth/logout',{method:'POST'});location.reload()};showView('summary');
</script></body></html>"""


@app.post("/auth/register")
def register(credentials: Credentials):
    with db() as connection:
        try:
            cursor = connection.execute(
                "INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
                (
                    credentials.email.lower(),
                    password_hash(credentials.password),
                    "admin" if credentials.email.lower() == ADMIN_EMAIL else "auditor",
                    now(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="El correo electrónico ya está registrado") from exc
    audit(cursor.lastrowid, "register", "cuenta creada")
    return {"ok": True, "message": "Cuenta creada correctamente"}


@app.post("/auth/login")
def login(credentials: Credentials):
    with db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email=?", (credentials.email.lower(),)).fetchone()
    if not user or not password_matches(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Las credenciales no son válidas")
    mfa_secret = decrypt_secret(user["mfa_secret"]) if user["mfa_secret"] else None
    if mfa_secret and (not credentials.mfa_code or not pyotp.TOTP(mfa_secret).verify(credentials.mfa_code)):
        raise HTTPException(status_code=401, detail="Se requiere un código MFA válido")
    response = HTMLResponse('{"ok":true}', media_type="application/json")
    set_session(response, user["id"])
    audit(user["id"], "login", "inicio de sesión correcto")
    return response


@app.get("/profile")
def profile(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        settings = connection.execute("SELECT * FROM user_settings WHERE user_id=?", (user["id"],)).fetchone()
        if not settings:
            connection.execute("INSERT INTO user_settings(user_id) VALUES(?)", (user["id"],))
            settings = connection.execute("SELECT * FROM user_settings WHERE user_id=?", (user["id"],)).fetchone()
    return {
        "email": user["email"],
        "display_name": user["display_name"] or user["email"].split("@")[0],
        "role": user["role"],
        "created_at": user["created_at"],
        "mfa_enabled": bool(user["mfa_secret"]),
        "settings": {
            "theme": settings["theme"],
            "notifications": bool(settings["notifications"]),
            "compact_mode": bool(settings["compact_mode"]),
        },
    }


@app.patch("/profile")
def update_profile(request: ProfileRequest, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        connection.execute("UPDATE users SET display_name=? WHERE id=?", (request.display_name.strip(), user["id"]))
    audit(user["id"], "profile_updated", "nombre visible actualizado")
    return {"ok": True, "message": "Perfil actualizado correctamente", "display_name": request.display_name.strip()}


@app.post("/profile/password")
def change_password(request: PasswordChangeRequest, user: sqlite3.Row = Depends(current_user)):
    if not password_matches(request.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="La contraseña actual no es válida")
    if request.current_password == request.new_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser diferente")
    with db() as connection:
        connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(request.new_password), user["id"]))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    audit(user["id"], "password_changed", "contraseña actualizada y sesiones revocadas")
    return {"ok": True, "message": "Contraseña actualizada. Inicia sesión de nuevo."}


@app.get("/settings")
def get_settings(user: sqlite3.Row = Depends(current_user)):
    return profile(user)["settings"]


@app.put("/settings")
def update_settings(request: SettingsRequest, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        connection.execute(
            """INSERT INTO user_settings(user_id, theme, notifications, compact_mode) VALUES(?,?,?,?)
               ON CONFLICT(user_id) DO UPDATE SET theme=excluded.theme,
               notifications=excluded.notifications, compact_mode=excluded.compact_mode""",
            (user["id"], request.theme, int(request.notifications), int(request.compact_mode)),
        )
    audit(user["id"], "settings_updated", f"theme={request.theme}")
    return {"ok": True, "message": "Configuración guardada"}


@app.post("/auth/logout")
def logout(session: str | None = Cookie(default=None)):
    response = HTMLResponse('{"ok":true}', media_type="application/json")
    if session:
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (digest(session),))
    response.delete_cookie("session")
    return response


@app.post("/auth/recover")
def recover(request: RecoveryRequest):
    with db() as connection:
        user = connection.execute("SELECT id FROM users WHERE email=?", (request.email.lower(),)).fetchone()
        if user:
            raw = secrets.token_urlsafe(48)
            connection.execute(
                "INSERT INTO reset_tokens VALUES (?, ?, ?, 0)",
                (digest(raw), user["id"], (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()),
            )
    # Production deployments must deliver this through an email provider; never log the token.
    return {"ok": True, "message": "Si la cuenta existe, se enviaron instrucciones de recuperación"}


@app.post("/auth/reset")
def reset(request: ResetRequest):
    with db() as connection:
        token = connection.execute(
            "SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 AND expires_at>?",
            (digest(request.token), now()),
        ).fetchone()
        if not token:
            raise HTTPException(status_code=400, detail="El token de recuperación no es válido o ha expirado")
        connection.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(request.password), token["user_id"]))
        connection.execute("UPDATE reset_tokens SET used=1 WHERE token_hash=?", (token["token_hash"],))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (token["user_id"],))
    audit(token["user_id"], "password_reset", "contraseña cambiada y sesiones revocadas")
    return {"ok": True, "message": "Contraseña actualizada correctamente"}


@app.post("/auth/mfa/setup")
def setup_mfa(user: sqlite3.Row = Depends(current_user)):
    secret = pyotp.random_base32()
    with db() as connection:
        connection.execute("UPDATE users SET mfa_secret=? WHERE id=?", (encrypt_secret(secret), user["id"]))
    audit(user["id"], "mfa_setup", "secreto MFA renovado")
    return {
        "secret": secret,
        "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="Authorized Security Scanner"),
        "message": "Añade este secreto a una aplicación autenticadora y verifícalo en /auth/mfa/verify",
    }


@app.post("/auth/mfa/verify")
def verify_mfa(request: MfaCode, user: sqlite3.Row = Depends(current_user)):
    secret = decrypt_secret(user["mfa_secret"]) if user["mfa_secret"] else None
    if not secret or not pyotp.TOTP(secret).verify(request.code):
        raise HTTPException(status_code=400, detail="El código MFA no es válido")
    audit(user["id"], "mfa_verified", "código MFA verificado")
    return {"ok": True, "message": "MFA verificado correctamente"}


@app.post("/scopes")
def add_scope(request: ScopeRequest, user: sqlite3.Row = Depends(require_role("admin", "auditor"))):
    try:
        network = ipaddress.ip_network(request.cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="El bloque CIDR no es válido") from exc
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="El alcance es demasiado grande; el máximo es de 256 direcciones")
    if not is_authorized_network(network):
        raise HTTPException(status_code=403, detail="La red no está en la allowlist administrativa")
    if any(not is_safe_scan_address(address) for address in network.hosts()):
        raise HTTPException(status_code=403, detail="El alcance contiene direcciones no permitidas")
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO scopes(user_id,cidr,label,status) VALUES(?,?,?,'pending')", (user["id"], str(network), request.label))
        scope = connection.execute("SELECT id, status FROM scopes WHERE user_id=? AND cidr=?", (user["id"], str(network))).fetchone()
    audit(user["id"], "scope_added", str(network))
    return {"ok": True, "scope_id": scope["id"], "cidr": str(network), "status": scope["status"]}


@app.get("/scopes")
def list_scopes(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        scopes = connection.execute(
            "SELECT id, cidr, label, status FROM scopes WHERE user_id=? ORDER BY id DESC", (user["id"],)
        ).fetchall()
    return {"scopes": [dict(scope) for scope in scopes]}


@app.get("/admin/scopes")
def admin_scopes(user: sqlite3.Row = Depends(require_role("admin"))):
    with db() as connection:
        scopes = connection.execute(
            """SELECT scopes.id, scopes.cidr, scopes.label, scopes.status, users.email
               FROM scopes JOIN users ON users.id=scopes.user_id ORDER BY scopes.id DESC"""
        ).fetchall()
    return {"scopes": [dict(scope) for scope in scopes]}


@app.post("/admin/scopes/{scope_id}/approve")
def approve_scope(scope_id: int, user: sqlite3.Row = Depends(require_role("admin"))):
    with db() as connection:
        cursor = connection.execute("UPDATE scopes SET status='approved' WHERE id=?", (scope_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Alcance no encontrado")
    audit(user["id"], "scope_approved", str(scope_id))
    return {"ok": True, "message": "Alcance aprobado"}


@app.get("/admin/audit")
def admin_audit(user: sqlite3.Row = Depends(require_role("admin"))):
    with db() as connection:
        events = connection.execute(
            "SELECT user_id, action, details, created_at FROM audit_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return {"events": [dict(event) for event in events]}


@app.get("/admin/users")
def admin_users(user: sqlite3.Row = Depends(require_role("admin"))):
    with db() as connection:
        users = connection.execute(
            "SELECT id, email, display_name, role, created_at FROM users ORDER BY id DESC"
        ).fetchall()
    return {"users": [dict(item) for item in users]}


@app.patch("/admin/users/{user_id}/role")
def update_user_role(user_id: int, request: RoleRequest, user: sqlite3.Row = Depends(require_role("admin"))):
    if user_id == user["id"] and request.role != "admin":
        raise HTTPException(status_code=400, detail="No puedes quitarte tu propio rol de administrador")
    with db() as connection:
        cursor = connection.execute("UPDATE users SET role=? WHERE id=?", (request.role, user_id))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    audit(user["id"], "user_role_updated", f"user={user_id} role={request.role}")
    return {"ok": True, "message": "Rol actualizado"}


@app.get("/scans/history")
def scan_history(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        runs = connection.execute(
            """SELECT scan_runs.id, scan_runs.status, scan_runs.created_at, scan_runs.completed_at,
                      scopes.cidr, scopes.label
               FROM scan_runs JOIN scopes ON scopes.id=scan_runs.scope_id
               WHERE scan_runs.user_id=? ORDER BY scan_runs.id DESC LIMIT 50""",
            (user["id"],),
        ).fetchall()
    return {"scans": [dict(run) for run in runs]}


@app.get("/scans/{scan_id}/report.csv")
def scan_report(scan_id: int, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        scan = connection.execute(
            "SELECT id FROM scan_runs WHERE id=? AND user_id=?", (scan_id, user["id"])
        ).fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Análisis no encontrado")
        rows = connection.execute(
            "SELECT address, port, is_open, latency_ms FROM scan_results WHERE scan_id=? ORDER BY address, port",
            (scan_id,),
        ).fetchall()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["direccion", "puerto", "estado", "latencia_ms"])
    writer.writerows(
        (row["address"], row["port"], "abierto" if row["is_open"] else "cerrado", row["latency_ms"])
        for row in rows
    )
    return PlainTextResponse(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="centinela-analisis-{scan_id}.csv"'},
    )


@app.post("/schedules")
def create_schedule(request: ScheduleRequest, user: sqlite3.Row = Depends(require_role("admin", "auditor"))):
    with db() as connection:
        scope = connection.execute(
            "SELECT id, status FROM scopes WHERE id=? AND user_id=?", (request.scope_id, user["id"])
        ).fetchone()
        if not scope or scope["status"] != "approved":
            raise HTTPException(status_code=400, detail="El alcance debe estar aprobado")
        if any(port < 1 or port > 65535 for port in request.ports):
            raise HTTPException(status_code=400, detail="El puerto no es válido")
        next_run = (datetime.now(timezone.utc) + timedelta(minutes=request.interval_minutes)).isoformat()
        cursor = connection.execute(
            """INSERT INTO scan_schedules(user_id,scope_id,interval_minutes,ports,enabled,next_run_at)
               VALUES(?,?,?,?,?,?)""",
            (user["id"], request.scope_id, request.interval_minutes, ",".join(map(str, sorted(set(request.ports)))), int(request.enabled), next_run),
        )
    audit(user["id"], "schedule_created", str(cursor.lastrowid))
    return {"ok": True, "schedule_id": cursor.lastrowid, "next_run_at": next_run}


@app.get("/schedules")
def list_schedules(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        schedules = connection.execute(
            """SELECT scan_schedules.id, scan_schedules.interval_minutes, scan_schedules.ports,
                      scan_schedules.enabled, scan_schedules.next_run_at, scopes.label, scopes.cidr
               FROM scan_schedules JOIN scopes ON scopes.id=scan_schedules.scope_id
               WHERE scan_schedules.user_id=? ORDER BY scan_schedules.id DESC""",
            (user["id"],),
        ).fetchall()
    return {"schedules": [dict(schedule) for schedule in schedules]}


@app.post("/schedules/run-due")
def run_due_schedules(user: sqlite3.Row = Depends(require_role("admin"))):
    with db() as connection:
        schedules = connection.execute(
            """SELECT scan_schedules.*, scopes.cidr, scopes.status
               FROM scan_schedules JOIN scopes ON scopes.id=scan_schedules.scope_id
               WHERE scan_schedules.enabled=1 AND scan_schedules.next_run_at<=?""",
            (now(),),
        ).fetchall()
    executed = []
    for schedule in schedules:
        if schedule["status"] != "approved" or not is_authorized_network(ipaddress.ip_network(schedule["cidr"])):
            continue
        ports = [int(port) for port in schedule["ports"].split(",") if port]
        result = execute_scan(user["id"], schedule["scope_id"], ports, 300)
        next_run = (datetime.now(timezone.utc) + timedelta(minutes=schedule["interval_minutes"])).isoformat()
        with db() as connection:
            connection.execute("UPDATE scan_schedules SET next_run_at=? WHERE id=?", (next_run, schedule["id"]))
        executed.append(result["scan_id"])
    audit(user["id"], "scheduled_scans_run", str(executed))
    return {"ok": True, "executed_scan_ids": executed}


@app.get("/inventory")
def inventory(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        items = connection.execute(
            """SELECT scan_results.address, scan_results.port, scan_results.latency_ms,
                      MAX(scan_runs.created_at) AS last_seen
               FROM scan_results JOIN scan_runs ON scan_runs.id=scan_results.scan_id
               WHERE scan_runs.user_id=? AND scan_results.is_open=1
               GROUP BY scan_results.address, scan_results.port
               ORDER BY last_seen DESC LIMIT 500""",
            (user["id"],),
        ).fetchall()
    return {"inventory": [dict(item) for item in items]}


@app.get("/alerts")
def alerts(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        rows = connection.execute(
            """SELECT id, scan_id, severity, title, details, acknowledged, created_at
               FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 100""",
            (user["id"],),
        ).fetchall()
    return {"alerts": [dict(row) for row in rows]}


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        cursor = connection.execute("UPDATE alerts SET acknowledged=1 WHERE id=? AND user_id=?", (alert_id, user["id"]))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    return {"ok": True}


@app.post("/scans")
def scan(request: ScanRequest, user: sqlite3.Row = Depends(require_role("admin", "auditor"))):
    ports = sorted(set(request.ports))
    if any(port < 1 or port > 65535 for port in ports):
        raise HTTPException(status_code=400, detail="El puerto no es válido")
    with db() as connection:
        scope = connection.execute("SELECT * FROM scopes WHERE id=? AND user_id=?", (request.scope_id, user["id"])).fetchone()
    if not scope or scope["status"] != "approved":
        raise HTTPException(status_code=404, detail="No se encontró el alcance autorizado")
    network = ipaddress.ip_network(scope["cidr"])
    if not is_authorized_network(network):
        raise HTTPException(status_code=403, detail="El alcance ya no está autorizado por la allowlist")
    return execute_scan(user["id"], scope["id"], ports, request.timeout_ms)


def execute_scan(user_id: int, scope_id: int, ports: list[int], timeout_ms: int) -> dict:
    with db() as connection:
        scope = connection.execute("SELECT * FROM scopes WHERE id=?", (scope_id,)).fetchone()
    if not scope or scope["status"] != "approved":
        raise HTTPException(status_code=404, detail="No se encontró el alcance autorizado")
    network = ipaddress.ip_network(scope["cidr"])
    if not is_authorized_network(network):
        raise HTTPException(status_code=403, detail="El alcance ya no está autorizado por la allowlist")
    results = []
    timeout = timeout_ms / 1000
    with db() as connection:
        scan_cursor = connection.execute(
            "INSERT INTO scan_runs(user_id,scope_id,status,created_at) VALUES(?,?,?,?)",
            (user_id, scope["id"], "running", now()),
        )
        scan_id = scan_cursor.lastrowid
    for address in network.hosts():
        if not is_safe_scan_address(address):
            continue
        for port in ports:
            started = time.monotonic()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                open_port = sock.connect_ex((str(address), port)) == 0
            finally:
                sock.close()
            latency = round((time.monotonic() - started) * 1000, 2)
            result = {"address": str(address), "port": port, "open": open_port, "latency_ms": latency}
            results.append(result)
            with db() as connection:
                connection.execute(
                    "INSERT INTO scan_results(scan_id,address,port,is_open,latency_ms) VALUES(?,?,?,?,?)",
                    (scan_id, str(address), port, int(open_port), latency),
                )
    with db() as connection:
        connection.execute("UPDATE scan_runs SET status='completed', completed_at=? WHERE id=?", (now(), scan_id))
        open_count = sum(1 for result in results if result["open"])
        if open_count:
            severity = "high" if any(result["port"] in {21, 23, 3389} for result in results if result["open"]) else "medium"
            connection.execute(
                """INSERT INTO alerts(user_id,scan_id,severity,title,details,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    user_id,
                    scan_id,
                    severity,
                    "Servicios expuestos detectados",
                    f"Se detectaron {open_count} puertos abiertos en {scope['cidr']}",
                    now(),
                ),
            )
    audit(user_id, "authorized_scan", f"scope={scope['cidr']} ports={ports}")
    return {"scan_id": scan_id, "scope": scope["cidr"], "results": results}
