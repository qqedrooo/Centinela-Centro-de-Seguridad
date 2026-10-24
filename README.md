# Escáner de Seguridad Autorizado

Backend web defensivo en español con FastAPI. Incluye:

- Registro, inicio de sesión con cookies `HttpOnly` y contraseñas con `scrypt`.
- Recuperación con tokens de un solo uso, expiración de 20 minutos y revocación de sesiones.
- Cifrado preparado mediante Fernet para secretos que se agreguen al despliegue.
- Alcances explícitos por usuario en CIDR, con un límite de 256 direcciones.
- Escaneo TCP no destructivo y limitado al alcance registrado; no ejecuta comandos del sistema ni explota vulnerabilidades.
- Registro de auditoría.
- Inventario persistente de servicios abiertos detectados.
- Alertas de exposición y opción de marcarlas como atendidas.
- Historial de análisis y reportes CSV descargables.
- Roles `admin`, `auditor` y `viewer`, con aprobación administrativa de alcances.
- Escaneos programados desde 60 minutos hasta 7 días, ejecutados solo sobre alcances aprobados.
- Protección CSRF, cabeceras HTTP de seguridad y validación de hosts.
- Allowlist administrativa obligatoria para impedir escaneos arbitrarios.
- Cifrado Fernet de secretos MFA almacenados en la base de datos.
- Cookies `Secure` en producción y `SameSite=Strict`.

## Arranque

1. Copia `.env.example` a `.env`, genera secretos y configura `AUTHORIZED_CIDRS` con redes propias aprobadas. `.env` nunca debe compartirse. `FERNET_KEY` puede generarse con:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

2. Instala dependencias y arranca:

   ```powershell
   python -m pip install -r requirements.txt
   python -m uvicorn app.main:app --reload --env-file .env
   ```

3. Abre `http://127.0.0.1:8000/docs`. La interfaz interactiva de la API mostrará el título y la descripción en español.

En producción usa HTTPS, `APP_ENV=production`, `COOKIE_SECURE=true`, un proveedor de correo transaccional para recuperación, secretos fuera del repositorio, MFA obligatorio y una allowlist administrada por un responsable de seguridad. Solo escanea activos propios o con autorización documentada. El sistema no ofrece seguridad absoluta: debe desplegarse detrás de un proxy TLS actualizado, con copias de seguridad protegidas, rotación de claves y monitorización.

Los escaneos programados se comprueban cada 30 segundos por un trabajador interno y respetan la allowlist, la aprobación del alcance y los límites de puertos. Para una instalación distribuida se recomienda mover esta tarea a un worker dedicado con cola persistente.
