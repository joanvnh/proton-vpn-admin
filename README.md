# Proton VPN Admin

Administrador multi-cuenta de configuraciones WireGuard de Proton VPN, operado
como **Telegram Mini App**. Proyecto personal de joan.

## Arquitectura

```
Teléfono (Mini App en Telegram)  →  Cloudflare Worker  →  api.proton.me
https://joanvnh.github.io/           (valida initData,      (API oficial
proton-vpn-admin/                   guarda sesiones en     de Proton)
(frontend estático)                 KV, proxy sin CORS)
```

- **Toda la criptografía pesada (SRP, bcrypt, generación de claves) corre en el
  teléfono**, que no tiene límites de CPU. El Worker es un proxy delgado.
- Las **contraseñas nunca llegan al Worker**: se guardan cifradas (AES-GCM con
  llave derivada de un PIN vía PBKDF2) en el CloudStorage de Telegram.
- El Worker solo acepta peticiones firmadas por Telegram del usuario autorizado
  (`OWNER_ID`) y guarda **sesiones** de Proton en KV (~30 días, con refresh).

## Estructura

- `docs/` — Mini App estática (GitHub Pages). `js/srp.js` es un port de
  `ProtonMail/go-srp` (MIT), verificado contra sus vectores de prueba
  (`test/srp.test.mjs` + `test/srp_ref.py`).
- `worker/worker.js` — backend en un solo archivo (se puede pegar directo en el
  dashboard de Cloudflare). Requiere: KV `SESS`, secreto `BOT_TOKEN`,
  variables `OWNER_ID` y `PAGES_ORIGIN`.
- `worker/wrangler.toml` — referencia para despliegue con wrangler.

## Despliegue del Worker (dashboard)

1. Workers & Pages → Create Worker → pegar `worker/worker.js` → Deploy.
2. Settings → Variables: añadir KV namespace `SESS`, secreto `BOT_TOKEN`
   (token del bot de Telegram), variables `OWNER_ID` (`775842719`) y
   `PAGES_ORIGIN` (`https://joanvnh.github.io`).
3. Copiar la URL `https://<nombre>.<subdominio>.workers.dev` y ponerla en
   `docs/js/app.js` (`WORKER_URL`), hacer push.
4. En BotFather (o vía `setChatMenuButton`): botón de menú del bot →
   Web App → `https://joanvnh.github.io/proton-vpn-admin/`.

## Funciones

- Bóveda de cuentas (múltiples cuentas Proton, PIN local).
- Ver configuraciones WireGuard persistentes (nombre, servidor, expiración).
- Crear con todas las opciones de la web: país/servidor con % de carga,
  NetShield, Moderate NAT, Port forwarding, VPN Accelerator, duración.
- Descarga el `.conf` + código QR para la app WireGuard del teléfono.
- Eliminar configuraciones (requiere sesión con scope `full`).
- Soporta 2FA TOTP. No soporta: modo legacy de 2 contraseñas, FIDO2.

## Notas de seguridad

- Nada de secretos en este repo. El token del bot vive solo como secreto del Worker.
- El login SRP verifica la prueba del servidor (`ServerProof`).
- Si Proton pide captcha (código 9001), hay que entrar una vez a
  `account.proton.me` y reintentar.
