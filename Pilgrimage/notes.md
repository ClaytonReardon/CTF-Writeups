10.129.239.70



## Flags
User.txt
dc00f0102821a60b8131b1472bf28ce7
Root.txt
a2ab5f4e888627538e74fb3d1d8fae1e

## Creds
emily:abigchonkyboi123


## Tech

## Info

#
Nmaop finds `.git` directory at pilgrimage/.git. Used git-dumper to grab it

# Possible SSRF
Image generates a link based on the url. Could be used for SSRF?
http://pilgrimage.htb/?message=http://10.10.14.72&status=success

# ImageMagick 7.1.0-49 CVE
In the git directory was a `magick` file. From this I was able to run `./magic -version` to get the version in use: 7.1.0-49. Searching for this I find a [CVE](https://nvd.nist.gov/vuln/detail/CVE-2022-44268) for information disclosure. Here is the [blogpost.](https://www.metabaseq.com/imagemagick-zero-days/) Here is the github [POC](https://github.com/voidz0r/CVE-2022-44268)

# Emily SSH Password
Now that I have file disclosure, I look around for some files that may be juicy. Looking through the source code from the `.git` repository, I see that the site is using an sqlite database located at `/var/db/pilgrimage` I decide to grab this file. It works and I decode it. I get a big old jumble of hex. Luckily I don't have to decode it any further. Just scrolling through it I see the line `plus1059password\x18\x01\x03\x17-emily--------------`(password redacted). I know that the creds I used are plus1059:password, so it's a fair assumption that these are emily's creds. From reading `etc/passwd` I know that emily Is a user on he box. Perhaps there's password reuse. I try to login to SSH with these creds, and it works!

# Binwalk Exploit -> Root
**Lessons Learned: ENUMERATE *EVERYTHING***
Pspy shows a script running constantly in the background as root called `/usr/sbin/malwarescanner.sh` Basically it monitors new files getting created in `/var/www/pilgrimage.htb/shrunk` and runs `binwalk` on them. 

Now, I thought the exploit here was command inejction. Since the `$filename` variable can be controlled by me, I thought I needed to create a filename that when it got passed to the `binwalk` command, would terminate the `binwalk` and then run my own command. I kept trying to create files with names along the lines of `; curl 10.10.14.72`. This is **NOT** the exploit.
 
The exploit is actually in `binwalk` itself. There's a fairly recent [CVE](https://portswigger.net/daily-swig/serious-security-hole-plugged-in-infosec-tool-binwalk) found in binwalk. I actually need to create a malicious file that when it gets passed to binwalk, will give me command execution. This can be done very simply using [this Github POC](https://github.com/electr0sm0g/CVE-2022-4510)

[This is a blogpost](https://portswigger.net/daily-swig/serious-security-hole-plugged-in-infosec-tool-binwalk) from Portswigger discussing the vuln and how it works.

The vuln comes from back in 2017 when the PFS extractor plugin was merged with binwalk. There was an attempt to mitigate path traversal by using `os.path.join` but this did not work. By creating a `PFS` filesystem with `../` in the name, binwalk can write files outside of the current directory. The exploit works by crafting a binwalk plugin. Binwalk will immediately load and execute this plugin once it's created. So we can createa  plugin to, for example, send a root shell to us. 