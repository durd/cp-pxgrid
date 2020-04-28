# cp-pxgrid
- [cp-pxgrid](#cp-pxgrid)
  * [Overview](#overview)
  * [Installation](#Installation)
  * [Why?](#why)
  * [Project implementation](#project-implementation)
    + [session_subscribe.cp.py](#session_subscribecppy)
    + [session_query_all.cp.py](#session_query_allcppy)
    + [session_query_reboot.cp.py](#session_query_rebootcppy)
    + [Firewall reload](#firewall-reload)
    + [cp-pxgrid High Availablity](#cp-pxgrid-high-availablity)
    + [Logging](#logging)
  * [Shortcomings](#shortcomings)
    + [pxGrid](#pxgrid)
    + [Check Point](#check-point)
    + [Me](#me)
- [Credit](#credit)
- [pxGrid](#pxgrid-1)

## Overview
cp-pxgrid is a client implementation of Cisco's [pxGrid](https://developer.cisco.com/docs/pxgrid/#!learning-pxgrid) Security Product Integration Framework (SPIF) that subscribes and reads from pxGrid and sends in this project, via [Identity Awareness API](https://sc1.checkpoint.com/documents/R80.30/WebAdminGuides/EN/CP_R80.30_IdentityAwareness_AdminGuide/html_frameset.htm?topic=documents/R80.30/WebAdminGuides/EN/CP_R80.30_IdentityAwareness_AdminGuide/151008) identity information to Check Point firewalls. This is done so that user or machine identities from Cisco ISE can be used in firewall rules using Check Point [Identity Awareness](https://www.checkpoint.com/products/identity-awareness/).

pxGrid runs primarily on [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) but all manner of products can publish data to pxGrid that is then spread to other subscribers. pxGrid uses [STOMP](http://stomp.github.io/) as a message broker much like [MQTT](https://en.wikipedia.org/wiki/MQTT). [WebSockets](https://en.wikipedia.org/wiki/WebSocket) can be used to create an low-overhead communication channel for streaming STOMP data.

In the larger scheme of things, [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) is primarily used on networks implementing [802.1x](https://en.wikipedia.org/wiki/IEEE_802.1X) with [RADIUS](https://en.wikipedia.org/wiki/RADIUS) as the authentication, authorization and accounting protocol of choice.

## Installation
### Requirements
* Python 3.6 or later
* Python module requirements via `pip3`

It's almost simple, lots of steps though. All this on a fresh Debian 10.3.
* [Generate](https://github.com/durd/cp-pxgrid/wiki/To-Generate-pxGrid-Certificates-from-ISE) your pxGrid certificate from ISE. **Important!**
* `scp` the zip-file to your server.
```console
user@host:~$ unzip <zip-file> -d pxgrid-cert
user@host:~$ git clone https://github.com/durd/cp-pxgrid.git
user@host:~$ cd cp-pxgrid
cp-pxgrid $ pip3 install -r requirements
cp-pxgrid $ mkdir /usr/local/cp-pxgrid
cp-pxgrid $ cp python/ /usr/local/cp-pxgrid/
cp-pxgrid $ cd /usr/local/cp-pxgrid/
user@host:/usr/local/cp-pxgrid $ cp ~/pxgrid-cert .
user@host:/usr/local/cp-pxgrid $ cd pxgrid-cert
# This will remove the password you set in ISE, so that we can run the script as a daemon/service.
# The other option is to have the password in plain text in the service. Not much better.
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ openssl rsa -in <private key> -out <private key.1>
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ rm <private key>
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ mv <private key>.1 <private key>
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ chmod 644 <private key>
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ cd ..
```
Before proceeding, make sure you have added your host to your Checkpoints gateways allowed hosts for Identity Web API and saved the PSK. Also make sure you allow traffic to the gate. What's it called properly??????
```console
user@host:/usr/local/cp-pxgrid $ cp gwconfig.py.example gwconfig.py
# Open gwconfig.py with your favourite editor.
# Add the HA/VIP-address of your gateway and PSK for it and save and exit the editor
user@host:/usr/local/cp-pxgrid/pxgrid-cert $ cd ~/cp-pxgrid
user@host:cp-pxgrid $ cp cp-pxgrid.logrotate /etc/logrotate.d/cp-pxgrid
user@host:cp-pxgrid $ cp cp-pxgrid.rsyslogd.conf /etc/rsyslog.d/cp-pxgrid.conf
# Edit all *.service files to fit your setup regarding ISE hostnames, nodenames, paths, and filenames of certificates and keys.
# The `.timer` file references a `.service` file, make sure it still corresponds! # Else the bulkdl-script will not execute and sessions will time out on the firewall.
user@host:cp-pxgrid $ cp *.service *.timer /etc/systemd/system/
user@host:cp-pxgrid $ systemctl enable cp-pxgrid-bulkdl-reboot.service cp-pxgrid.service cp-pxgrid-bulkdl.timer
```
If the information in the `.service`-files, the IP of the gate and its PSK are correct then:
```console
cp-pxgrid $ systemctl start cp-pxgrid.service cp-pxgrid-bulkdl.timer
```
You should start seeing output in `/var/log/cp-pxgrid.log`

## Why?
We were working on implementing an 802.1x-network, and using the logged in identities to be able to create firewall rules based on machine and username identities and in extension Active Directory groups and identities. Machine identities didn't work as intended after some time and we were told that pxGrid was sending out the wrong information.  
I had noticed earlier that machine identities were used as usernames on the firewall instead of machine. I never thought anything about this as the feature worked as expected anyway. I asked Check Point what values from pxGrid they were matching against, so that I could get back to Cisco. I never got an answer to this. I finally was told that our Cisco ISE was a version they did not support, IDC supported ISE v2.4 and we had been on v2.6 for quite some time.

Either way, I got tired of waiting on TAC, and remembering about [pxgrid-rest-ws](https://github.com/cisco-pxgrid/pxgrid-rest-ws) I preemptively started developing this project. Oh yes, clients with IPv6 was broken on Check Points IDC, but is supported with this project.

## Project implementation
cp-pxgrid is implemented using [Python](https://www.python.org/) and several Python modules with the intent of creating an asynchronous (non-blocking) client in case a firewall is too slow to respond or that there is too much data coming from [pxGrid](https://developer.cisco.com/docs/pxgrid/#!learning-pxgrid).

[Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) is configured with no reauthentication as recommended by Cisco, probably because overloading ISE is possible otherwise. Reauthentication can also only be configured by as much as 65535s or 18 hours. Reauthentication also relies entirely on the clients supplicant being responsive and work *every* time. RADIUS accounting is configured as default from the cat9300 l3-switch which is 12h. Accounting is used by ISE to keep a session updated and active, it is also more lightweight and only relies on the switch to see an active session.

**Note:** This script is currently only for machine authentications as Check Points Identity Collector works well for user authentications. Check Point is working on supporting Cisco ISE v2.6, which I hope fixes machine authentications. The script however is very easily extended to support user authentications, the code is half there already. Even better, it can also run on Linux.

### session_subscribe.cp.py
When the above script is running with ~300 klients on a WIFI network, CPU-usage on the 1 vcpu server is practically 0%, memory usage is 0,7% on the same server with 4GB of RAM. Stats for an entire wired network with ~800 clients is coming.

### session_query_all.cp.py
Should be run *within* the configured `fetchhours` in gwconfig.py by either CRON or the supplied systemd timer. It collects and injects the created and updated sessions from ISE, so that there is an overlap against `fetchhours`. This script actually keeps the identity sessions on the firewall active and extends the sessions timeout everytime it is run, unless a session is removed of course.

### session_query_reboot.cp.py
The most CPU intensive script is `session_query_reboot.cp.py` which is supposed to be run at server startup or reboot. The script downloads the complete session database from ISE. This is so because it is unknown for how long the server reboots for or is stopped for maintenance or downtime. Typically run on the same server as above, CPU usage is ~21% and runs for ~4s as measured with the `time` command on Linux.

### Firewall reload
No consideration has actually been taken to the inevitablity of a firewall reloading. Even firewalls in active/active or active/standby configuration might die because of hardware failure, power outage or simply a bug in software.  
Care should be taken to manually run `session_query_reboot.cp.py` to populate the firewalls identity session table. A simple reboot of a cp-pxgrid server could also be done.

### cp-pxgrid High Availablity
Check Points Identity Awareness is so pragmatic that if the firewall receives multiple updates for the same identity, it simply extends the identity sessions timeout accordingly to the supplied `session-timeout` API attribute.  
Therefore, this project can be run on 2 or more servers without any synchronisation without issue. As long as one server has access to the Identity Awareness API and Cisco ISE, all is well.

### Logging
All scripts log to syslog under their own programnames for the sake of rsyslogd. There are different loglevels, but all logs can be customised in the scripts.  
An example of sorting the programname to a specific logfile is included. Also included is configuration file for logrotate.

## Shortcomings
### pxGrid
There are a few shortcomings of pxGrid, for example no session timeout is published along with the data. This makes it hard to create a timeout of the identity session on the firewall and created the need for `session_query_all.cp.py`. [Check Point IDC](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk108235)  creates its own database containing identities received on pxGrid. Based on the time received, the software queries ISE for that particular IP to see if ISE still has a session for it or not. This specific implementation was out of scope for this project and therefore not implemented. It could potentially have smoothed out the periodic gathering of updated sessions.  
MQTT would maybe have been a better choice of message broker as it allows for buffering of messages to ensure all subscribers receive the same information, it would have alleviated the need for both `session_query_all.cp.py` and `session_query_reboot.cp.py`. Iirc this is called [MQTT QoS](http://www.steves-internet-guide.com/understanding-mqtt-qos-levels-part-1/), not to be confused with network [QoS](https://en.wikipedia.org/wiki/Quality_of_service).
Also, filtering! Allow for filtering of sessions! Like, I only want sessions that have state: STARTED.

### Check Point
Another shortcoming is Check Points Identity Awareness API, that it does not support a `session-timeout` of `0` to account for ISE by default not having a timeout in pxGrid on active sessions. There is a reason for this of course, and I can see that having `0` is practically unlimited. If there for some reason is no `DISCONNECT` that would clear that session, this could expend memory the firewall could use for its connection table instead.

### Me
I'm not a python programmer. I actually don't consider myself a programmer or developer at all. It has always been from necessity. Hence some code is probably unnecessary or could be moved to a function. I'm not sure `asyncio` is done right, because I simply don't know how I would test it.  
All pull requests are welcome of course.

# Credit
This project relies very heavily on Cisco's example project of a pxGrid v2.0 client [pxgrid-rest-ws](https://github.com/cisco-pxgrid/pxgrid-rest-ws). Everything below is from the original README of Cisco's repo. The latest version is of course available at Cisco's repo above.  
It was fun learning about Git more properly and actually using Python for real for once. Python did get on my nerves a few times regarding data types and variable references. But all was figured out, probably not remembered but why else would Google and StackOverflow exist?

# pxGrid
pxGrid is a protocol framework that defines the control mechanisms to facilitate machine-to-machine communications.

Benefits of using pxGrid:
- Reduce complexity of meshed network
- Centralized authentication and authorization
- Service abstraction
- Minimize human configuration errors

This project contains documentation and samples to use pxGrid.

See [documentation](https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki) to learn how to use pxGrid.
