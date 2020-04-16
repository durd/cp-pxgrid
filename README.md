# cp-pxgrid
- [cp-pxgrid](#cp-pxgrid)
  * [Overview](#overview)
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
  * [pxGrid 'state' attribute](#pxgrid--state--attribute)
- [Credit](#credit)
- [pxGrid](#pxgrid-1)

## Overview
cp-pxgrid is a client implementation of Cisco's [pxGrid](https://developer.cisco.com/docs/pxgrid/#!learning-pxgrid) Security Product Integration Framework (SPIF) that subscribes and reads from pxGrid and sends via API identity information to Check Point firewalls. This is done so that user or machine identities from Cisco ISE can be used in firewall rules using Check Point [Identity Awareness](https://www.checkpoint.com/products/identity-awareness/).

pxGrid runs primarily on [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) but all manner of products can publish data to pxGrid that is then spread to other subscribers. pxGrid uses [STOMP](http://stomp.github.io/) as a message broker much like [MQTT](https://en.wikipedia.org/wiki/MQTT). [WebSockets](https://en.wikipedia.org/wiki/WebSocket) can be used to create an low-overhead communication channel for streaming STOMP data.

In the larger scheme of things, [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) is primarily used on networks implementing [802.1x](https://en.wikipedia.org/wiki/IEEE_802.1X) with [RADIUS](https://en.wikipedia.org/wiki/RADIUS) as the authentication, authorization and accounting protocol of choice.

## Project implementation
cp-pxgrid is implemented using [Python](https://www.python.org/) and several Python modules with the intent of creating an asynchronous (non-blocking) client in case a firewall is too slow to respond or that there is too much data coming from [pxGrid](https://developer.cisco.com/docs/pxgrid/#!learning-pxgrid).

[Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) is configured with no reauthentication as recommended by Cisco, probably because overloading ISE is possible otherwise. Reauthentication can also only be configured by as much as 65535s or 18 hours. Reauthentication also relies entirely on the clients supplicant being responsive and work *every* time. RADIUS accounting is configured as default from the cat9300 l3-switch which is 12h. Accounting is used by ISE to keep a session updated and active, it is also more lightweight and only relies on the switch to see an active session.

### session_subscribe.cp.py
When the above script is running with ~300 klients on a WIFI network, CPU-usage on the 1 vcpu server is practically 0%, memory usage is 0,7% on the same server with 4GB of RAM. Stats for an entire wired network with ~800 clients is coming.

### session_query_all.cp.py
Is run by default every 8th hour by CRON. It collects by default the last 9 hours of created and updated sessions from ISE so that there is an overlap. This script actually keeps the identity sessions on the firewall active and extends the sessions timeout everytime it is run, unless a session is removed of course.

### session_query_reboot.cp.py
The most CPU intensive script is `session_query_reboot.cp.py` which is supposed to be run at server startup or reboot. The script downloads the complete session database from ISE. This is so because it is unknown for how long the server reboots for or is stopped for maintenance or downtime. Typically run on the same server as above, CPU usage is ~21% and runs for ~4s as measured with the `time` command on Linux.

### Firewall reload
No consideration has actually been taken to the inevitablity of a firewall reloading. Even firewalls in active/active or active/standby configuration might die because of hardware failure, power outage or simple a bug in software.  
Care should be taken run manually run `session_query_reboot.cp.py` to populate the firewalls identity session table.

### cp-pxgrid High Availablity
Check Points Identity Awareness is so pragmatic that if the firewall receives multiple updates for the same identity, it simply extends the identity sessions timeout accordingly to the supplied `session-timeout` API attribute.  
Therefore, this project can be run on 2 or more servers without any synchronisation without issue. As long as one server has access to the Identity Awareness API and Cisco ISE, all is well.

### Logging
All scripts log to syslog under their own programnames for the sake of rsyslogd. There are different loglevels, but all logs can be customised in the scripts.  
An example of sorting the programname to a specific logfile is included. Also included is configuration file for logrotate.

## Shortcomings
### pxGrid
There are a few shortcomings of pxGrid, for example no session timeout is publised along with the data. This makes it hard to create a timeout of the identity session on the firewall and created the need for `session_query_all.cp.py`. There are implementations that create their own database containing identities received on pxGrid. Based on the time received, the software queries ISE for that particular IP to see if ISE still has a session for it or not. This specific implementation was out of scope for this project and therefore not implemented. It could potentially have smoothed out the periodic gathering of updated sessions, but was deemed not enough.  
MQTT would maybe have been a better choice of message broker as it allows for buffering of messages to ensure all subscribers receive the same information, it would have alleviated the need for both `session_query_all.cp.py` and `session_query_reboot.cp.py`. Iirc this is called [MQTT QoS](http://www.steves-internet-guide.com/understanding-mqtt-qos-levels-part-1/), not to be confused with network [QoS](https://en.wikipedia.org/wiki/Quality_of_service).

### Check Point
Another shortcoming is Check Points Identity Awareness API, that it does not support a `session-timeout` of `0` to account for ISE by default not having a timeout on active sessions. There is a reason for this of course, and I can see that having `0` is practically unlimited. If there for some reason is no `DISCONNECT` that would clear that session, this could expend memory the firewall could use for its connection table instead.

## pxGrid 'state' attribute
While ISE Live Logs page provide events in real time, Live Sessions page can be used to view sessions that ISE is maintaining at given point in time. As noted in the ISE Live Logs section above, sessions are successful authentication event that ISE received RADIUS accounting Start for.  
You may be wondering what happens if ISE doesn’t receive RADIUS accounting start from the network device for a give session? Even if ISE doesn’t receive RADIUS accounting start, ISE will maintain it, but for shorter duration.  
‘Started’ status means ISE received accompanying RADIUS accounting start whereas ‘Authenticated’ status means ISE received RADIUS authentication request that was successfully authenticated, but there was no RADIUS accounting start.  
For authentications with missing RADIUS accounting start, ISE only maintains session for 1 hour. When ISE isn’t maintaining the session, you end up with endpoints on the network but is not visible to ISE as connected endpoint as such ISE cannot send CoA which may break many of the advanced ISE use cases.  
Another case of ‘Authenticated’ is where ISE is configured with passive ID and/or Easy Connect. In these cases, ISE learned that a AD domain user was authenticated via WMI or AD agent but there were no RADIUS accounting received related to the same endpoint IP address. There are additional session status and following table summarizes the different session status:

* Authenticated  
ISE accepted the session, but did not receive accounting start. Aside from misconfiguration, typical reason to see Authenticated status is for RADIUS keepalive requests or passive ID without matching MAB/802.1X sessions. If no accounting start message is received, the session will be removed after 1 hour.

* Started  
ISE received RADIUS accounting start. Unless posture is used, most of the sessions should show up as Started. ISE requires interim accounting message to be sent within 5 days, if not the session will be removed.

* Postured  
The endpoint has been posture checked and compliant using the AnyConnect posture module. This status is not applicable for temporal agent which shows up as 'Started' even when compliant.

* Authenticating & Authorized  
These are legacy status and should not show up on a properly configured ISE deployment.

* Terminated  
ISE received RADIUS accounting stop. Terminated session will be removed from the table after 15 minutes.

* DISCONNECTED  
Terminated session. Our own addition to the list. Works with Terminated.

# Credit
This project relies very heavily on Cisco's example project of a pxGrid v2.0 client [pxgrid-rest-ws](https://github.com/cisco-pxgrid/pxgrid-rest-ws). Everything below is from the original README of Cisco's repo. THe latest version is of course available at Cisco's repo above.  
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
