# pxGrid
pxGrid is a protocol framework that defines the control mechanisms to facilitate machine-to-machine communications.

Benefits of using pxGrid:
- Reduce complexity of meshed network
- Centralized authentication and authorization
- Service abstraction
- Minimize human configuration errors

This project contains documentation and samples to use pxGrid.

See [documentation](https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki) to learn how to use pxGrid.

# pxGrid 'state' attribute
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
