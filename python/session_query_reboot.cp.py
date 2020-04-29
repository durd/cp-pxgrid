# 3rd-party modules
import signal
import asyncio
import ipaddress
import urllib.request
import base64
import time
import logging
import json
import sys
from logging.handlers import SysLogHandler
from asyncio.tasks import FIRST_COMPLETED

# project specific modules
from pxgrid import PxgridControl
from config import Config
from cp import cpia_add, cpia_del
import gwconfig as cfg


# init logging
log = logging.getLogger("cp-pxgrid-bulkdl-reboot")
# set lowest loglevel to be logged
log.setLevel(logging.INFO)
#log.setLevel(logging.DEBUG)
# add syslog handler and set facility
handler = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
# some formatting
#formatter = logging.Formatter('%(name)s[%(process)d]: %(levelname)s %(module)s.%(funcName)s: %(asctime)s %(message)s')
# above was a bit long
formatter = logging.Formatter('%(name)s[%(process)d]: %(levelname)s %(funcName)s: %(asctime)s %(message)s')
# apply formatting and handler
handler.setFormatter(formatter)
log.addHandler(handler)


async def query(config, secret, url, payload):
    log.info(f'query url={url}')
    log.info(f'  request={payload}')
    handler = urllib.request.HTTPSHandler(context=config.get_ssl_context())
    opener = urllib.request.build_opener(handler)
    rest_request = urllib.request.Request(url=url, data=str.encode(payload))
    rest_request.add_header('Content-Type', 'application/json')
    rest_request.add_header('Accept', 'application/json')
    b64 = base64.b64encode((config.get_node_name() + ':' + secret).encode()).decode()
    rest_request.add_header('Authorization', 'Basic ' + b64)
    rest_response = opener.open(rest_request)
    log.info(f'  response status={str(rest_response.getcode())}')
    #print('  response content=' + rest_response.read().decode())

    message = json.loads(rest_response.read().decode())
    if message["sessions"]:
        for obj in message["sessions"]:
            try:
                if ("isMachineAuthentication" in obj) and (obj["state"] == "STARTED"):
                    if obj["isMachineAuthentication"] == "true":
                        #print("obj=" + json.dumps(obj, sort_keys=True, indent=2))
                        if "ipAddresses" not in obj:
                            log.error(f'no ip-addresses in: {json.loads(obj)}')
                            continue
                        obj["ipAddresses"] = list(filter(None, obj["ipAddresses"]))
                        for ip in obj["ipAddresses"]:
                            try:
                                cp_ident_add = {}
                                cp_ident_add["machine"] = obj["adHostSamAccountName"]
                                cp_ident_add["domain"] = obj["adHostDomainName"]
                                if "endpointOperatingSystem" in obj: cp_ident_add["machine-os"] = obj["endpointOperatingSystem"]
                                cp_ident_add["machine-groups"] = [obj["ctsSecurityGroup"]]
                                cp_ident_add["fetch-machine-groups"] = 0
                                cp_ident_add["session-timeout"] = cfg.gwtimeout
                                ipa = ipaddress.ip_address(ip)
                                if (ipa.version == 4) and (not ipa.is_link_local):
                                    cp_ident_add["ip-address"] = ip
                                elif (ipa.version == 6) and (not ipa.is_link_local):
                                    cp_ident_add["ip-address"] = ip
                                else:
                                    log.warning(f'link-local for {cp_ident_add["machine"]}: {ip} ({obj["state"]})')
                                    continue
                                tasks = []
                                for gw, psk in cfg.gws.items():
                                    task = asyncio.create_task(cpia_add(gw, psk, cp_ident_add))
                                    tasks.append(task)
                                    log.info(f'{cp_ident_add["machine"]} {obj["state"]} {cp_ident_add["machine-groups"]} {cp_ident_add["ip-address"]} sent to {gw}')
                                responses = await asyncio.gather(*tasks)
                                for task in responses:
                                    for gw, resp in task.items():
                                        resp = json.loads(resp)
                                    if "ipv4-address" in resp:
                                        log.info(f'Response from {gw}: {resp["ipv4-address"]} {resp["message"]}')
                                    elif "ipv6-address" in resp:
                                        log.info(f'Response from {gw}: {resp["ipv6-address"]} {resp["message"]}')
                                del cp_ident_add
                            except Exception:
                                log.exception('')
                                continue
                    elif obj["isMachineAuthentication"] == "false":
                        # User authentication, not handled by this script. Yet. Easily implemented though
                        log.debug(f'isMachineAuthentication is false but state is STARTED in: {json.dumps(obj)}')
                        continue
                        obj["ipAddresses"] = list(filter(None, obj["ipAddresses"]))
                        if not obj["ipAddresses"]: continue
                        for ip in obj["ipAddresses"]:
                            try:
                                info = {}
                                info["user"] = obj["adUserSamAccountName"]
                                info["machine"] = obj["adHostSamAccountName"]
                                info["domain"] = obj["adHostDomainName"]
                                info["machine-os"] = obj["endpointOperatingSystem"]
                                info["user-groups"] = obj["ctsSecurityGroup"]
                                info["machine-groups"] = obj["ctsSecurityGroup"]
                                ipa = ipaddress.ip_address(ip)
                                if ipa.version == 4:
                                    info["ip-address"] = ip
                                    cp_ident["requests"].append(info)
                                if (ipa.version == 6) and (not ipa.is_link_local):
                                    info["ip-address"] = ip
                                    cp_ident["requests"].append(info)
                            except Exception:
                                log.exception('')
                                continue
                        #print("cp_ident=" + json.dumps(cp_ident, sort_keys=True, indent=2))
                    else:
                        pass
                elif ("isMachineAuthentication" in obj) and (obj["state"] == "DISCONNECTED"):
                    #if (obj["isMachineAuthentication"] == "true") and (obj["adHostSamAccountName"] == "SR180371$"):
                    if obj["isMachineAuthentication"] == "true":
                        #print("obj=" + json.dumps(obj, sort_keys=True, indent=2))
                        if "ipAddresses" not in obj:
                            log.error(f'no ip-addresses in: {json.dumps(obj)}')
                            continue
                        obj["ipAddresses"] = list(filter(None, obj["ipAddresses"]))
                        for ip in obj["ipAddresses"]:
                            try:
                                cp_ident_del = {}
                                ipa = ipaddress.ip_address(ip)
                                if (ipa.version == 4) and (not ipa.is_link_local):
                                    cp_ident_del["ip-address"] = ip
                                elif (ipa.version == 6) and (not ipa.is_link_local):
                                    cp_ident_del["ip-address"] = ip
                                else:
                                    log.warning(f'link-local for {obj["adHostSamAccountName"]} {ip} ({obj["state"]})')
                                    continue
                                tasks = []
                                for gw, psk in cfg.gws.items():
                                    task = asyncio.create_task(cpia_del(gw, psk, cp_ident_del))
                                    tasks.append(task)
                                    log.info(f'{obj["adHostSamAccountName"]} {obj["state"]} {ip} sent to {gw}')
                                responses = await asyncio.gather(*tasks)
                                for task in responses:
                                    for gw, resp in task.items():
                                        resp = json.loads(resp)
                                    if ("count" in resp) and (resp["count"] == "1"):
                                        if "ipv4-address" in resp:
                                            log.info(f'Response from {gw}: {resp["ipv4-address"]} {resp["message"]}')
                                        elif "ipv6-address" in resp:
                                            log.info(f'Response from {gw}: {resp["ipv6-address"]} {resp["message"]}')
                                    elif ("count" in resp) and (resp["count"] == "0"):
                                        log.info(f'Response from {gw}: {resp["message"]}')
                                del cp_ident_del
                            except Exception:
                                log.exception('')
                                continue
                else:
                    log.warning(f'no isMachineAuthentication or STARTED in: {json.dumps(obj)}')
            except Exception:
                log.exception('')
                continue
    else:
        print("boo")

if __name__ == '__main__':
    config = Config()
    pxgrid = PxgridControl(config=config)

    while pxgrid.account_activate()['accountState'] != 'ENABLED':
        time.sleep(60)

    # lookup for session service
    service_lookup_response = pxgrid.service_lookup('com.cisco.ise.session')
    service = service_lookup_response['services'][0]
    node_name = service['nodeName']
    url = service['properties']['restBaseUrl'] + '/getSessions'

    secret = pxgrid.get_access_secret(node_name)['secret']

    loop = asyncio.get_event_loop()
    bulkdl = asyncio.ensure_future(query(config, secret, url, '{}'))

    loop.add_signal_handler(signal.SIGINT, bulkdl.cancel)
    loop.add_signal_handler(signal.SIGTERM, bulkdl.cancel)

    # Event loop
    loop.run_until_complete(bulkdl)
