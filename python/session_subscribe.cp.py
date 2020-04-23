# 3rd-party modules
import asyncio
import json
import signal
import sys
import time
import ipaddress
import traceback
import logging
from logging.handlers import SysLogHandler
from asyncio.tasks import FIRST_COMPLETED

# project specific modules
from config import Config
from pxgrid import PxgridControl
from websockets import ConnectionClosed
from ws_stomp import WebSocketStomp
from cp import cpia_add, cpia_del
import gwconfig as cfg


# init logging
log = logging.getLogger("cp-pxgrid")
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


async def future_read_message(ws, future):
    try:
        message = await ws.stomp_read_message()
        future.set_result(message)
    except ConnectionClosed:
        log.info('Websocket connection closed')

async def subscribe_loop(config, secret, ws_url, topic):
    ws = WebSocketStomp(ws_url, config.get_node_name(), secret, config.get_ssl_context())
    await ws.connect()
    log.info(f'Connecting to websocket')
    await ws.stomp_connect(pubsub_node_name)
    log.info(f'Connecting to stomp {pubsub_node_name}')
    await ws.stomp_subscribe(topic)
    log.info(f'Subscribing to {topic}')
    log.info("Ctrl-C, SIGINT or SIGTERM to disconnect...")
    while True:
        future = asyncio.Future()
        future_read = future_read_message(ws, future)
        try:
            await asyncio.wait([future_read], return_when=FIRST_COMPLETED)
        except asyncio.CancelledError:
            log.info('Cancellation caught')
            await ws.stomp_disconnect('123')
            # wait for receipt
            log.info('Disconnecting from stomp')
            await asyncio.sleep(3)
            await ws.disconnect()
            log.info('Disconnected from stomp')
            # close logging socket
            logging.shutdown()
            break
        else:
            message = json.loads(future.result())
            if message["sessions"]:
                for obj in message["sessions"]:
                    try:
                        if ("isMachineAuthentication" in obj) and (obj["state"] == "STARTED"):
                            if obj["isMachineAuthentication"] == "true":
                                #print("obj=" + json.dumps(obj, sort_keys=True, indent=2))
                                if "ipAddresses" not in obj:
                                    log.error(f'no ip-addresses in: {json.dumps(obj)}')
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
                                            cp_ident_add["shared-secret"] = psk
                                            task = asyncio.create_task(cpia_add(gw, cp_ident_add))
                                            tasks.append(task)
                                            log.info(f'{cp_ident_add["machine"]} {obj["state"]} {cp_ident_add["machine-groups"]} {cp_ident_add["ip-address"]} sent to {gw}')
                                        responses = await asyncio.gather(*tasks)
                                        responses = json.loads(responses[0])
                                        if "ipv4-address" in responses:
                                            log.info(f'Response: {responses["ipv4-address"]} {responses["message"]}')
                                        elif "ipv6-address" in responses:
                                            log.info(f'Response: {responses["ipv6-address"]} {responses["message"]}')
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
                            else:
                                pass
                        elif ("isMachineAuthentication" in obj) and (obj["state"] == "DISCONNECTED"):
                            if obj["isMachineAuthentication"] == "true":
                                #print("obj=" + json.dumps(obj, sort_keys=True, indent=2))
                                if "ipAddresses" not in obj:
                                    log.error(f'no ip-addresses in: ' + json.dumps(obj))
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
                                            cp_ident_del["shared-secret"] = psk
                                            task = asyncio.create_task(cpia_del(gw, cp_ident_del))
                                            tasks.append(task)
                                        responses = await asyncio.gather(*tasks)
                                        responses = json.loads(responses[0])
                                        if ("count" in responses) and (responses["count"] == "1"):
                                            if "ipv4-address" in responses:
                                                log.info(f'Response: {responses["ipv4-address"]} {responses["message"]}')
                                            elif "ipv6-address" in responses:
                                                log.info(f'Response: {responses["ipv6-address"]} {responses["message"]}')
                                        elif ("count" in responses) and (responses["count"] == "0"):
                                            log.info(f'Response: {responses["message"]}')
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
    pubsub_service_name = service['properties']['wsPubsubService']
    topic = service['properties']['sessionTopic']

    # lookup for pubsub service
    service_lookup_response = pxgrid.service_lookup(pubsub_service_name)
    pubsub_service = service_lookup_response['services'][0]
    pubsub_node_name = pubsub_service['nodeName']
    secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
    ws_url = pubsub_service['properties']['wsUrl']

    loop = asyncio.get_event_loop()
    subscribe_task = asyncio.ensure_future(subscribe_loop(config, secret, ws_url, topic))

    # Setup signal handlers
    loop.add_signal_handler(signal.SIGINT, subscribe_task.cancel)
    loop.add_signal_handler(signal.SIGTERM, subscribe_task.cancel)

    # Event loop
    loop.run_until_complete(subscribe_task)
