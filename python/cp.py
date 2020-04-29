import json
import aiohttp
import logging


async def cpia_add(gw, psk, identities):
    #print("cpia_add=" + json.dumps(identities))
    protocol = 'https://'
    path = '/_IA_API/v1.0/add-identity'
    url = f'{protocol}{gw}{path}'
    identities["shared-secret"] = psk
    timeout = aiohttp.ClientTimeout(total=5)
    # ""'ssl': False" disables ssl verification
    kwargs = {'headers': {'content-type': 'application/json'}, 'ssl': False}
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=json.dumps(identities), **kwargs) as resp:
                ret = {}
                ret[gw] = await resp.text()
                return ret
    except Exception:
        log.exception('')

async def cpia_del(gw, psk, identities):
    #print("cpia_del=" + json.dumps(identities))
    protocol = 'https://'
    path = '/_IA_API/v1.0/delete-identity'
    url = f'{protocol}{gw}{path}'
    identities["shared-secret"] = psk
    timeout = aiohttp.ClientTimeout(total=5)
    # ""'ssl': False" disables ssl verification
    kwargs = {'headers': {'content-type': 'application/json'}, 'ssl': False}
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=json.dumps(identities), **kwargs) as resp:
                ret = {}
                ret[gw] = await resp.text()
                return ret
    except Exception:
        log.exception('')
