"""Bounded live browser verification of evidence, filters, responsiveness and STOP."""
import base64
import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.runtime/ui-verification'
OUT.mkdir(exist_ok=True)
token=(ROOT/'.runtime/operator-token').read_text().strip()
chrome=Path(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Google/Chrome/Application/chrome.exe'
with socket.socket() as port_socket:
    port_socket.bind(('127.0.0.1',0))
    port=port_socket.getsockname()[1]
process=subprocess.Popen([str(chrome),'--headless=new','--disable-gpu','--no-first-run',
    f'--remote-debugging-port={port}','--remote-allow-origins=http://localhost',
    f'--user-data-dir={OUT / "chrome-profile"}','about:blank'],
    stdout=subprocess.DEVNULL,stderr=open(OUT/"chrome.log","w"),
    creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
ws=None
try:
    last_error = None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(50):
        try:
            pages=json.load(opener.open(f'http://127.0.0.1:{port}/json',timeout=1))
            target=next(p for p in pages if p['type']=='page')
            ws=connect(target['webSocketDebuggerUrl'],origin='http://localhost',open_timeout=10,proxy=None,max_size=20*1024*1024)
            break
        except Exception as exc:
            last_error = exc
            time.sleep(.2)
    if ws is None: raise RuntimeError(f'Browser did not start: {last_error}; exit={process.poll()}; log={(OUT/'chrome.log').read_text()[-2000:]}')
    serial=0
    def call(method,params=None):
        global serial
        serial+=1
        ws.send(json.dumps(dict(id=serial,method=method,params=params or {})))
        while True:
            response=json.loads(ws.recv())
            if response.get('id')==serial:
                if 'error' in response: raise RuntimeError(response['error'])
                return response.get('result',{})
    def evaluate(expression):
        return call('Runtime.evaluate',dict(expression=expression,returnByValue=True))['result'].get('value')
    def until(expression,timeout=20):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if evaluate(expression): return
            time.sleep(.2)
        raise AssertionError(expression)
    call('Page.enable')
    call('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False))
    call('Page.navigate',dict(url='http://127.0.0.1:8798/#access='+token))
    until("document.querySelectorAll('#events tr').length>0")
    assert evaluate("document.querySelector('#run-status').textContent")=='RUNNING'
    until("document.querySelector('#detail').textContent.includes('secret_upload')")
    assert evaluate("document.querySelector('#detail').textContent.includes('/work/.env')")
    (OUT/'desktop.png').write_bytes(base64.b64decode(call('Page.captureScreenshot')['data']))
    evaluate("document.querySelector('#search').value='no-resource-matches';document.querySelector('#search').dispatchEvent(new Event('input'))")
    assert evaluate("document.querySelectorAll('#events tr').length") == 0
    assert evaluate("document.querySelector('#empty h2').textContent")=='No matching events'
    evaluate("document.querySelector('#search').value='';document.querySelector('#search').dispatchEvent(new Event('input'))")
    call('Emulation.setDeviceMetricsOverride',dict(width=390,height=1000,deviceScaleFactor=1,mobile=True))
    time.sleep(.2)
    assert evaluate('document.documentElement.scrollWidth <= 390')
    (OUT/'mobile.png').write_bytes(base64.b64decode(call('Page.captureScreenshot')['data']))
    call('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False))
    evaluate("document.querySelector('#stop').click()")
    until("document.querySelector('#run-status').textContent==='STOPPED'",timeout=40)
    assert evaluate("document.querySelector('#stop').disabled")
    (OUT/'stopped.png').write_bytes(base64.b64decode(call('Page.captureScreenshot')['data']))
    evidence=dict(live_feed=True,source_evidence=True,search_empty_state=True,mobile_no_horizontal_overflow=True,
                  stop_control_verified=True)
    (OUT/'verification.json').write_text(json.dumps(evidence,indent=2))
    print(json.dumps(evidence,indent=2))
finally:
    if ws: ws.close()
    process.terminate()
    process.wait(timeout=10)
