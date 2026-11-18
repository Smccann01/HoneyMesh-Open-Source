#!/usr/bin/env python3
"""Exercise the shipped dashboard render functions in headless Chrome."""
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1].joinpath('dashboard.go').read_text()
start = source.index('        function renderExchangeKnownClusters(clusters) {')
end = source.index('        let liveTab', start)
exchange = source[start:end]
start = source.index('        function renderTrust(rows, targetSelector) {')
end = source.index('        function renderTraps(', start)
trust = source[start:end]
fixture = '''<!doctype html><html><body>
<div id="exchange-known-clusters"></div><div id="trusted-mesh-networks"></div>
<table id="trust-modal-table"><tbody></tbody></table><div id="result"></div>
<script>
let trustedMeshNetworksState = [];
let lastExchangeKnownClusters = [];
''' + exchange + trust + '''
const payload = "<img src=x onerror=alert(1)>\\\"'";
renderExchangeKnownClusters([{cluster_id:payload,last_seen:payload,trusted:false}]);
renderTrustedMeshNetworks([{cluster_id:payload}]);
renderTrust([{peer:payload,last_report:payload,score:0,total:0,valid:0,invalid:0}], '#trust-modal-table tbody');
const noElements = document.querySelectorAll('img').length === 0;
const literal = document.getElementById('exchange-known-clusters').textContent.includes(payload) && document.querySelector('#trust-modal-table tbody').textContent.includes(payload);
const buttons = document.querySelectorAll('#exchange-known-clusters button').length === 3 && document.querySelectorAll('#trust-modal-table button').length === 5;
document.querySelector('#exchange-known-clusters button').click();
const works = trustedMeshNetworksState.length === 1 && trustedMeshNetworksState[0].cluster_id === payload;
document.getElementById('result').textContent = noElements && literal && buttons && works ? 'XSS_FIXTURE_PASS' : 'XSS_FIXTURE_FAIL';
</script></body></html>'''
with tempfile.TemporaryDirectory() as directory:
    page = Path(directory, 'fixture.html')
    page.write_text(fixture)
    result = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--dump-dom', page.as_uri()], capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or 'id="result">XSS_FIXTURE_PASS<' not in result.stdout:
        raise SystemExit('browser XSS fixture failed: ' + result.stdout[-1000:] + result.stderr[-500:])
    print('XSS_FIXTURE_PASS: markup stayed literal and trust controls worked')
