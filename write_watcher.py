# Writes watcher.py - the KIWI WATCHER Python script
import os

code = r"""
import os, subprocess, json, time

def orca_terminal_list():
    r = subprocess.run(['orca','terminal','list','--json'], capture_output=True, text=True, stderr=subprocess.DEVNULL)
    return json.loads(r.stdout).get('result',{}).get('terminals',[])

def orca_terminal_send(terminal, text):
    subprocess.run(['orca','terminal','send','--terminal',terminal,'--text',text,'--enter'], stderr=subprocess.DEVNULL)

def file_epoch_ms(fp):
    try:    return int(os.path.getmtime(fp) * 1000)
    except: return None

def test_file_done(fp):
    if not os.path.exists(fp): return False
    with open(fp,'r',errors='ignore') as fh: c = fh.read().lower()
    return any(k in c for k in ['done','finished','complete'])

def test_screen_to(pv):
    pv = pv.lower()
    return any(k in pv for k in ['timed out','limit reached','timeout'])

LeadTerminal = 'term_a262bc09-3426-4675-bcd2-9c13d31755da'

Workers = [
    {'Label':'A4',  'Handle':'term_ef9a3e46', 'StatusFile':'docs/agents/agent-4-status.md'},
    {'Label':'A5',  'Handle':'term_3c90ea4d', 'StatusFile':'docs/agents/agent-5-status.md'},
    {'Label':'A6',  'Handle':'term_9e70fa6f', 'StatusFile':'docs/agents/agent-6-status.md'},
    {'Label':'A7',  'Handle':'term_9a1e77c8', 'StatusFile':'docs/agents/agent-7-status.md'},
    {'Label':'A8',  'Handle':'term_14f69e68', 'StatusFile':'docs/agents/agent-8-status.md'},
    {'Label':'A9',  'Handle':'term_c1785574', 'StatusFile':'docs/agents/agent-9-status.md'},
    {'Label':'A10', 'Handle':'term_77011ae4', 'StatusFile':'docs/agents/agent-10-status.md'},
]

baselineDone  = {}
baselineMtime = {}
for w in Workers:
    baselineDone[w['Label']]  = test_file_done(w['StatusFile'])
    baselineMtime[w['Label']] = file_epoch_ms(w['StatusFile'])

print('KIWI WATCHER started. 7 workers, ~60s loop.')
print('Lead:', LeadTerminal)
print('BASELINE (startup state):')
for lbl in baselineDone:
    print('  %s done=%s mtime=%s' % (lbl, baselineDone[lbl], baselineMtime[lbl]))
print('------------------------------------------------------------------------')

prevMtimes = dict(baselineMtime)

while True:
    now = int(time.time() * 1000)
    terminals = orca_terminal_list()
    wTerms = {}
    for w in Workers:
        t = [x for x in terminals if x.get('handle','').startswith(w['Handle']+'-')]
        wTerms[w['Label']] = t[0] if t else None
    reports = []
    for w in Workers:
        lbl     = w['Label']
        term    = wTerms[lbl]
        sf      = w['StatusFile']
        handle  = term['handle'] if term else 'NOT_FOUND'
        lastOut = term.get('lastOutputAt') if term else None
        preview = term.get('preview','').strip() if term else ''
        idleSec = round((now - lastOut)/1000, 1) if lastOut else -1
        curMtime = file_epoch_ms(sf)
        isDone  = test_file_done(sf)
        wasDone = baselineDone[lbl]
        mBumped = (prevMtimes[lbl] is not None and curMtime is not None and curMtime > prevMtimes[lbl])
        idleLong = idleSec > 300
        screenTO = test_screen_to(preview)
        if curMtime is not None: prevMtimes[lbl] = curMtime
        pShow = (preview[:90]+'...') if len(preview)>90 else preview
        print('[%s] handle=%s idle=%ss done=%s wasDoneAtStart=%s mtimeBumped=%s idle>300=%s screenTO=%s'
              % (lbl,handle,idleSec,isDone,wasDone,mBumped,idleLong,screenTO))
        print('       preview:', pShow)
        reason = ''
        if mBumped and isDone:
            reason = '%s task finished (agent-%s-status.md mtime updated, status=done)' % (lbl, lbl)
        elif idleLong:
            reason = '%s idle > 300s (%s s) at bare prompt' % (lbl, idleSec)
        elif screenTO:
            reason = '%s screen shows timed out / limit reached' % lbl
        if reason: reports.append('WATCHER: ' + reason)
    if reports:
        print()
        print('>>> REPORTING TO LEAD (%d msg) <<<' % len(reports))
        for line in reports:
            print('  ->', line)
            orca_terminal_send(LeadTerminal, line)
    else:
        print(); print('-- all-clear, no report --')
    print('------------------------------------------------------------------------')
    time.sleep(60)
"""

with open('watcher.py','w',encoding='utf-8') as f:
    f.write(code.lstrip())
print('watcher.py written OK')
