import os, subprocess, json, time, sys, re

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def orca_terminal_list():
    r = subprocess.run(['orca','terminal','list','--json'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace')
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

def test_shell_prompt_waiting(pv):
    lines = [raw.strip() for raw in pv.splitlines() if raw.strip()]
    if not lines:
        return False
    last = lines[-1]
    powershell = re.match(r'^PS\s+[A-Za-z]:\\[^\r\n]*>\s*$', last, re.I)
    cmd = re.match(r'^[A-Za-z]:\\[^\r\n]*>\s*$', last, re.I)
    posix = re.match(r'^(?:\$|>|❯|>)\s*$', last)
    return bool(powershell or cmd or posix)

def terminal_activity(pv):
    """Return (active_process, shell_prompt_waiting), conservatively."""
    if test_shell_prompt_waiting(pv):
        return False, True
    low = pv.lower()
    fragments = [
        'ran command', 'running command', 'esc twice to interrupt',
        'cargo test', 'cargo check', 'npm run', 'npm build', 'npx ',
        'vitest', 'pytest', 'test run', 'running tests', 'compiling',
        'building', 'build·', 'build ·', 'executing',
    ]
    spinners = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏⣾⣽⣻⢿⡿⣟⣯⣷⬝■▣'
    return any(k in low for k in fragments) or any(ch in pv for ch in spinners), False

def test_true_idle(pv):
    active, prompt = terminal_activity(pv)
    return prompt and not active


LeadTerminal = 'term_db8527c7-eb71-4274-b416-61c91143a6cf'
ExcludedPrefixes = (LeadTerminal, 'term_621f9265', 'term_30e63397')

Workers = [
    {'Label':'A11', 'Handle':'term_d869b293', 'StatusFile':'docs/agents/agent-11-status.md'},
    {'Label':'A12', 'Handle':'term_4cc53da5', 'StatusFile':'docs/agents/agent-12-status.md'},
    {'Label':'A13', 'Handle':'term_e5adf4d9', 'StatusFile':'docs/agents/agent-13-status.md'},
    {'Label':'A15', 'Handle':'term_c47aa1d7', 'StatusFile':'docs/agents/agent-15-status.md'},
    {'Label':'A16', 'Handle':'term_87c46343', 'StatusFile':'docs/agents/agent-16-status.md'},
    {'Label':'A17', 'Handle':'term_71a0b324', 'StatusFile':'docs/agents/agent-17-status.md'},
    {'Label':'A18', 'Handle':'term_f7e88089', 'StatusFile':'docs/agents/agent-18-status.md'},
    {'Label':'A23', 'Handle':'term_e26f119b-e762-429c-81a1-252a53c0e5c8', 'StatusFile':'docs/agents/agent-23-status.md'},
    {'Label':'A24', 'Handle':'term_ee5cbe6c-4c3b-4500-8aa5-11df880df9a4', 'StatusFile':'docs/agents/agent-24-status.md'},
]

def matches_handle(handle, prefix):
    return bool(handle) and (handle == prefix or handle.startswith(prefix + '-'))

baselineDone  = {}
baselineMtime = {}
for w in Workers:
    baselineDone[w['Label']]  = test_file_done(w['StatusFile'])
    baselineMtime[w['Label']] = file_epoch_ms(w['StatusFile'])

prevDone = dict(baselineDone)
prevIdle = {w['Label']: False for w in Workers}
prevScreenTO = {w['Label']: False for w in Workers}

print('KIWI WATCHER started. %d workers, ~60s loop.' % len(Workers))
print('Lead:', LeadTerminal)
print('Excluded: Lead, Planner, and Watcher terminals')
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
        t = [x for x in terminals
             if matches_handle(x.get('handle',''), w['Handle'])
             and x.get('connected', False)
             and not x.get('orphaned', False)]
        wTerms[w['Label']] = t[0] if t else None
    reports = []
    for w in Workers:
        lbl     = w['Label']
        term    = wTerms[lbl]
        sf      = w['StatusFile']
        if term is None:
            isDone = test_file_done(sf)
            prevDone[lbl] = isDone
            prevIdle[lbl] = False
            prevScreenTO[lbl] = False
            print('[%s] terminal=DEAD reports=SUPPRESSED' % lbl)
            continue
        handle  = term['handle']
        lastOut = term.get('lastOutputAt')
        preview = term.get('preview','').strip()
        idleSec = round((now - lastOut)/1000, 1) if lastOut else -1
        curMtime = file_epoch_ms(sf)
        isDone  = test_file_done(sf)
        wasDone = prevDone[lbl]
        wasIdle = prevIdle[lbl]
        wasScreenTO = prevScreenTO[lbl]
        activeProcess, promptWaiting = terminal_activity(preview)
        trueIdle = idleSec > 300 and test_true_idle(preview)
        screenTO = test_screen_to(preview)
        if curMtime is not None: prevMtimes[lbl] = curMtime
        prevDone[lbl] = isDone
        prevIdle[lbl] = trueIdle
        prevScreenTO[lbl] = screenTO
        pShow = (preview[:90]+'...') if len(preview)>90 else preview
        print('[%s] handle=%s idle=%ss done=%s trueIdle=%s activeProcess=%s promptWaiting=%s screenTO=%s'
              % (lbl,handle,idleSec,isDone,trueIdle,activeProcess,promptWaiting,screenTO))
        print('       preview:', pShow)
        if isDone and not wasDone:
            reports.append('WATCHER: %s status file transitioned to done' % lbl)
        elif trueIdle and not wasIdle:
            reports.append('WATCHER: %s TRUE idle > 300s (%ss; shell prompt waiting)' % (lbl, idleSec))
        elif screenTO and not wasScreenTO:
            reports.append('WATCHER: %s screen shows timed out / limit reached' % lbl)
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
