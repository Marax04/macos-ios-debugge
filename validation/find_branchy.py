import subprocess, json
p = subprocess.Popen([r'C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe','--transport=stdio'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
def s(r): p.stdin.write((json.dumps(r)+chr(10)).encode()); p.stdin.flush()
def rc(): return json.loads(p.stdout.readline())
s({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'t','version':'1'}}}); rc()
s({'jsonrpc':'2.0','method':'notifications/initialized'})
T=r'C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe'
s({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'project.open','arguments':{'path':T}}}); rc()
s({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'analyze.function','arguments':{'binary_id':'bin-0001','address':0x140000000}}})
r=rc()
funcs=json.loads(r['result']['content'][0]['text'])['functions']
for f in funcs[:200]:
    e=f.get('end','')
    if not isinstance(e,str) or not e.startswith('0x'): continue
    try: a=int(f['addr'],16); end=int(e,16)
    except: continue
    if end - a > 300 and f.get('confidence') in ('Medium','High'):
        s({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'decompile.function','arguments':{'binary_id':'bin-0001','address':a}}})
        rr=rc()
        c=rr.get('result',{}).get('content',[{}])[0].get('text','')
        goto_cnt = c.count('goto ')
        if_cnt = len([x for x in c.split() if x=='if'])
        loc_cnt = c.count('loc_')
        print(f'fn {hex(a)} sz {end-a}: if={if_cnt} goto={goto_cnt} loc={loc_cnt}')
        if if_cnt > 0:
            print(c[:3000])
            break
p.terminate()
