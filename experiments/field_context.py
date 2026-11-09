"""Ordered-capture development experiment; independent GTAE adaptation.

No live traffic, label fitting, author checkpoint loading, or test tuning.
Use GTAE/.venv/bin/python. Outputs stay in this improvement workspace.
"""
from pathlib import Path
import argparse, bisect, collections, copy, gzip, hashlib, heapq, json, random
import sqlite3, sys, time
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'GTAE/src'))
from gtae_ids.packets import capture_records,packet_features,UnsupportedPacket
from gtae_ids.data import key_tuple,is_benign
from gtae_ids.graphs import adjacency,laplacian_pe,batch_tensors

MASK=(2,3,7,8,9,10,11,12,13,14,15,16,21,22)

def dump(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,allow_nan=False)+'\n')

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def extract(out):
    """Reproduce old session IDs, retaining capture order instead of sorting.

    Full record ordinals and times retain last observed activity for context.
    Reused labels are disclosed schedule-derived development labels only.
    """
    db=sqlite3.connect(f'file:{ROOT}/GTAE/data/processed/main.sqlite?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    original={r['id']:dict(r) for r in db.execute("select * from flows where dataset='CICIDS2017'")};db.close()
    bysource=collections.defaultdict(dict)
    for ident,r in original.items():bysource[r['source']][ident]=r
    receipts=[];allrows=[]
    for source,labels in sorted(bysource.items()):
        filehash=sha(source);active={};expiry=[];last=-float('inf');clock=-float('inf');stats=collections.Counter();kept=[]
        def flush(f):
            ident=hashlib.sha256(f"{filehash}|{f['src']}|{f['dst']}|{f['start']:.9f}".encode()).hexdigest()
            old=labels.get(ident)
            f['id']=ident;f['source']=Path(source).name
            f['label']=old['label'] if old else 'UNLABELED'
            f['label_source']=old['label_source'] if old else 'unmatched source session'
            if old:
                stats['matched_old_id']+=1
                stats['prefix_changed_by_arrival_order']+=int(bytes.fromhex(f['features'])!=old['features'])
            f.pop('closed');f.pop('seq');kept.append(f)
        for ts,raw,link in capture_records(source,stats,True):
            clock=max(clock,ts)
            try:pkt=packet_features(raw,link,ts)
            except UnsupportedPacket as error:
                stats[str(error)]+=1;continue
            stats['accepted_tcp_ipv4']+=1
            idx=stats['records'];last=max(last,pkt.timestamp)
            while expiry and expiry[0][0]<last-120:
                t,k=heapq.heappop(expiry)
                if k in active and active[k]['end']==t:flush(active.pop(k))
            key=key_tuple(pkt.src,pkt.dst);f=active.get(key);syn=bool(pkt.flags&2 and not pkt.flags&16)
            if f and syn and (f['closed'] or f['seq'] is None or pkt.seq!=f['seq']):
                flush(f);del active[key];f=None
            if f is None:
                f={'src':pkt.src,'dst':pkt.dst,'start':pkt.timestamp,'end':pkt.timestamp,
                   'seq':pkt.seq if syn else None,'initial_syn':syn,'closed':False,
                   'records':[],'times':[],'observed_times':[],'features':''};active[key]=f
            f['end']=max(f['end'],pkt.timestamp)
            f['records'].append(idx);f['times'].append(pkt.timestamp);f['observed_times'].append(clock)
            if len(f['records'])<=8:
                v=pkt.features+bytes(25) if pkt.src==f['src'] else bytes(25)+pkt.features
                f['features']+=v.hex()
            if pkt.flags&5:f['closed']=True
            heapq.heappush(expiry,(f['end'],key))
            if len(expiry)>max(20000,len(active)*4):
                expiry=[(f['end'],k) for k,f in active.items()];heapq.heapify(expiry)
        for f in active.values():flush(f)
        receipts.append({'source':source,'sha256':filehash,'old_rows':len(labels),'stats':dict(stats),
                         'missing_old_ids':sorted(set(labels)-{r['id'] for r in kept})})
        allrows.extend(kept);print(Path(source).name,len(kept),flush=True)
    out.mkdir(parents=True,exist_ok=True)
    with gzip.open(out/'ordered-flows.jsonl.gz','wt') as f:
        for r in allrows:f.write(json.dumps(r)+'\n')
    dump(out/'source-audit.json',{'original_db_sha256':sha(ROOT/'GTAE/data/processed/main.sqlite'),
         'sources':receipts,'rows':len(allrows),'label_status':'reused development labels, not CSV flow/onset ground truth',
         'order':'per-source original pcap record ordinal; clock uses running maximum timestamp over ALL raw records'})

def load(path):
    with gzip.open(path,'rt') as f:rows=[json.loads(s) for s in f]
    # Sensor decision time is monotonic even if source timestamps go backward.
    events=collections.defaultdict(list)
    for r in rows:r['bytes']=bytes.fromhex(r['features'])
    if all('observed_times' in r and len(r['observed_times'])==len(r['records']) for r in rows):return rows
    for r in rows:
        for i,(record,t) in enumerate(zip(r['records'],r['times'])):events[r['source']].append((record,t,r,i))
    for group in events.values():
        high=-float('inf')
        for _,t,r,i in sorted(group,key=lambda v:v[0]):
            high=max(high,t)
            if 'observed_times' not in r:r['observed_times']=[0.]*len(r['times'])
            r['observed_times'][i]=high
    return rows

def vector(row,p,masked=False,available=None):
    n=min(p,len(row['records']) if available is None else available)
    x=np.zeros(50*p,np.float32)
    x[:50*n]=np.frombuffer(row['bytes'][:50*n],np.uint8)/255.
    if masked:
        for j in range(p):
            for direction in (0,25):x[[j*50+direction+i for i in MASK]]=0
    return x

def graph(target,universe,p,masked=False,context='past',window=60.,cap=128):
    cutoff=target['records'][p-1];now=target['observed_times'][p-1]
    chosen=[]
    if context=='past':
        for r in universe:
            if r['source']!=target['source'] or r['id']==target['id']:continue
            n=bisect.bisect_right(r['records'],cutoff)
            if n and now-r['observed_times'][n-1]<=window:
                chosen.append((r['records'][n-1],r['id'],r,n))
        chosen.sort(key=lambda t:(-t[0],t[1]));chosen=chosen[:cap-1]
    elif context!='self':raise ValueError(context)
    nodes=[(target,p)]+[(r,n) for _,_,r,n in chosen]
    x=np.stack([vector(r,p,masked,n) for r,n in nodes])
    mask=adjacency([(tuple(r['src']),tuple(r['dst'])) for r,_ in nodes])
    pe=laplacian_pe(mask,8)
    records=[r['records'][min(p,n)-1] for r,n in nodes]
    assert max(records)<=cutoff
    return (x,mask,pe),{'ids':[r['id'] for r,_ in nodes],'represented_records':records,
                          'incident_neighbors':int(mask[0].sum()-1),
                          'cutoff':cutoff,'neighbors':len(nodes)-1}

def make_manifest(rows,out):
    stages={k:[] for k in ('train1','train2','validation','test')}
    # Assignment is independent of length and representation; all stages retain short context flows.
    for r in rows:
        v=int(hashlib.sha256(('20261104|'+r['id']).encode()).hexdigest()[:8],16)%100
        stage=('train1' if v<40 else 'train2' if v<60 else 'validation' if v<80 else 'test') if is_benign(r['label']) else 'test'
        stages[stage].append(r)
    limits={'train1':128,'train2':128,'validation':200,'test':None}
    ids={};counts={}
    for stage,rs in stages.items():
        eligible=[r for r in rs if r['initial_syn'] and len(r['bytes'])>=400 and r['label']!='UNLABELED']
        eligible.sort(key=lambda r:hashlib.sha256(('target|'+r['id']).encode()).hexdigest())
        chosen=eligible if limits[stage] is None else eligible[:limits[stage]]
        ids[stage]=[r['id'] for r in chosen]
        counts[stage]={'context_rows':len(rs),'eligible_targets':len(eligible),'selected_targets':len(chosen),
                       'selected_labels':dict(collections.Counter(r['label'] for r in chosen))}
    manifest={'seed':20261104,'source_sha256':sha(out/'ordered-flows.jsonl.gz'),'ids':ids,'counts':counts,
              'context_ids':{k:[r['id'] for r in rs] for k,rs in stages.items()},
              'status':'development only; data previously explored; labels schedule-derived; no untouched independent test',
              'packet_counts':[2,8],'mask_positions_per_25_byte_direction':MASK,'window_seconds':60,'edge_cap':128,
              'epochs':5,'model_seed':20261104,'detector':'IsolationForest, 150 trees, random_state=20261104',
              'threshold':'benign validation higher 0.99 quantile; strict score > threshold',
              'context_policy':'split-specific observed sessions, no final-length/label filter at graph decision',
              'label_provenance':'main.sqlite development labels; attacks schedule+tuple rules; benign Monday declared',
              'training_scope':'local feasibility and simple control only; not confirmatory factorial study'}
    dump(out/'pilot-manifest.json',manifest)
    return manifest

def audit(rows,manifest,out):
    idrow={r['id']:r for r in rows};checks={};collision={}
    for p in (2,8):
        for masked in (False,True):
            groups=collections.defaultdict(list)
            for r in rows:
                if len(r['bytes'])>=50*p and r['label']!='UNLABELED':groups[vector(r,p,masked).tobytes()].append(r)
            cross=[];conflicts=0;binary_conflicts=0;mixed=[]
            stageid={i:k for k,ids in manifest['ids'].items() for i in ids}
            for group in groups.values():
                if len({r['label'] for r in group})>1:
                    conflicts+=1;mixed.append(dict(collections.Counter(r['label'] for r in group)))
                binary_conflicts+=int(len({is_benign(r['label']) for r in group})>1)
                ss={stageid[r['id']] for r in group if r['id'] in stageid}
                if len(ss)>1:cross.append([r['id'] for r in group if r['id'] in stageid])
            collision[f'p{p}_{"mask" if masked else "raw"}']={'eligible_rows':sum(map(len,groups.values())),
                'groups':len(groups),'conflicting_attack_class_groups':conflicts,
                'conflicting_binary_label_groups':binary_conflicts,'mixed_class_counts':mixed,
                'largest_group':max(map(len,groups.values()),default=0),
                'selected_split_spanning_groups':len(cross),'cross_ids':cross}
        # Append future records to all universe members and prove graph byte inputs remain identical.
        eligible=[idrow[i] for ids in manifest['ids'].values() for i in ids]
        for t in eligible[:32]:
            universe=rows;g,receipt=graph(t,universe,p)
            future=copy.deepcopy(rows)
            for r in future:
                r['records'].append(max(t['records'][p-1]+1,r['records'][-1]+1))
                r['observed_times'].append(max(t['observed_times'][p-1]+100,r['observed_times'][-1]+1))
            g2,receipt2=graph(t,future,p)
            assert receipt==receipt2 and all(np.array_equal(a,b) for a,b in zip(g,g2))
        checks[str(p)]={'future_append_invariance_cases':min(32,len(eligible)),'passed':True}
    coverage={label:{str(p):sum(r['initial_syn'] and len(r['bytes'])>=50*p for r in rows if r['label']==label)
                    for p in (2,8)}|{'all_labeled_sessions':sum(r['label']==label for r in rows)}
              for label in sorted({r['label'] for r in rows if r['label']!='UNLABELED'})}
    dump(out/'data-gate.json',{'invariance':checks,'collisions':collision,'coverage':coverage,
         'confirmatory_fit_allowed':False,'pilot_allowed':True,
         'reasons':['previously explored bounded development data','schedule-derived attack labels','Monday-only local benign capture']})

def pilot(rows,manifest,out):
    """Train/validation feasibility; no attack or heldout test metrics are opened."""
    import torch
    from gtae_ids.model import GTAE
    from sklearn.ensemble import IsolationForest
    torch.set_num_threads(2);random.seed(manifest['model_seed']);np.random.seed(manifest['model_seed'])
    torch.manual_seed(manifest['model_seed'])
    byid={r['id']:r for r in rows}
    stage={k:[byid[i] for i in ids] for k,ids in manifest['context_ids'].items()}
    target={k:[byid[i] for i in ids] for k,ids in manifest['ids'].items()}
    cfg=json.loads((ROOT/'GTAE/configs/paper.json').read_text())
    # One p8, raw/past arm benchmarks fitting before larger experiments.
    cfg['epochs']=manifest['epochs'];model=GTAE(8,cfg);opt=torch.optim.Adam(model.parameters(),lr=.001)
    start=time.perf_counter()
    graphs={k:[graph(r,stage[k],8)[0] for r in target[k]] for k in ('train1','validation')}
    setup=time.perf_counter()-start;history=[];best=float('inf');state=None
    for epoch in range(manifest['epochs']):
        model.train();order=np.random.default_rng(manifest['model_seed']+epoch).permutation(len(graphs['train1']))
        losses=[]
        for i in range(0,len(order),8):
            batch=[graphs['train1'][j] for j in order[i:i+8]];x,m,pe,v=batch_tensors(batch,'cpu')
            opt.zero_grad();loss=(model(x,m,pe)[:,0]-x[:,0]).square().mean();loss.backward();opt.step();losses.append(float(loss.detach()))
        model.eval();vs=[]
        with torch.inference_mode():
            for i in range(0,len(graphs['validation']),8):
                x,m,pe,v=batch_tensors(graphs['validation'][i:i+8],'cpu')
                vs.extend((model(x,m,pe)[:,0]-x[:,0]).square().mean(-1).tolist())
        vl=float(np.mean(vs));history.append({'epoch':epoch+1,'train_target_mse':float(np.mean(losses)),'validation_target_mse':vl})
        if vl<best:best=vl;state=copy.deepcopy(model.state_dict())
        print('pilot',history[-1],flush=True)
    model.load_state_dict(state)
    torch.save({'model':state,'manifest':manifest,'config':cfg},out/'pilot-p8-raw-past.pt')
    counts=collections.Counter(len(g[0])-1 for g in graphs['train1'])
    result={'scope':'one p8 raw/past train+benign-validation feasibility run; no test performance',
            'graph_setup_seconds':setup,'total_seconds':time.perf_counter()-start,'history':history,
            'train_neighbor_counts':dict(sorted(counts.items())),
            'model_parameters':sum(v.numel() for v in model.parameters()),'device':'cpu','torch':torch.__version__,
            'implementation_sha256':sha(__file__),'manifest_sha256':sha(out/'pilot-manifest.json')}
    # Simple controls use the identical target IDs. Only benign validation scores are summarized.
    controls={}
    for p in (2,8):
        for masked in (False,True):
            x=np.stack([vector(r,p,masked) for r in target['train2']])
            val=np.stack([vector(r,p,masked) for r in target['validation']])
            overlap=set(map(bytes,x))&set(map(bytes,val))
            if overlap:
                controls[f'p{p}_{"mask" if masked else "raw"}']={
                    'status':'blocked: fit/validation share identical represented vectors',
                    'overlapping_vector_groups':len(overlap),'validation_rows':len(val)}
                continue
            forest=IsolationForest(n_estimators=150,random_state=manifest['model_seed'],n_jobs=2).fit(x)
            scores=-forest.score_samples(val);threshold=float(np.quantile(scores,.99,method='higher'))
            controls[f'p{p}_{"mask" if masked else "raw"}']={'validation_rows':len(val),'threshold':threshold,
                'validation_alerts':int(np.sum(scores>threshold)),'fit_ids':manifest['ids']['train2']}
    result['simple_control_validation']=controls
    dump(out/'pilot-results.json',result)

def main():
    a=argparse.ArgumentParser();a.add_argument('command',choices=['extract','gate','pilot']);args=a.parse_args()
    out=Path(__file__).resolve().parent/'local-2026-11-04'
    if args.command=='extract':extract(out);return
    rows=load(out/'ordered-flows.jsonl.gz')
    if args.command=='gate':
        manifest=make_manifest(rows,out);audit(rows,manifest,out)
    else:
        manifest=json.loads((out/'pilot-manifest.json').read_text())
        assert sha(out/'ordered-flows.jsonl.gz')==manifest['source_sha256']
        pilot(rows,manifest,out)

if __name__=='__main__':main()
