"""Frozen development factorial with chronological, feature-group-disjoint targets.

All context is taken from actual past sessions in the same capture, without
label, split or final-length filters. This is not an independent final test.
"""
import argparse,collections,copy,csv,hashlib,json,random,time
from pathlib import Path
import numpy as np
import field_context as fc

HERE=Path(__file__).resolve().parent
DATA=HERE/'local-2026-11-04'
OUT=HERE/'factorial-2026-11-04'

def group(r):return fc.vector(r,2,True).tobytes()

def prepare(rows):
    OUT.mkdir(exist_ok=True)
    monday=[r for r in rows if fc.is_benign(r['label'])]
    sources={r['source'] for r in monday};assert len(sources)==1
    source_audit=json.loads((DATA/'source-audit.json').read_text())
    last=next(s['stats']['records'] for s in source_audit['sources'] if Path(s['source']).name in sources)
    candidates=sorted([r for r in monday if r['initial_syn'] and len(r['bytes'])>=400],key=lambda r:(r['records'][0],r['id']))
    # Equal raw-record windows left <16 retained test targets because a few
    # long sessions dominate the capture tail. Use chronological target-start
    # quantiles instead, chosen before any detector scores have been produced.
    bounds=[candidates[int(len(candidates)*f)]['records'][0]-1 for f in (.4,.6,.8)]+[last]
    names=['train1','train2','validation','test'];buckets={k:[] for k in names}
    skipped=collections.Counter();allgroups={};before=collections.Counter()
    for r in candidates:
        j=next(i for i,b in enumerate(bounds) if r['records'][0]<=b)
        if r['records'][7]>bounds[j]:skipped['crosses_temporal_boundary']+=1;continue
        stage=names[j];before[stage]+=1;k=group(r)
        if k in allgroups and allgroups[k]!=stage:
            skipped[f'{stage}_repeated_earlier_masked_p2_group']+=1;continue
        allgroups[k]=stage;buckets[stage].append(r)
    caps={'train1':128,'train2':128,'validation':200,'test':100}
    counts={};selected={}
    for stage,rs in buckets.items():
        ordered=sorted(rs,key=lambda r:hashlib.sha256(('20261104|'+r['id']).encode()).hexdigest())
        selected[stage]=ordered[:caps[stage]]
        counts[stage]={'before_group_filter':before[stage],'after_group_filter':len(rs),
            'group_count':len({group(r) for r in rs}),'selected':len(selected[stage]),
            'selected_group_count':len({group(r) for r in selected[stage]})}
        if len(selected[stage])<16:raise ValueError(f'{stage} has too little support even for development pilot')
    attackgroups=collections.defaultdict(list)
    for r in rows:
        if r['label']!='UNLABELED' and not fc.is_benign(r['label']) and r['initial_syn'] and len(r['bytes'])>=400:
            attackgroups[r['label']].append(r)
    fitgroups={group(r) for k in names[:-1] for r in selected[k]}
    for label,rs in sorted(attackgroups.items()):
        rs=sorted(rs,key=lambda r:hashlib.sha256(('20261104|'+r['id']).encode()).hexdigest())
        chosen=[r for r in rs if group(r) not in fitgroups][:100]
        selected['test'].extend(chosen)
        counts[label]={'eligible':len(rs),'selected':len(chosen),
                       'eligible_masked_p2_groups':len({group(r) for r in rs}),
                       'selected_masked_p2_groups':len({group(r) for r in chosen})}
    # The chronology guard prevents any eventual heldout target from contributing
    # even a partial prefix to the fitting/validation graph snapshots.
    endfit=max(r['records'][7] for k in names[:-1] for r in selected[k])
    for r in selected['test']:
        if r['source'] in sources:assert r['records'][0]>bounds[2]>=endfit
    sets={k:{group(r) for r in rs} for k,rs in selected.items()}
    for i,a in enumerate(names):
        for b in names[i+1:]:assert not sets[a]&sets[b],(a,b)
    manifest={'status':'exploratory development experiment; previously explored data and capture-day confounding',
        'source_sha256':fc.sha(DATA/'ordered-flows.jsonl.gz'),
        'record_boundaries':bounds,'last_raw_record':last,'benign_source':next(iter(sources)),
        'split_policy':'40/20/20/20 eligible target-start chronological quantiles; SYN and p8 within window; masked-p2 group retained only earliest window',
        'preflight_change':'equal raw-record windows failed minimum16 retained benign test targets; changed before producing detector scores',
        'context_policy':'all observed sessions in same source; no label/split/length filter; 60s all-record clock; 128 edges',
        'loss':'target-edge MSE only, new matched adaptation, not R0 full-graph MSE',
        'epochs':20,'checkpoint_selection':'fixed final epoch; no validation selection',
        'seeds':[20261104,20261105,20261106],'packet_counts':[2,8],
        'fields':['raw','mask'],'contexts':['self','past'],'counts':counts,'excluded':dict(skipped),
        'ids':{k:[r['id'] for r in rs] for k,rs in selected.items()},
        'model_config':json.loads((fc.ROOT/'GTAE/configs/paper.json').read_text()),
        'detector':'IsolationForest,150 trees,default score settings; same seed as neural model',
        'calibration':'negative score_samples; benign validation higher quantiles at .99 and .95, strict >',
        'test_scope':'fixed cap100 per class, matched >=8 targets for both p; conditional metrics, no prevalence claim',
        'scripts':{'field_context.py':fc.sha(HERE/'field_context.py'),'run_factorial.py':fc.sha(__file__)},
        'inherited_source_hashes':{name:fc.sha(fc.ROOT/'GTAE/src/gtae_ids'/name)
                                   for name in ('model.py','graphs.py','packets.py','data.py')}}
    fc.dump(OUT/'manifest.json',manifest)
    for file in manifest['scripts']:(OUT/file).write_bytes((HERE/file).read_bytes())
    print('FROZEN',json.dumps(counts),flush=True)

def graphs_and_invariants(rows,manifest):
    byid={r['id']:r for r in rows};source=collections.defaultdict(list)
    for r in rows:source[r['source']].append(r)
    graphs={};receipts=[]
    for p in manifest['packet_counts']:
        for context in manifest['contexts']:
            for stage,ids in manifest['ids'].items():
                values=[]
                for ident in ids:
                    target=byid[ident];universe=source[target['source']]
                    g,receipt=fc.graph(target,universe,p,context=context)
                    # Rebuild from a truncated stream, not from future-complete flow metadata.
                    prefix=[]
                    for row in universe:
                        n=__import__('bisect').bisect_right(row['records'],receipt['cutoff'])
                        if not n:continue
                        r=dict(row);r['records']=row['records'][:n];r['observed_times']=row['observed_times'][:n]
                        r['bytes']=row['bytes'][:50*min(n,8)];prefix.append(r)
                    gp,rp=fc.graph(target,prefix,p,context=context)
                    assert receipt==rp
                    for a,b in zip(g,gp):np.testing.assert_array_equal(a,b)
                    # Mask changes only the declared feature positions; graph/PE stay fixed.
                    gm,rm=fc.graph(target,prefix,p,masked=True,context=context)
                    assert receipt==rm
                    np.testing.assert_array_equal(g[1],gm[1]);np.testing.assert_array_equal(g[2],gm[2])
                    values.append(g)
                    receipts.append({'p':p,'context':context,'stage':stage,'target':ident,**receipt})
                graphs[(p,context,stage)]=values
    fc.dump(OUT/'graph-receipts.json',receipts)
    fc.dump(OUT/'invariant-checks.json',{'passed':True,'decisions_checked':len(receipts),
        'mask_arms_checked':2*len(receipts),'test_targets_checked':len(manifest['ids']['test']),
        'method':'full-capture history versus truncated visible stream, all targets/stages/prefix/context arms',
        'degree':{f'p{p}_{stage}':{'selected_context_mean':float(np.mean([r['neighbors'] for r in receipts if r['p']==p and r['context']=='past' and r['stage']==stage])),
            'incident_nonzero':sum(r['incident_neighbors']>0 for r in receipts if r['p']==p and r['context']=='past' and r['stage']==stage),
            'targets':len(manifest['ids'][stage])} for p in (2,8) for stage in manifest['ids']}})
    return graphs

def transform(graphs,p,masked):
    if not masked:return graphs
    positions=[j*50+d+k for j in range(p) for d in (0,25) for k in fc.MASK]
    result=[]
    for x,m,pe in graphs:
        x=x.copy();x[:,positions]=0;result.append((x,m,pe))
    return result

def run(rows,manifest):
    import torch
    import sklearn
    from sklearn.ensemble import IsolationForest
    from gtae_ids.model import GTAE
    torch.set_num_threads(2)
    graphs=graphs_and_invariants(rows,manifest)
    byid={r['id']:r for r in rows};testrows=[byid[i] for i in manifest['ids']['test']]
    labels=[r['label'] for r in testrows];records=[]
    allscores=[]
    def metrics(scores,val,seed,p,field,context):
        result=[]
        for alpha in (.01,.05):
            threshold=float(np.quantile(val,1-alpha,method='higher'));yp=scores>threshold
            count={label:{'n':labels.count(label),'alerts':sum(bool(y) for y,l in zip(yp,labels) if l==label)} for label in sorted(set(labels))}
            result.append({'seed':seed,'p':p,'field':field,'context':context,'nominal_budget':alpha,
                'threshold':threshold,'validation_n':len(val),'validation_alerts':int(np.sum(val>threshold)),
                'per_class':count,'test_benign_FPR':count['BENIGN']['alerts']/count['BENIGN']['n'],
                'test_attack_TPR':sum(v['alerts'] for k,v in count.items() if k!='BENIGN')/sum(v['n'] for k,v in count.items() if k!='BENIGN')})
        allscores.extend({'seed':seed,'p':p,'field':field,'context':context,'id':r['id'],'label':r['label'],'score':float(s)} for r,s in zip(testrows,scores))
        return result
    def encode(model,gs):
        vals=[];model.eval()
        with torch.inference_mode():
            for i in range(0,len(gs),8):
                x,m,pe,v=fc.batch_tensors(gs[i:i+8],'cpu');vals.append(model.encode(x,m,pe)[:,0].numpy())
        return np.concatenate(vals)
    start=time.perf_counter()
    for seed in manifest['seeds']:
        for p in manifest['packet_counts']:
            for field in manifest['fields']:
                masked=field=='mask'
                for context in manifest['contexts']:
                    tag=f'{seed}-p{p}-{field}-{context}';dest=OUT/'models'/tag;dest.mkdir(parents=True,exist_ok=True)
                    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
                    model=GTAE(p,manifest['model_config']);opt=torch.optim.Adam(model.parameters(),lr=.001)
                    gs={k:transform(graphs[(p,context,k)],p,masked) for k in manifest['ids']}
                    history=[];fitstart=time.perf_counter()
                    for epoch in range(manifest['epochs']):
                        model.train();order=np.random.default_rng(seed+epoch).permutation(len(gs['train1']));losses=[]
                        for i in range(0,len(order),8):
                            batch=[gs['train1'][j] for j in order[i:i+8]];x,m,pe,v=fc.batch_tensors(batch,'cpu')
                            opt.zero_grad();loss=(model(x,m,pe)[:,0]-x[:,0]).square().mean()
                            assert torch.isfinite(loss);loss.backward();opt.step();losses.append(float(loss.detach()))
                        model.eval();vls=[]
                        with torch.inference_mode():
                            for i in range(0,len(gs['validation']),8):
                                x,m,pe,v=fc.batch_tensors(gs['validation'][i:i+8],'cpu')
                                vls.extend((model(x,m,pe)[:,0]-x[:,0]).square().mean(-1).tolist())
                        vl=float(np.mean(vls));history.append({'epoch':epoch+1,'train':float(np.mean(losses)),'validation':vl})
                    finalstate=copy.deepcopy(model.state_dict())
                    z={k:encode(model,gs[k]) for k in ('train2','validation','test')}
                    forest=IsolationForest(n_estimators=150,random_state=seed,n_jobs=2).fit(z['train2'])
                    scores=-forest.score_samples(z['test']);val=-forest.score_samples(z['validation'])
                    records.extend(metrics(scores,val,seed,p,field,context))
                    torch.save({'model':finalstate,'seed':seed,'p':p,'field':field,'context':context},dest/'model.pt')
                    fc.dump(dest/'fit.json',{'history':history,'fit_seconds':time.perf_counter()-fitstart,
                        'parameters':sum(t.numel() for t in model.parameters()),'test_selected':False})
                    print('DONE',tag,round(time.perf_counter()-fitstart,2),flush=True)
                # Simple raw-header control, identical train2 and validation identities.
                data={k:np.stack([fc.vector(byid[i],p,masked) for i in ids]) for k,ids in manifest['ids'].items()}
                forest=IsolationForest(n_estimators=150,random_state=seed,n_jobs=2).fit(data['train2'])
                records.extend(metrics(-forest.score_samples(data['test']),-forest.score_samples(data['validation']),seed,p,field,'tabular'))
    fc.dump(OUT/'results.json',{'status':'complete development factorial; no generalization or improved-GTAE claim',
        'seconds':time.perf_counter()-start,'metrics':records,'test_opened_after_manifest_and_invariant_checks':True,
        'manifest_sha256':fc.sha(OUT/'manifest.json'),'torch':torch.__version__,
        'sklearn':sklearn.__version__,'numpy':np.__version__,'models':24})
    with (OUT/'scores.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(allscores[0]));w.writeheader();w.writerows(allscores)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['prepare','run']);args=parser.parse_args()
    rows=fc.load(DATA/'ordered-flows.jsonl.gz')
    if args.command=='prepare':prepare(rows)
    else:
        m=json.loads((OUT/'manifest.json').read_text());assert fc.sha(DATA/'ordered-flows.jsonl.gz')==m['source_sha256']
        for name,h in m['scripts'].items():assert fc.sha(HERE/name)==h,'Code changed after freeze'
        for name,h in m['inherited_source_hashes'].items():assert fc.sha(fc.ROOT/'GTAE/src/gtae_ids'/name)==h
        run(rows,m)

if __name__=='__main__':main()
