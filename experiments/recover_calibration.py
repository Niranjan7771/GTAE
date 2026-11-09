"""Recover missing calibration artifacts from frozen project model checkpoints.

No neural fitting or selection. Deterministically reconstruct IF fits, then
require every saved test score and threshold to match before exporting.
"""
import collections,csv,json
from pathlib import Path
import joblib,numpy as np,torch
from sklearn.ensemble import IsolationForest
import field_context as fc
import run_factorial as runner
from gtae_ids.model import GTAE

out=runner.OUT;m=json.loads((out/'manifest.json').read_text());results=json.loads((out/'results.json').read_text())
assert fc.sha(runner.DATA/'ordered-flows.jsonl.gz')==m['source_sha256']
for name,h in m['scripts'].items():assert fc.sha(runner.HERE/name)==h
rows=fc.load(runner.DATA/'ordered-flows.jsonl.gz');byid={r['id']:r for r in rows}
source=collections.defaultdict(list)
for r in rows:source[r['source']].append(r)
rawgraphs={}
for p in (2,8):
    for context in ('self','past'):
        for stage in ('train2','validation','test'):
            rawgraphs[(p,context,stage)]=[fc.graph(byid[i],source[byid[i]['source']],p,context=context)[0] for i in m['ids'][stage]]
saved=collections.defaultdict(dict)
for r in csv.DictReader((out/'scores.csv').open()):saved[(int(r['seed']),int(r['p']),r['field'],r['context'])][r['id']]=float(r['score'])
torch.set_num_threads(2)
def encode(model,graphs):
    model.eval();zs=[]
    with torch.inference_mode():
        for i in range(0,len(graphs),8):
            x,mask,pe,_=fc.batch_tensors(graphs[i:i+8],'cpu');zs.append(model.encode(x,mask,pe)[:,0].numpy())
    return np.concatenate(zs)
calibration=[];receipts=[]
for seed in m['seeds']:
    for p in (2,8):
        for field in ('raw','mask'):
            for context in ('self','past','tabular'):
                tag=f'{seed}-p{p}-{field}-{context}';dest=out/'calibration'/tag;dest.mkdir(parents=True,exist_ok=True)
                before=None
                if context=='tabular':
                    z={k:np.stack([fc.vector(byid[i],p,field=='mask') for i in m['ids'][k]]) for k in ('train2','validation','test')}
                else:
                    path=out/'models'/tag/'model.pt';before=fc.sha(path)
                    checkpoint=torch.load(path,map_location='cpu',weights_only=True)
                    model=GTAE(p,m['model_config']);model.load_state_dict(checkpoint['model'])
                    z={k:encode(model,runner.transform(rawgraphs[(p,context,k)],p,field=='mask')) for k in ('train2','validation','test')}
                    assert fc.sha(path)==before
                forest=IsolationForest(n_estimators=150,random_state=seed,n_jobs=2).fit(z['train2'])
                ts=-forest.score_samples(z['test']);vs=-forest.score_samples(z['validation'])
                expected=np.array([saved[(seed,p,field,context)][i] for i in m['ids']['test']])
                np.testing.assert_allclose(ts,expected,rtol=0,atol=1e-12)
                for metric in results['metrics']:
                    if (metric['seed'],metric['p'],metric['field'],metric['context'])!=(seed,p,field,context):continue
                    threshold=float(np.quantile(vs,1-metric['nominal_budget'],method='higher'))
                    assert abs(threshold-metric['threshold'])<=1e-12
                    assert int(np.sum(vs>threshold))==metric['validation_alerts']
                np.savez_compressed(dest/'embeddings.npz',**z,
                    **{k+'_ids':np.array(m['ids'][k]) for k in ('train2','validation','test')})
                joblib.dump(forest,dest/'detector.joblib')
                calibration.extend({'seed':seed,'p':p,'field':field,'context':context,'id':i,'score':float(s)} for i,s in zip(m['ids']['validation'],vs))
                receipts.append({'tag':tag,'test_scores_verified':len(ts),'max_absolute_difference':float(np.max(abs(ts-expected))),
                    'checkpoint_sha256':before,'detector_sha256':fc.sha(dest/'detector.joblib'),
                    'embeddings_sha256':fc.sha(dest/'embeddings.npz')})
                print('RECOVERED',tag,flush=True)
with (out/'validation-scores.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(calibration[0]));w.writeheader();w.writerows(calibration)
fc.dump(out/'calibration-recovery.json',{'status':'all original test scores/thresholds reproduced, no neural refit',
    'script_sha256':fc.sha(__file__),'receipts':receipts,'validation_score_rows':len(calibration),
    'note':'original runner omitted validation-score export; deterministic IF refits recovered artifacts, all checkpoints unchanged'})
