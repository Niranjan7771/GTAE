from pathlib import Path
import collections,csv,json,os
import numpy as np

base=Path(__file__).resolve().parent/'factorial-2026-11-04'
out=json.loads((base/'results.json').read_text());manifest=json.loads((base/'manifest.json').read_text())
scores=list(csv.DictReader((base/'scores.csv').open()))
groups=collections.defaultdict(list)
for r in scores:groups[(int(r['seed']),int(r['p']),r['field'],r['context'])].append(r)
for metric in out['metrics']:
    key=(metric['seed'],metric['p'],metric['field'],metric['context']);rows=groups[key]
    assert len(rows)==len(manifest['ids']['test'])
    assert set(r['id'] for r in rows)==set(manifest['ids']['test'])
    for label,entry in metric['per_class'].items():
        rs=[r for r in rows if r['label']==label]
        assert len(rs)==entry['n']
        assert sum(float(r['score'])>metric['threshold'] for r in rs)==entry['alerts']

tags=[('raw','self'),('raw','past'),('mask','self'),('mask','past'),('raw','tabular'),('mask','tabular')]
label=lambda f,c: f'{f} / {c}'
lines=['# Development field/context experiment — measured results, 4 November 2026','',
'**Status: exploratory development evidence. This is not an exact GTAE reproduction, a proven improvement, or an independent generalization test.**','',
'Twenty-four independent reconstruction fits completed: raw/masked header × self/past context × p2/p8 × three seeds, fixed 20 epochs. Twelve simple Isolation Forest controls use the same identities and packet vectors. Each neural arm fits an Isolation Forest on its benign train2 embeddings. The declared 1%/5% settings are benign-validation quantiles, not guaranteed operational false-alert rates.','',
'## Frozen population and causal input checks','',
f"Selected benign targets: {manifest['counts']['train1']['selected']} train1, {manifest['counts']['train2']['selected']} train2, {manifest['counts']['validation']['selected']} validation, {manifest['counts']['test']['selected']} test. Test attacks: 100 DDoS, 100 Slowloris, 10 FTP; all targets have eight observed packets, so p2/p8 use identical IDs.",'',
'Masked-p2 feature groups do not cross target fitting, validation and test partitions. The Monday capture was split by chronological target-start quantiles; p8 completion had to remain in its stage window. Repeating masked-p2 groups were retained only in their earliest stage. Test attack classes were capped by fixed identity hash before scores. Each decision uses all observed sessions in its capture, without a label/split/final-length context filter.','',
'Physical PCAP record indices and a running timestamp maximum over every raw record fix availability and recency. Every selected decision was rebuilt from its truncated visible history; all raw/masked and self/past graph tensors matched the full-history cutoff construction. Source IDs, code hashes, target IDs, graph receipts, histories and scores are saved beside this report.','',
'| Population | Eligible before group filter | Retained | Selected | Selected masked-p2 groups |',
'|---|---:|---:|---:|---:|']
for stage in ('train1','train2','validation','test'):
    c=manifest['counts'][stage];lines.append(f"| benign {stage} | {c['before_group_filter']} | {c['after_group_filter']} | {c['selected']} | {c['selected_group_count']} |")
for stage in ('DDoS','DoS Slowloris','FTP-Patator'):
    c=manifest['counts'][stage];lines.append(f"| {stage} | {c['eligible']} | — | {c['selected']} | {c['selected_masked_p2_groups']} |")

for budget in (.01,.05):
    lines.extend(['',f'## Conditional prefix results at nominal {100*budget:.0f}% validation budget','',
        'Values are mean [minimum, maximum] across the three fixed model seeds. Seed ranges are not confidence intervals. Attack TPR averages the declared 210 selected attacks; benign FPR uses 100 selected benign flows.','',
        '| p | Representation / context | Attack TPR % | Benign FPR % |','|---:|---|---:|---:|'])
    for p in (2,8):
        for field,context in tags:
            rs=[r for r in out['metrics'] if r['p']==p and r['field']==field and r['context']==context and r['nominal_budget']==budget]
            fmt=lambda key:f"{100*np.mean([r[key] for r in rs]):.2f} [{100*min(r[key] for r in rs):.2f}, {100*max(r[key] for r in rs):.2f}]"
            lines.append(f'| {p} | {label(field,context)} | {fmt("test_attack_TPR")} | {fmt("test_benign_FPR")} |')
lines.extend(['','## Interpretation limits','',
'All benign rows are from a Monday prefix and all attack labels from bounded later-day samples. Labels are reused schedule/endpoint-derived development labels rather than independently joined provider CSV labels. Differences can reflect capture conditions. DDoS test flows represent only one masked-p2 signature; they are not 100 independent signatures. The validation set has 139 rows from 55 masked-p2 groups, so 1% is a coarse calibration target. Group filtering substantially changes cohort coverage.','',
'The neural models are a target-edge reconstruction adaptation with one IF detector, not the source four-detector GTAE ensemble. Context and field arms have identical declared target IDs, architectures, fit budgets and seeds. The result supports local mechanism diagnostics only. Prefix metrics are conditional on matched p8 eligibility and a capped case-control sample; they are not all-flow opportunity recall, multi-prefix first-alert performance, calibrated deployment precision, or attack-onset detection.','',
'No winner was selected or retuned after test scoring. Test labels/features defined the fixed class caps and input checks; only test scores were withheld until the manifest and invariants were fixed. The metadata phrase `test_opened_after_manifest_and_invariant_checks` refers to test scores, not previously unobserved labels. Full-source verification and independent transfer remain pending.','',
'The original runner omitted validation-score export. `recover_calibration.py` recovered it through frozen neural checkpoints and deterministic IF reconstruction, with no neural refit or selection. All 11,160 test scores and 72 thresholds/counts match exactly. The archive now includes 5,004 validation scores, detectors and embeddings, with hashes in `calibration-recovery.json`.','',
'## Reproduce','',
'From FYP:','',
'```sh',
'GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/field_context.py extract',
'GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/run_factorial.py prepare',
'GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/run_factorial.py run',
'GTAE/.venv/bin/python GTAE-Improvement-Paper-2026-11-03/experiments/summarize_factorial.py','```','',
'The saved completed output should be inspected before rerunning; source/capture hashes are enforced. Local timing describes this small CPU experiment and is not a packet-throughput claim.'])
(base/'RESULTS.md').write_text('\n'.join(lines)+'\n')

os.environ.setdefault('MPLCONFIGDIR',str(base/'mpl-cache'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams.update({'font.size':12,'axes.labelsize':12,'xtick.labelsize':11.5,'ytick.labelsize':11})
fig,axs=plt.subplots(2,2,figsize=(10,6.8),sharex='col')
colors=['#467EAA','#103E62','#D4A05A','#AD5F28','#8B949C','#4F5A63']
for col,p in enumerate((2,8)):
    for row,(key,title) in enumerate((('test_attack_TPR','Attack TPR (%)'),('test_benign_FPR','Benign FPR (%)'))):
        ax=axs[row,col]
        for j,(field,context) in enumerate(tags):
            rs=[r for r in out['metrics'] if r['p']==p and r['field']==field and r['context']==context and r['nominal_budget']==.01]
            vals=[100*r[key] for r in rs]
            ax.bar(j,np.mean(vals),color=colors[j],alpha=.8,width=.7)
            ax.scatter(np.array([j]*len(vals))+np.linspace(-.12,.12,len(vals)),vals,s=19,color='#152737',zorder=4)
        ax.set_ylabel(title);ax.set_ylim(0,105);ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
        if row==0:ax.set_title(f'p{p}, nominal 1% validation budget',fontsize=12)
        ax.set_xticks(range(6),[label(*x).replace(' / ','\n') for x in tags],fontsize=11.5)
fig.suptitle('Development prefix metrics (3 seeds)\nCapture-day confounding; repeated signatures; no generalization claim',fontsize=14)
fig.tight_layout(rect=[0,0,.99,.92])
fig.savefig(base/'development-results.png',dpi=180);fig.savefig(base/'development-results.pdf')
print('all confusion counts independently recomputed from saved scores;',len(out['metrics']),'metric rows')
