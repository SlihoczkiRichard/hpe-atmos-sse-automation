"""E2 thesis figures: scale-out timeline (E2-20261112-02) and activation milestones (-01 ... -05).

Usage: python 05-results/e2_figures.py <E2 results dir>
The results dir holds the lab.py run folders (E2-20261112-0N, each with runs.csv and scaler/) and
nginx_ip_per_min_20261112.txt (per-minute request counts per connector source address on the
backend, see docs/measurement-guide.md, Experiment 2). Writes <dir>/figures/e2_*.pdf and .png.
"""
import os, sys
if len(sys.argv) != 2:
    sys.exit(__doc__)
os.chdir(sys.argv[1]); os.makedirs("figures", exist_ok=True)
import csv, glob, re
from datetime import datetime as D, timezone, timedelta
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
C1C,C2C="#1f77b4","#e67e22"
RUNS=["E2-20261112-01","E2-20261112-02","E2-20261112-03","E2-20261112-04","E2-20261112-05"]
def events(d):
    ev={}
    for r in csv.reader(open(glob.glob(d+"/scaler/*_events.csv")[0])):
        if len(r)>2 and r[2] not in ev: ev[r[2]]=r
    s=ev["ACTIVATION_SUMMARY"][3]
    m={k:float(v) for k,v in re.findall(r"(VM_POWERED_ON|GUEST_REACHABLE|CONNECTOR_API_REPORTED_AVAILABLE)=verified\(\+([0-9.]+)s",s)}
    return ev,m
nginx={}
for line in open("nginx_ip_per_min_20261112.txt"):
    n,hm,ip=line.split(); nginx[(hm,ip)]=int(n)
# ---- Figure 1: representative run timeline
d="E2-20261112-02"
ev,m=events(d)
runs=list(csv.DictReader(open(d+"/runs.csv")))
L0=D.fromisoformat(runs[0]["started_utc"]); P=D.fromisoformat(ev["POWER_ON_SENT"][0])
p=(P-L0).total_seconds()
ts=list(csv.DictReader(open(glob.glob(d+"/scaler/*_timeseries.csv")[0])))
fig,(a1,a2)=plt.subplots(2,1,figsize=(9,5.6),sharex=True,gridspec_kw={"height_ratios":[1.1,1]})
for key,col,lab in (("c1_cpu_pct",C1C,"C1 (SR-CONN01)"),("c2_cpu_pct",C2C,"C2 (SR-CONN02)")):
    xs=[(D.fromisoformat(x["timestamp_utc"])-L0).total_seconds() for x in ts if x[key]]
    ys=[float(x[key]) for x in ts if x[key]]
    a1.plot(xs,ys,color=col,lw=1.2,marker=".",ms=3,label=lab+" CPU")
a1.axhline(80,color="#888",ls=":",lw=1); a1.text(-55,82,"küszöb 80 %",fontsize=8,color="#666")
marks=[(p-0.11,"trigger + POWER_ON",":"),(p+m["VM_POWERED_ON"],"VM on","-."),(p+m["GUEST_REACHABLE"],"guest SSH","--"),(p+m["CONNECTOR_API_REPORTED_AVAILABLE"],"API: Available","-")]
for ax in (a1,a2):
    for x,l,s in marks: ax.axvline(x,color="#444",ls=s,lw=0.9,label=l if ax is a1 else None)
a1.set_ylim(0,100); a1.set_ylabel("CPU [%]"); a1.legend(loc="upper center",bbox_to_anchor=(0.5,1.22),fontsize=8,frameon=False,ncol=3)
# bottom: req/s per connector per minute (nginx) + hey round throughput
start=L0.replace(second=0,microsecond=0)-timedelta(minutes=1)
for k in range(0,16):
    t=start+timedelta(minutes=k); hm=t.strftime("%H:%M"); x=(t-L0).total_seconds()
    v1=nginx.get((hm,"10.0.1.121"),0)/60; v2=nginx.get((hm,"10.0.1.122"),0)/60
    a2.bar(x,v1,width=58,align="edge",color=C1C,alpha=0.85,label="C1 (nginx)" if k==0 else None)
    a2.bar(x,v2,width=58,align="edge",bottom=v1,color=C2C,alpha=0.85,label="C2 (nginx)" if k==0 else None)
for r in runs:
    a=(D.fromisoformat(r["started_utc"])-L0).total_seconds(); b=(D.fromisoformat(r["ended_utc"])-L0).total_seconds()
    a2.plot([a,b],[float(r["successful_rps"])]*2,color="black",lw=2,label="hey kör átlaga" if r["sweep"]=="1" else None)
a2.set_ylim(0,4800); a2.set_ylabel("sikeres kérés/s"); a2.set_xlabel("idő a terhelés kezdete óta [s]")
a2.set_xlim(-60,780); a2.legend(loc="lower right",fontsize=8,frameon=False,ncol=3)
for ax in (a1,a2):
    for s in ("top","right"): ax.spines[s].set_visible(False)
fig.tight_layout(); fig.savefig("figures/e2_scaleout_timeline.pdf"); fig.savefig("figures/e2_scaleout_timeline.png",dpi=200)
# ---- Figure 2: activation milestones across reps
rows=[]
for d in RUNS:
    ev,m=events(d); runs=list(csv.DictReader(open(d+"/runs.csv")))
    P=D.fromisoformat(ev["POWER_ON_SENT"][0]); r2=D.fromisoformat(runs[1]["started_utc"])
    m["DATA"]=(r2-P).total_seconds(); rows.append(m)
keys=[("VM_POWERED_ON","VM bekapcsolva (vCenter)"),("GUEST_REACHABLE","vendég OS elérhető (SSH)"),("DATA","C2 forgalmat kap (nginx)*"),("CONNECTOR_API_REPORTED_AVAILABLE","portál API: Available")]
fig,ax=plt.subplots(figsize=(8,2.9))
for i,(k,l) in enumerate(keys):
    v=sorted(r[k] for r in rows); y=len(keys)-1-i
    ax.plot(v,[y]*len(v),"o",color="#5e35b1",ms=6,alpha=0.8)
    med=v[len(v)//2]; ax.plot([med],[y],"|",color="black",ms=18,mew=2)
    ax.text(158,y,(f"medián {med:.1f} s ({v[0]:.1f}–{v[-1]:.1f} s)").replace(".",","),va="center",fontsize=8)
ax.set_yticks(range(len(keys))); ax.set_yticklabels([l for _,l in keys][::-1],fontsize=9)
ax.set_xlim(0,240); ax.set_xlabel("idő a bekapcsolási parancs (POWER_ON_SENT) óta [s]")
for s in ("top","right"): ax.spines[s].set_visible(False)
ax.grid(axis="x",color="#eee")
fig.tight_layout(); fig.savefig("figures/e2_activation_milestones.pdf"); fig.savefig("figures/e2_activation_milestones.png",dpi=200)
print([ {k:round(v,1) for k,v in r.items()} for r in rows])
