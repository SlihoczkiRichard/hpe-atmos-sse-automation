"""E3 thesis figure: http probe of the five valid failover repetitions, aligned to the fault marker.

Usage: python 05-results/e3_figures.py <E3 results dir>
The results dir holds the lab.py e3 run folders (markers.csv, probes_http.csv,
probes_persistent.csv). Writes <dir>/figures/e3_failover_timeline.pdf and .png.
"""
import os, sys
if len(sys.argv) != 2:
    sys.exit(__doc__)
os.chdir(sys.argv[1]); os.makedirs("figures", exist_ok=True)
import csv, sys
from datetime import datetime as D
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
runs=[("CAL2","E3-20261109-CAL2"),("r03","E3-20261109-r03"),("r04","E3-20261114-r04"),("r05","E3-20261114-r05"),("r06","E3-20261114-r06")]
OK,FAIL,CLR,PER="#2e7d32","#c62828","#1565c0","#212121"
fig,ax=plt.subplots(figsize=(9,3.6))
for i,(lab,d) in enumerate(runs):
    y=len(runs)-1-i
    M={}
    for r in csv.DictReader(open(f"{d}/markers.csv")): M.setdefault(r["kind"],D.fromisoformat(r["utc"]))
    F=M["fault_injected"]; C=M["fault_cleared"]
    rows=[r for r in csv.DictReader(open(f"{d}/probes_http.csv")) if r["event"]=="probe"]
    t=[(D.fromisoformat(r["end_utc"])-F).total_seconds() for r in rows]; keep=[x<=840 for x in t]; rows=[r for r,k in zip(rows,keep) if k]; t=[x for x,k in zip(t,keep) if k]
    ok=[x for x,r in zip(t,rows) if r["ok"]=="True"]; bad=[x for x,r in zip(t,rows) if r["ok"]!="True"]
    ax.vlines(ok,y-0.3,y+0.3,color=OK,lw=0.6)
    ax.vlines(bad,y-0.3,y+0.3,color=FAIL,lw=0.9)
    c=(C-F).total_seconds(); ax.plot([c],[y+0.42],marker="v",color=CLR,ms=6,ls="none")
    pr=[r for r in csv.DictReader(open(f"{d}/probes_persistent.csv")) if r["event"]=="exchange" and r["ok"]!="True"]
    if pr:
        pb=(D.fromisoformat(pr[0]["end_utc"])-F).total_seconds(); ax.plot([pb],[y-0.42],marker="^",color=PER,ms=5,ls="none")
    fo=[x for x in ok if bad and x>bad[0]][0]
    ax.text(870,y,f"{fo:.0f} s",va="center",fontsize=9)
ax.axvline(0,color="#555",ls="--",lw=1)
ax.set_yticks(range(len(runs))); ax.set_yticklabels([l for l,_ in runs][::-1])
ax.set_xlim(-70,930); ax.set_ylim(-0.7,len(runs)-0.3)
ax.set_xlabel("idő a hiba (C2 vNIC bontása) óta [s]")
ax.text(870,len(runs)-0.45,"vissza:",fontsize=8,color="#555")
from matplotlib.lines import Line2D
h=[Line2D([],[],color=OK,lw=2,label="http kérés sikeres"),Line2D([],[],color=FAIL,lw=2,label="http kérés timeout"),
   Line2D([],[],marker="v",color=CLR,ls="none",label="C2 visszakapcsolva"),Line2D([],[],marker="^",color=PER,ls="none",label="persistent kapcsolat megszakad")]
ax.legend(handles=h,loc="upper center",bbox_to_anchor=(0.5,-0.22),ncol=4,frameon=False,fontsize=8)
for s in ("top","right"): ax.spines[s].set_visible(False)
fig.tight_layout()
fig.savefig("figures/e3_failover_timeline.pdf"); fig.savefig("figures/e3_failover_timeline.png",dpi=200)
print("ok")
