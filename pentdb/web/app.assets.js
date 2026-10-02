// PentDB 面板 · 资产明细视图：左树右表 / 实体下钻分区明细（属性卡·关联漏洞·证据·参数表·原始观测折叠）/ 手动补录区联动（#asset-tree 事件委托）
let adTab="ov";  // 详情页签态（ov/vuln/ev/raw），跨条目保持——连续查看同类信息不跳回
let codeGroups=[];  // 响应码语义组多选：2xx/3xx/wall/404/5xx/none
const CODE_GROUPS=[["2xx","2xx 可交互"],["3xx","3xx 跳转"],["wall","401/403 墙"],["404","4xx 其他"],["5xx","5xx 异常"],["none","未探测"]];
function reviewTag(r){
  return r==="pending"?`<span class="tag t-new">有待审</span>`
    :r==="confirmed"?`<span class="tag t-confirmed">已确认</span>`
    :`<span class="tag t-rejected">已驳回</span>`;
}
async function loadAssets(){
  const params={project:PROJECT,atype:$("#f-atype").value,status:$("#f-status").value,q:$("#f-q").value,code_group:codeGroups.join(",")};
  const d=await api("assets",params);
  let assets=d.assets||[], sum=d.summary||{};
  // 树选中锚定：在服务端过滤结果之上叠加子树成员集合过滤（区分树锚定语境，避免与"真实无资产"混读）
  const treeOn=!!(TREE.sel&&TREE.selSet);
  if(treeOn){const s=TREE.selSet;assets=assets.filter(a=>s.has(a.atype+"/"+a.akey));}
  const hint=Object.keys(sum).sort().map(k=>`${k} ${sum[k]}`).join(" · ");
  $("#asset-hint").textContent=(treeOn?`树锚定 · 子树匹配 ${assets.length} 条 ｜ `:`实体 ${assets.length} ｜ `)+hint;
  const head="<tr><th>实体（规范 key）</th><th>类型</th><th>上级</th><th>属性</th><th>观测 / 审</th><th>范围</th><th>首见 · 末见</th><th>生命周期</th></tr>";
  const rows=assets.map(a=>{
      const sc=a.attrs.scopes||[];
      const scope=sc.includes("in")?"in":(sc.length&&sc.every(x=>x==="out")?"out":"unknown");
      const chips=[];
      (a.attrs.ports||[]).forEach(x=>chips.push(":"+x));
      (a.attrs.services||[]).forEach(x=>chips.push(x));
      (a.attrs.techs||[]).forEach(x=>chips.push(x));
      (a.attrs.params||[]).forEach(x=>chips.push("?"+x));
      (a.attrs.codes||[]).forEach(x=>chips.push("HTTP "+x));
      return `<tr class="arow ${selAsset===a.atype+"/"+a.akey?"on":""}" data-ak="${esc(a.atype+"/"+a.akey)}">`+
        `<td title="${esc(a.akey)}"><b>${esc(a.akey)}</b></td><td>${kindTag(a.atype)}</td>`+
        `<td class="muted" title="${a.parent_akey?esc(a.parent_atype+" : "+a.parent_akey):""}">${a.parent_akey?esc(a.parent_atype+" : "+a.parent_akey):"—"}</td>`+
        `<td>${chips.map(c=>`<span class="tag t-kind">${esc(c)}</span>`).join(" ")||'<span class="muted">—</span>'}</td>`+
        `<td>${a.obs} 条 ${reviewTag(a.review)}</td>`+
        `<td>${scopeTag(scope)}</td>`+
        `<td class="muted">${(a.first_seen||"").slice(0,10)} · ${(a.last_seen||"").slice(0,10)}</td>`+
        `<td>${a.stale?'<span class="tag t-rejected">stale</span>':'<span class="tag t-confirmed">active</span>'}</td></tr>`;
    }).join("");
  $("#asset-table").innerHTML=head+(rows||"<tr><td>"+
    (treeOn?"树锚定下无匹配资产（可点上方提示条 ✕ 清除锚定）":"无资产（rebuild-assets 可随时重建）")+
    "</td></tr>");
  if(selAsset&&!assets.some(a=>a.atype+"/"+a.akey===selAsset)){selAsset=null;$("#asset-detail").innerHTML="<span class='muted'>← 点击资产行下钻原始观测</span>";}
  else renderAssetDetail();
}
$("#asset-table").onclick=e=>{
  const row=e.target.closest(".arow"); if(!row)return;
  const k=row.dataset.ak;
  selAsset=(selAsset===k)?null:k;
  loadAssets();
};
function renderCodeChips(){
  $("#code-chips").innerHTML=CODE_GROUPS.map(([v,l])=>
    `<span class="sev-chip ${codeGroups.includes(v)?"on":""}" data-cg="${v}">${l}</span>`).join("");
}
$("#code-chips").onclick=e=>{
  const g=e.target.dataset&&e.target.dataset.cg; if(!g)return;
  codeGroups=codeGroups.includes(g)?codeGroups.filter(x=>x!==g):[...codeGroups,g];
  renderCodeChips(); loadAssets();
};
renderCodeChips();

async function renderAssetDetail(){
  const box=$("#asset-detail");
  if(!selAsset){box.innerHTML="<span class='muted'>← 点击资产行下钻原始观测</span>";return;}
  const i=selAsset.indexOf("/");
  const atype=selAsset.slice(0,i), akey=selAsset.slice(i+1);
  const all=(await api("assets",{project:PROJECT,atype})).assets.find(a=>a.akey===akey);
  if(!all){box.innerHTML="";return;}
  let det={findings:[],evidence:[]};
  try{det=await api("asset-detail",{project:PROJECT,atype,akey});}
  catch(e){box.innerHTML=`<span class='muted'>资产明细加载失败：${esc(e.message)}</span>`;return;}
  const evs=(await api("events",{project:PROJECT,ids:all.event_ids.join(",")})).events||[];
  const attrs=all.attrs||{};
  // —— 页签化（对齐发现页 fd-tabs；成熟产品通行的固定详情栏+页签切内容，如 Burp Request/Response）——
  // ov=摘要+属性+参数清单 ｜ vuln=关联漏洞 ｜ ev=探测报文+证据 ｜ raw=原始观测回放 ｜ probe=探测观测（仅 host/domain）
  const showProbe=(atype==="host"||atype==="domain");
  const tabs=[["ov","概览"],["vuln","关联漏洞"],["ev","报文·证据"],["raw","观测回放"]];
  if(showProbe)tabs.push(["probe","探测观测"]);
  if(!tabs.some(t=>t[0]===adTab))adTab="ov";  // 跨条目保持的页签在新条目不存在时回落概览
  let html=`<div class="muted" style="margin-bottom:6px"><b>${esc(akey)}</b> ｜ 首见 ${(all.first_seen||"").slice(0,10)} ｜ 末见 ${(all.last_seen||"").slice(0,10)} ｜ ${all.obs} 条观测 ${reviewTag(all.review)} ${all.stale?'<span class="tag t-rejected">stale</span>':'<span class="tag t-confirmed">active</span>'}</div>`;
  html+=`<div class="fd-tabs" id="ad-tabs">${tabs.map(([k,label])=>
    `<span class="fd-tab ${adTab===k?"on":""}" data-adtab="${k}">${label}</span>`).join("")}</div>`;
  // —— 概览：摘要行 + 结构化属性卡（Goby 式分组标签）+ 参数清单 ——
  const ATTR_META=[["ports","端口"],["services","服务"],["techs","技术栈"],["params","参数"],["codes","状态码"],["titles","标题"],["scopes","范围"]];
  const cards=ATTR_META.filter(([k])=>(attrs[k]||[]).length).map(([k,label])=>
    `<div class="attr-card"><span class="al">${label}</span>`+
    attrs[k].map(x=>`<span class="tag t-kind">${esc(x)}</span>`).join("")+`</div>`).join("");
  let ov=`<div class="ad-h">属性</div>`+(cards?`<div class="attr-cards">${cards}</div>`:`<span class='muted'>无结构化属性</span>`);
  const params=attrs.params||[];
  if(params.length)ov+=`<div class="ad-h">参数清单（注入面判断）</div>`+
    `<table><tr><th>参数名</th></tr>`+params.map(p=>`<tr><td>${esc(p)}</td></tr>`).join("")+`</table>`;
  // —— 关联漏洞（finding/osint 按 parent_ext 归属，按严重度分组排序）——
  const order=SEVS.map(s=>s[0]);
  const bySev={};
  (det.findings||[]).forEach(f=>{(bySev[f.severity||""]=bySev[f.severity||""]||[]).push(f)});
  const sevHtml=order.filter(s=>bySev[s]).map(s=>
    `<div class="ad-sev"><span class="tag sev-${s||"none"}">${sevLabel(s)} × ${bySev[s].length}</span>`+
    bySev[s].map(f=>`<div class="rec"><div class="hd"><b>#${f.id}</b> ${kindTag(f.kind)} <b>${esc(f.title||f.value)}</b> ${lifeTag(lifeOf(f))} ${tag(f.status)}</div>`+
      `<div class="src">归因: ${esc(f.parent_ext||"—")}</div></div>`).join("")+`</div>`).join("");
  let vuln=sevHtml||`<span class='muted'>无关联漏洞</span>`;
  // —— 报文·证据：探测报文（exec 自动解析）+ 证据直达 ——
  let ev="";
  const pkts=det.exec_packets||[];
  if(pkts.length){
    ev+=`<div class="ad-h">探测报文（exec 自动解析）</div>`+pkts.map(p=>{
      const hints=(EXEC_FLAG_HINTS||[]).filter(([k])=>(p.flags||{})[k]).map(([,s])=>s);
      return `<div class="pkt-card">`+
        `<div class="hd"><b>exec 自动解析</b><span class="muted">挂 test #${p.event_id} · sha256 ${esc((p.sha256||"").slice(0,16))}…</span>`+
        `<span style="flex:1"></span><button class="mini" data-ev="${p.ev_id}">查看原文</button></div>`+
        `<details open><summary>请求</summary><pre>${esc(p.request||"")}</pre></details>`+
        `<details><summary>响应</summary><pre>${esc(p.response||"")}</pre></details>`+
        (hints.length?`<div class="muted" style="font-size:12px;margin-top:2px">${esc(hints.join(" "))}</div>`:"")+
        `<pre class="hidden" id="evc-${p.ev_id}"></pre></div>`;
    }).join("");
  }
  const evHtml=(det.evidence||[]).map(e=>
    `<div class="rec"><div class="hd"><b>#${e.id}</b> <span class="tag t-kind">${esc(e.etype||"file")}</span> <b>${esc(e.note||e.ev_title||"")}</b>`+
    (e.exists?` <button class="mini" data-ev="${e.id}">查看</button>`:` <span class="tag sev-crit">文件缺失</span>`)+
    `</div><div class="src" title="${esc(e.path)}">${esc(e.path)} ｜ ${esc(e.created_at||"")}</div></div>`+
    `<pre class="hidden" id="evc-${e.id}"></pre>`).join("");
  ev+=`<div class="ad-h">证据</div>`+(evHtml||`<span class='muted'>无证据</span>`);
  // —— 原始观测回放（整页签即回放，不再套折叠层）——
  const replay=evs.map(r=>
    `<div class="rec"><div class="hd"><b>#${r.id}</b> ${kindTag(r.kind)} <b>${esc(r.value)}</b> ${tag(r.status)}`+
    ` <span class="muted">${(r.created_at||"").slice(0,10)} · ${r.origin}${r.confidence?"/"+r.confidence:""}</span></div>`+
    (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
    `<div class="src">来源: ${esc(r.source)}</div></div>`).join("")||"<span class='muted'>无观测记录</span>";
  html+=[["ov",ov],["vuln",vuln],["ev",ev],["raw",replay]].concat(showProbe?[["probe",""]]:[]).map(([k,c])=>
    `<div id="ad-${k}" class="${adTab!==k?"hidden":""}">${c}</div>`).join("");
  box.className="";
  box.innerHTML=html;
  if(showProbe)await renderProbePane(akey,atype==="host"||atype==="domain");
}

// ---------------- 探测观测（Burp 式：扫描所见逐条可查，过滤在视图层） ----------------
// 双视图：目录（AWVS Sites 式，host+path 去重取最新观测，按路径段合成目录树）｜ 流水（逐条观测审计）
let PROBE={rows:[],groups:[],q:"",view:"dir",exp:{},canTree:false,akey:"",sel:""};
const PROBE_GROUPS=[["2xx","2xx 可交互"],["3xx","3xx 跳转"],["wall","401/403 墙"],["404","404 软目标"],["5xx","5xx/其他"]];
function probeGroup(s){s=parseInt(s,10)||0;
  if(s>=200&&s<300)return "2xx"; if(s>=300&&s<400)return "3xx";
  if(s===401||s===403)return "wall"; if(s===404)return "404"; return "5xx";}
async function renderProbePane(akey,canTree){
  const box=$("#ad-probe");if(!box)return;
  box.innerHTML="<span class='muted'>探测观测加载中…</span>";
  let rows=[];
  try{rows=(await api("probes",{project:PROJECT,host:akey})).probes||[];}
  catch(e){box.innerHTML=`<span class='muted'>探测观测加载失败：${esc(e.message)}</span>`;return;}
  PROBE.rows=rows;PROBE.akey=akey;PROBE.canTree=!!canTree;
  PROBE.exp={};
  renderProbeFrame();
}
function probeFiltered(){  // 过滤在视图层共享：状态组+路径搜索对两种视图同口径
  const q=PROBE.q.toLowerCase();
  return PROBE.rows.filter(r=>{const a=r.attrs||{};
    if(PROBE.groups.length&&!PROBE.groups.includes(probeGroup(a.status)))return false;
    return !q||(a.path||"").toLowerCase().includes(q)||(r.value||"").toLowerCase().includes(q);});
}
function probeDedup(rows){  // host+path 去重：API 按 id 倒序，首个即最新观测；其余进历史（正序重排）
  const m={};
  rows.forEach(r=>{const k=(r.value||"")+" "+((r.attrs||{}).path||"");
    if(!m[k])m[k]={latest:r,hist:[]};else m[k].hist.push(r);});
  Object.values(m).forEach(it=>it.hist.reverse());
  return Object.values(m);
}
function renderProbeFrame(){
  const box=$("#ad-probe");if(!box)return;
  const uniq=probeDedup(PROBE.rows).length;
  const nhosts=new Set(PROBE.rows.map(r=>(r.value||"").toLowerCase())).size;
  const cnt={};PROBE.rows.forEach(r=>{const g=probeGroup((r.attrs||{}).status);cnt[g]=(cnt[g]||0)+1;});
  const chips=PROBE_GROUPS.map(([v,l])=>
    `<span class="sev-chip ${PROBE.groups.includes(v)?"on":""}" data-pg="${v}">${l} ${cnt[v]||0}</span>`).join("");
  const views=PROBE.canTree?`<span class="sev-chip ${PROBE.view==="dir"?"on":""}" data-pv="dir">目录</span>`+
    `<span class="sev-chip ${PROBE.view!=="dir"?"on":""}" data-pv="list">流水</span>`:"";
  box.innerHTML=`<div class="ad-h">探测观测（逐路径扫描全录 · 零门槛入观测层 · 不参与资产归并）｜ `+
    (PROBE.canTree?`唯一路径 ${uniq} ｜ `:"")+(nhosts>1?`host ${nhosts} 个 ｜ `:"")+`观测 ${PROBE.rows.length} 条</div>`+
    `<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap">`+
    views+
    `<input id="probe-q" placeholder="过滤路径…" value="${esc(PROBE.q)}" style="max-width:220px">`+
    `<span id="probe-chips">${chips}</span></div><div id="probe-body"></div><div id="probe-detail" class="pdetail hidden"></div>`;
  renderProbeBody();
}
function renderProbeBody(){
  const box=$("#probe-body");if(!box)return;
  if(PROBE.view==="dir"&&PROBE.canTree)renderProbeDir(box);
  else{renderProbeList(box);const d=$("#probe-detail");if(d){d.innerHTML="";d.classList.add("hidden");}}
}
function renderProbeList(box){
  const rows=probeFiltered();
  box.innerHTML=rows.length?`<table><tr><th>状态</th><th>长度</th><th>路径</th><th>类型</th><th>时间 · 来源</th></tr>`+
    rows.slice(0,400).map(r=>{const a=r.attrs||{};
      return `<tr><td><span class="pstat p-${probeGroup(a.status)}">${esc(a.status||"—")}</span></td>`+
        `<td class="muted">${esc(a.len||"—")}</td>`+
        `<td title="${esc((r.value||"")+(a.path||""))}">${esc(a.path||"—")}`+
        (a.location?` <span class="muted">→ ${esc(a.location)}</span>`:"")+
        (a.server?` <span class="tag t-kind">${esc(a.server)}</span>`:"")+
        `</td><td class="muted">${esc((a.ctype||"").split(";")[0]||"—")}</td>`+
        `<td class="muted" title="${esc(r.source||"")}">${(r.created_at||"").slice(0,16)} · ${esc((r.source||"").slice(0,26))}</td></tr>`;}).join("")+
    `</table>`+(rows.length>400?`<div class="muted">仅显示前 400 条（共 ${rows.length}），请用过滤条件收窄</div>`:"")
    :`<span class='muted'>无匹配探测观测（该 host 尚未做过目录扫描入库，或全被过滤条件挡住）</span>`;
}
// —— 目录视图（AWVS Sites 式）：去重后按路径段合成目录树，目录在前叶子在后，默认展开第一级目录 ——
// 多 host（domain 聚合）时顶层多一层 host 节点，各 host 独立成树（Burp Sites：不跨 host 合并目录），默认收起
function probeBuildTree(items){
  const root={children:new Map(),leaves:[]};
  items.forEach(it=>{
    const a=it.latest.attrs||{};
    const segs=(a.path||"/").split("/").filter(Boolean);
    let cur=root;
    segs.slice(0,-1).forEach(s=>{if(!cur.children.has(s))cur.children.set(s,{children:new Map(),leaves:[]});cur=cur.children.get(s);});
    cur.leaves.push(it);
  });
  return root;
}
function probeTreeHtml(n,depth,host,base,prefix){
  let html="";
  const cntLeaves=x=>{let c=x.leaves.length;x.children.forEach(ch=>c+=cntLeaves(ch));return c;};
  [...n.children.entries()].sort((x,y)=>x[0].localeCompare(y[0])).forEach(([name,ch])=>{
    const dirPath=prefix+name+"/", key="dir/"+host+"/"+depth+"/"+name;
    const open=PROBE.exp[key]!==undefined?PROBE.exp[key]:false;  // 默认全收起，点开逐层看（用户拍板）
    const sel="dir:"+host+":"+dirPath;
    html+=`<div class="pnode pdir${PROBE.sel===sel?" on":""}" data-psel="${esc(sel)}" style="padding-left:${depth*16+4}px">`+
      `<span class="pcaret" data-pexp="${esc(key)}">${open?"▾":"▸"}</span><span class="pdirname">${esc(name)}/</span>`+
      `<span class="tcount">${cntLeaves(ch)}</span></div>`;
    if(open)html+=probeTreeHtml(ch,depth+1,host,base,dirPath);
  });
  n.leaves.sort((x,y)=>((x.latest.attrs||{}).path||"").localeCompare((y.latest.attrs||{}).path||""));
  n.leaves.forEach(it=>{
    const a=it.latest.attrs||{};
    const path=a.path||"/";
    const segs=path.split("/").filter(Boolean);
    const label=segs.length?segs[segs.length-1]+(path.endsWith("/")?"/":""):"/";
    const sel="leaf:"+host+":"+path;
    html+=`<div class="pnode pleaf${PROBE.sel===sel?" on":""}" data-psel="${esc(sel)}" style="padding-left:${depth*16+4}px" title="${esc(host+path)}">`+
      `<span class="pcaret"><span class="pdot p-${probeGroup(a.status)}" title="HTTP ${esc(a.status||"—")}"></span></span>`+
      `<span class="plabel">${esc(label)}</span>`+
      (it.hist.length?`<span class="phist" title="共 ${it.hist.length+1} 轮观测，点行看历史">×${it.hist.length+1}</span>`:"")+
      `</div>`;
  });
  return html;
}
function renderProbeDir(box){
  const items=probeDedup(probeFiltered());
  const hosts={};
  items.forEach(it=>{const h=(it.latest.value||"?").toLowerCase();(hosts[h]=hosts[h]||[]).push(it);});
  const names=Object.keys(hosts).sort();
  if(!names.length){box.innerHTML="<span class='muted'>无匹配探测观测（或全被过滤条件挡住）</span>";renderProbeDetail();return;}
  let html="";
  if(names.length===1){  // host 详情：单棵目录树
    html=probeTreeHtml(probeBuildTree(hosts[names[0]]),0,names[0],0,"/");
  }else{  // domain 聚合：顶层 host 节点各自成树（默认收起，点开看该 host 的目录树）
    names.forEach(h=>{
      const key="host/"+PROBE.akey+"/"+h, sel="host:"+h+":";
      const open=PROBE.exp[key]!==undefined?PROBE.exp[key]:false;
      html+=`<div class="pnode phost${PROBE.sel===sel?" on":""}" data-psel="${esc(sel)}" style="padding-left:4px">`+
        `<span class="pcaret" data-pexp="${esc(key)}">${open?"▾":"▸"}</span><span class="pdirname">${esc(h)}</span>`+
        `<span class="tcount">${hosts[h].length}</span></div>`;
      if(open)html+=probeTreeHtml(probeBuildTree(hosts[h]),1,h,1,"/");
    });
  }
  box.innerHTML=html;
  renderProbeDetail();
}
// —— 详情区（master-detail 的 detail pane）：点树节点才出现，Location/长度/时间·来源/历史等元数据全在这里 ——
function renderProbeDetail(){
  const box=$("#probe-detail");if(!box)return;
  if(!PROBE.sel||PROBE.view!=="dir"){box.innerHTML="";box.classList.add("hidden");return;}
  box.classList.remove("hidden");
  const i=PROBE.sel.indexOf(":"),j=PROBE.sel.indexOf(":",i+1);
  const type=PROBE.sel.slice(0,i),host=PROBE.sel.slice(i+1,j),path=PROBE.sel.slice(j+1);
  const all=probeDedup(PROBE.rows).filter(x=>(x.latest.value||"").toLowerCase()===host);
  const distLine=cnt=>PROBE_GROUPS.filter(([v])=>cnt[v]).map(([v,l])=>`<span class="muted">${l.split(" ")[0]} ${cnt[v]}</span>`).join("");
  if(type==="leaf"){
    const it=all.find(x=>(x.latest.attrs||{}).path===path);
    if(!it){box.innerHTML="";return;}
    const a=it.latest.attrs||{},url=host+path;
    box.innerHTML=`<div class="pd-hd"><b>${esc(url)}</b> <span class="tcopy" data-pcopy="${esc(url)}" title="复制完整 URL">⧉</span></div>`+
      `<div class="pd-line"><span class="pstat p-${probeGroup(a.status)}">${esc(a.status||"—")}</span>`+
      (a.location?`<span class="muted">→ ${esc(a.location)}</span>`:"")+
      `<span class="muted">len ${esc(a.len||"—")}</span><span class="muted">${esc((a.ctype||"").split(";")[0]||"—")}</span>`+
      (a.server?`<span class="tag t-kind">${esc(a.server)}</span>`:"")+
      `<span class="muted">最新 ${(it.latest.created_at||"").slice(0,16)} · ${esc((it.latest.source||"").slice(0,44))}</span></div>`+
      (it.hist.length?`<div class="pd-h">历史轮次（${it.hist.length}）</div>`+it.hist.map(h=>{const ha=h.attrs||{};
        return `<div class="pd-line"><span class="pstat p-${probeGroup(ha.status)}">${esc(ha.status||"—")}</span>`+
        (ha.location?`<span class="muted">→ ${esc(ha.location)}</span>`:"")+
        `<span class="muted">len ${esc(ha.len||"—")}</span><span class="muted">${(h.created_at||"").slice(0,16)} · ${esc((h.source||"").slice(0,44))}</span></div>`;}).join("")
      :`<div class="muted" style="margin-top:6px">仅一轮观测</div>`);
  }else if(type==="dir"){
    let node=probeBuildTree(all),ok=true;
    path.split("/").filter(Boolean).forEach(s=>{if(ok&&node.children.has(s))node=node.children.get(s);else ok=false;});
    if(!ok){box.innerHTML="";return;}
    const cnt={};(function w(x){x.leaves.forEach(it=>{const g=probeGroup((it.latest.attrs||{}).status);cnt[g]=(cnt[g]||0)+1;});x.children.forEach(w);})(node);
    const total=Object.values(cnt).reduce((a,b)=>a+b,0);
    box.innerHTML=`<div class="pd-hd"><b>${esc(host+path)}</b> <span class="tcopy" data-pcopy="${esc(host+path)}" title="复制目录前缀 URL">⧉</span></div>`+
      `<div class="pd-line"><span class="muted">子路径 ${total} 条</span>${distLine(cnt)}</div>`;
  }else{  // host 节点（domain 聚合视图顶层）
    const cnt={};all.forEach(it=>{const g=probeGroup((it.latest.attrs||{}).status);cnt[g]=(cnt[g]||0)+1;});
    box.innerHTML=`<div class="pd-hd"><b>${esc(host)}</b></div>`+
      `<div class="pd-line"><span class="muted">唯一路径 ${all.length} 条</span>${distLine(cnt)}</div>`;
  }
}
$("#asset-detail").addEventListener("click",async e=>{
  // 页签切换：纯 DOM hidden 切换，不重请求（与发现页 fd-tab 同一交互）
  const tb=e.target.closest("[data-adtab]");
  if(tb){adTab=tb.dataset.adtab;
    ["ov","vuln","ev","raw","probe"].forEach(k=>{const el=$("#ad-"+k);if(el)el.classList.toggle("hidden",adTab!==k)});
    document.querySelectorAll("#ad-tabs .fd-tab").forEach(x=>x.classList.toggle("on",x.dataset.adtab===adTab));
    return;}
  // 探测观测过滤：状态码组 chips（纯前端过滤已拉取行，不重请求）
  const pg=e.target.closest("[data-pg]");
  if(pg){const g=pg.dataset.pg;
    PROBE.groups=PROBE.groups.includes(g)?PROBE.groups.filter(x=>x!==g):[...PROBE.groups,g];
    document.querySelectorAll("#probe-chips .sev-chip").forEach(x=>x.classList.toggle("on",PROBE.groups.includes(x.dataset.pg)));
    renderProbeBody();return;}
  // 探测观测视图切换：目录（去重树）/ 流水（逐条审计）
  const pv=e.target.closest("[data-pv]");
  if(pv){PROBE.view=pv.dataset.pv;
    document.querySelectorAll("[data-pv]").forEach(x=>x.classList.toggle("on",x.dataset.pv===PROBE.view));
    renderProbeBody();return;}
  // 探测观测目录/历史折叠（会话态，不持久化——观测集随扫描变化）
  const px=e.target.closest("[data-pexp]");
  if(px){const k=px.dataset.pexp;PROBE.exp[k]=!PROBE.exp[k];renderProbeBody();return;}
  // 探测观测选中（master-detail）：点树行 → 下方详情区显示该节点元数据
  const ps=e.target.closest("[data-psel]");
  if(ps){PROBE.sel=ps.dataset.psel;renderProbeBody();return;}
  // 探测观测复制完整 URL（与资产树 ⧉ 同交互）
  const pc=e.target.closest("[data-pcopy]");
  if(pc){e.stopPropagation();navigator.clipboard.writeText(pc.dataset.pcopy)
    .then(()=>{const t=pc.textContent;pc.textContent="✓";setTimeout(()=>pc.textContent=t,900)})
    .catch(()=>{});return;}
  // 证据查看：内联展开 pre，与 app.findings.js 证据链 [data-ev] 同一交互模式
  const ev=e.target.closest("[data-ev]");if(!ev)return;
  const pre=$("#evc-"+ev.dataset.ev);if(!pre)return;
  if(!pre.classList.contains("hidden")){pre.classList.add("hidden");return;}
  try{
    const r=await fetch("/api/evidence/view?id="+ev.dataset.ev);
    const d=await r.json();
    if(!r.ok){pre.textContent="读取失败: "+(d.error||r.status);}
    else pre.textContent=d.binary?"（二进制内容，请按上方路径在资源管理器打开）":d.content;
  }catch(err){  // 网络层 reject（断连/服务重启）：内联降级，不产生 unhandled rejection
    pre.textContent="读取失败: "+err.message;
  }
  pre.classList.remove("hidden");
});
// 探测观测路径过滤（input 委托：只重渲染列表，不重请求）
$("#asset-detail").addEventListener("input",e=>{
  if(e.target.id==="probe-q"){PROBE.q=e.target.value;renderProbeBody();}
});
const treeExpKey=()=>"pttree:"+PROJECT;
function saveTreeExp(){try{sessionStorage.setItem(treeExpKey(),JSON.stringify(TREE.expanded))}catch(e){}}
// 展开/折叠全部：遍历平铺索引，对所有有子节点的节点改写展开记录并持久化（过滤态不受影响，渲染时仍全展开）
function expandAllTree(){Object.values(TREE.index).forEach(n=>{if(n.children.length)TREE.expanded[n.id]=true});saveTreeExp();renderAssetTree();}
function collapseAllTree(){Object.values(TREE.index).forEach(n=>{if(n.children.length)TREE.expanded[n.id]=false});saveTreeExp();renderAssetTree();}
function treeFilter(){TREE.q=$("#tree-q").value.trim().toLowerCase();TREE.hideStale=$("#tree-hidestale").checked;renderAssetTree();}
const epLabel=k=>{if(k.startsWith("?"))return k.slice(1);const i=k.indexOf("/");return i>=0?k.slice(i):k};
function mkNode(atype,akey,asset,synth){
  return {id:atype+"/"+akey,atype,akey,asset:asset||null,synth:!!synth,parent:null,children:[],count:0,vuln:0,
    label:atype==="endpoint"?epLabel(akey):akey,
    title:synth?akey+"（合成根，非库内资产）":akey};
}
async function loadAssetTree(){
  try{
    // 并行拉资产 + 发现（finding/osint）：后者用于构建子树漏洞红色角标
    const [d,f]=await Promise.all([api("assets",{project:PROJECT}),api("findings",{project:PROJECT})]);
    try{TREE.expanded=JSON.parse(sessionStorage.getItem(treeExpKey())||"{}")}catch(e){TREE.expanded={}}
    // 漏洞角标统计：finding.parent_ext 为逗号分隔的观测事件 id 串（数字段才有效），
    // 按「观测事件 id → 漏洞条数」累计；资产由观测归并而成（assets.event_ids），
    // buildAssetTree 内再经 event_ids 映射到资产并向上汇总到子树
    const vulnMap={};
    (f.findings||[]).forEach(x=>{
      String(x.parent_ext||"").split(",").forEach(t=>{
        const s=t.trim();
        if(/^\d+$/.test(s))vulnMap[+s]=(vulnMap[+s]||0)+1;
      });
    });
    buildAssetTree(d.assets||[],vulnMap);
    syncTreeSel();
    renderAssetTree();
  }catch(e){$("#asset-tree").innerHTML="<span class='muted'>资产树加载失败："+esc(e.message)+"</span>";}
}
function buildAssetTree(assets,vulnMap){
  const doms=assets.filter(a=>a.atype==="domain"),hosts=assets.filter(a=>a.atype==="host"),
    svcs=assets.filter(a=>a.atype==="service"),eps=assets.filter(a=>a.atype==="endpoint");
  const domSet=new Set(doms.map(a=>a.akey)),dnodes={},roots=[],regRoots={};
  doms.forEach(a=>dnodes[a.akey]=mkNode("domain",a.akey,a));
  // domain：库内只记一跳，这里按 FQDN 后缀链重建多级子域（挂最长的现存祖先域）
  doms.forEach(a=>{
    const p=a.akey.split(".");
    for(let i=1;i<p.length-1;i++){
      const c=p.slice(i).join(".");
      if(domSet.has(c)){dnodes[c].children.push(dnodes[a.akey]);dnodes[a.akey].parent=dnodes[c].id;return;}
    }
  });
  // 无现存祖先的域名：归到注册域根（不存在则合成根节点）
  doms.forEach(a=>{
    if(dnodes[a.akey].parent)return;
    const p=a.akey.split(".");
    const reg=p.length>2?p.slice(-(p[p.length-2].length<=3?3:2)).join("."):a.akey;
    if(reg===a.akey){roots.push(dnodes[a.akey]);return;}
    if(!regRoots[reg]){
      if(dnodes[reg]){regRoots[reg]=dnodes[reg];if(!dnodes[reg].parent)roots.push(dnodes[reg]);}
      else{regRoots[reg]=mkNode("domain",reg,null,true);roots.push(regRoots[reg]);}
    }
    regRoots[reg].children.push(dnodes[a.akey]);
    dnodes[a.akey].parent=regRoots[reg].id;
  });
  // 通配挂载：endpoint/service 按 parent_akey 依次试 service→host→domain；都缺但 parent 像主机名则合成挂靠节点（仅展示态，不落库）
  const hnodes={},snodes={};
  hosts.forEach(a=>{const n=mkNode("host",a.akey,a);hnodes[a.akey]=n;roots.push(n);});
  svcs.forEach(a=>{const n=mkNode("service",a.akey,a);snodes[a.akey]=n;
    const p=hnodes[a.parent_akey]||dnodes[a.parent_akey];
    if(p){p.children.push(n);n.parent=p.id;}else roots.push(n);});
  const orph=mkNode("group","未归属",null,true);orph.id="__orphan";orph.title="归属信息缺失的孤儿 endpoint";
  const HOSTNAME_RE=/^[A-Za-z0-9._-]+$/;
  // endpoint 按路径段建树（Burp Site Map 式）：带目录前缀的逐段合成 group 节点（仅展示态，不落库），无路径的根级端点直接挂叶子
  const dmap={};
  const dirOf=(p,segs)=>{let cur=p;
    for(const seg of segs){
      const ak=cur.akey+"/"+seg,id="dir/"+ak;
      if(!dmap[id]){const n=mkNode("group",ak,null,true);n.label=seg;n.title="路径分组（仅展示态，不落库）";dmap[id]=n;cur.children.push(n);n.parent=cur.id;}
      cur=dmap[id];
    }return cur;};
  eps.forEach(a=>{const n=mkNode("endpoint",a.akey,a);
    let p=snodes[a.parent_akey]||hnodes[a.parent_akey]||dnodes[a.parent_akey];
    if(!p&&a.parent_akey&&HOSTNAME_RE.test(a.parent_akey)){p=mkNode("host",a.parent_akey,null,true);roots.push(p);}
    if(p){const i=a.akey.indexOf("/");
      const segs=i>=0?a.akey.slice(i+1).split("/").filter(Boolean):[];
      // 仅 2 段及以上才建路径分组；单段根级路径（/login 等）保持叶子直挂，避免同名目录自我嵌套
      const t=segs.length>1?dirOf(p,segs.slice(0,-1)):p;
      t.children.push(n);n.parent=t.id;
      if(segs.length>1)n.label=segs[segs.length-1];
    }else{orph.children.push(n);n.parent="__orphan";}});
  if(orph.children.length)roots.push(orph);
  // 子树资产计数徽标 + 漏洞红色角标 + 平铺索引（供锚定/展开定位）
  const idx={};
  const cnt=n=>{let s=n.synth?0:1,v=0;
    // 自身漏洞：经 event_ids（构成该资产的观测事件）查 vulnMap 累计；合成节点无资产则为 0
    if(!n.synth&&n.asset)(n.asset.event_ids||[]).forEach(e=>{v+=vulnMap[e]||0});
    n.children.forEach(c=>{s+=cnt(c);v+=c.vuln});
    n.count=s;n.vuln=v;idx[n.id]=n;return s;};
  roots.forEach(cnt);
  // 两级排序：目录节点（有子节点）排前、叶子排后，同级内再按 label 字典序
  const dirKey=n=>n.children.length?0:1;
  const byLabel=(a,b)=>dirKey(a)-dirKey(b)||a.label.localeCompare(b.label);
  const sortAll=n=>{n.children.sort(byLabel);n.children.forEach(sortAll);};
  // 根级：目录优先之外，同键时 host 再优先于 domain/group（host 是探测主体，最常下钻）
  const byRoot=(a,b)=>dirKey(a)-dirKey(b)
    ||(a.atype==="host"?0:1)-(b.atype==="host"?0:1)
    ||a.label.localeCompare(b.label);
  roots.sort(byRoot);roots.forEach(sortAll);
  TREE.nodes=roots;TREE.index=idx;
}
function renderAssetTree(){
  const box=$("#asset-tree");if(!box)return;
  const q=TREE.q;
  const hasFresh=n=>{if(!n.synth&&n.asset)return !n.asset.stale;return n.children.some(hasFresh);};
  const visible=n=>(!q||n.akey.toLowerCase().includes(q)||n.children.some(visible))
                &&(!TREE.hideStale||hasFresh(n));
  let html="";
  (function walk(nodes,depth){
    nodes.forEach(n=>{
      if(!visible(n))return;
      const open=q||TREE.hideStale?true:(TREE.expanded[n.id]!==undefined?TREE.expanded[n.id]:depth<=1); // 默认展开到第 2 层（根+二级目录）；过滤态全展开
      const staleCls=hasFresh(n)?"":" tstale"; // 子树全部 30 天未见 → 灰显
      html+=`<div class="tnode${staleCls} ${TREE.sel===n.id?"on":""}" data-tid="${esc(n.id)}" style="padding-left:${depth*14+4}px" title="${esc(n.title)}">`+
        (n.children.length?`<span class="tcaret" data-caret="${esc(n.id)}">${open?"▾":"▸"}</span>`:`<span class="tcaret tleaf">·</span>`)+
        `<span class="tdot d-${n.atype}"></span><span class="tlabel">${esc(n.label)}</span>`+
        (n.count>1?`<span class="tcount">${n.count}</span>`:"")+
        (n.vuln>0?`<span class="tvuln" title="子树关联漏洞 ${n.vuln} 条">${n.vuln}</span>`:"")+
        (n.akey&&!n.akey.startsWith("?")?`<span class="tcopy" data-copy="${esc(n.akey)}" title="复制完整地址">⧉</span>`:"")+
        `</div>`;
      if(open&&n.children.length)walk(n.children,depth+1);
    });
  })(TREE.nodes,0);
  box.innerHTML=html||`<span class='muted'>${(q||TREE.hideStale)?"无匹配节点":"暂无资产（rebuild-assets 后出现）"}</span>`;
}
function subtreeSet(n){const s=new Set();(function w(x){if(!x.synth)s.add(x.id);x.children.forEach(w)})(n);return s;}
function selectTreeNode(id){
  const n=TREE.index[id];if(!n)return;
  TREE.sel=id;TREE.selSet=subtreeSet(n);
  let cur=n.parent;while(cur&&TREE.index[cur]){TREE.expanded[cur]=true;cur=TREE.index[cur].parent;}
  saveTreeExp();
  renderAssetTree();
  $("#tree-sel-txt").innerHTML=`树选中：<b>${esc(n.label)}</b>（子树 ${TREE.selSet.size} 条）`;
  $("#tree-sel-bar").classList.remove("hidden");
  loadAssets();
}
function clearTreeSel(){
  TREE.sel=null;TREE.selSet=null;
  renderAssetTree();
  $("#tree-sel-bar").classList.add("hidden");
  loadAssets();
}
function syncTreeSel(){ // 树缓存重建后：选中节点消失则清锚定并重刷表格，避免残留过期子树过滤
  if(!TREE.sel)return;
  const n=TREE.index[TREE.sel];
  if(!n){TREE.sel=null;TREE.selSet=null;$("#tree-sel-bar").classList.add("hidden");loadAssets();return;}
  TREE.selSet=subtreeSet(n);
  $("#tree-sel-txt").innerHTML=`树选中：<b>${esc(n.label)}</b>（子树 ${TREE.selSet.size} 条）`;
}
$("#asset-tree").addEventListener("click",e=>{
  const cp=e.target.closest("[data-copy]");
  if(cp){e.stopPropagation();navigator.clipboard.writeText(cp.dataset.copy)
    .then(()=>{const t=cp.textContent;cp.textContent="✓";setTimeout(()=>cp.textContent=t,900)})
    .catch(()=>{});return;}
  const c=e.target.closest("[data-caret]");
  if(c){const id=c.dataset.caret;TREE.expanded[id]=c.textContent.trim()==="▾"?false:true;saveTreeExp();renderAssetTree();return;}
  const tn=e.target.closest(".tnode");if(!tn)return;
  if(TREE.sel===tn.dataset.tid)clearTreeSel();else selectTreeNode(tn.dataset.tid);
});
