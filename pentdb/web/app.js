const $=s=>document.querySelector(s);
const Kinds=["domain","port","path","param","finding","osint","note","test"];
let PROJECT="";
const qs=o=>new URLSearchParams(o).toString();
async function api(path,params){const r=await fetch("/api/"+path+(params?"?"+qs(params):""));if(!r.ok)throw new Error(await r.text());return r.json()}

async function boot(){
  const d=await api("projects");
  const sel=$("#proj"); sel.innerHTML=d.projects.map(p=>`<option>${p.name}</option>`).join("");
  const urlProj=new URLSearchParams(location.search).get("project")||"";
  PROJECT=urlProj||sel.value;
  if(PROJECT)sel.value=PROJECT;
  sel.onchange=()=>{PROJECT=sel.value;location.search="?project="+encodeURIComponent(PROJECT)};
  $("#m-kind").innerHTML=Kinds.filter(k=>k!=="test").map(k=>`<option>${k}</option>`).join("");
  $("#m-kind").onchange=()=>$("#m-sev").classList.toggle("hidden",$("#m-kind").value!=="finding");
  loadAll();
}
function loadAll(){loadOverview();loadFindings();loadAssetTree();loadAssets();loadTimeline();loadReview();loadReport()}

async function loadLint(btn){
  const t0=new Date().toLocaleTimeString();
  if(btn){btn.disabled=true;btn.textContent="检查中…";}
  try{
    const d=await api("lint",{project:PROJECT});
    const E=d.errors||[],W=d.warns||[];
    $("#lint-sum").innerHTML=E.length?`<span class="tag sev-crit">error × ${E.length}</span>`+
      (W.length?` <span class="tag sev-med">warn × ${W.length}</span>`:""):
      (W.length?`<span class="tag sev-med">warn × ${W.length}</span>`:`<span class="tag t-confirmed">0 error ✓ 通过</span>`);
    $("#lint-out").innerHTML=
      E.map(e=>`<div style="color:var(--red)">✖ ${esc(e)}</div>`).join("")+
      W.map(w=>`<div style="color:var(--amber)">⚠ ${esc(w)}</div>`).join("")||
      "<span style='color:var(--teal)'>全部记录通过门禁检查（source 溯源 / 状态 / scope / test 归因）</span>";
    $("#lint-at").textContent="检查于 "+t0;
  }catch(e){
    $("#lint-sum").innerHTML="";
    $("#lint-out").innerHTML=`<span style="color:var(--red)">检查失败：${esc(e.message)}</span>`;
  }finally{
    if(btn){btn.disabled=false;btn.textContent="重新检查";}
  }
}

async function manualAdd(){
  const kind=$("#m-kind").value;
  const body={project:PROJECT,kind:kind,value:$("#m-value").value,note:$("#m-note").value,
    source:$("#m-source").value,scope:$("#m-scope").value,update:$("#m-update").checked};
  if(kind==="finding")body.severity=$("#m-sev").value;
  const msg=$("#m-msg");
  try{
    const r=await fetch("/api/manual-add",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||r.status);
    msg.style.color="var(--teal)";
    msg.textContent=`已入库 ✓ #${d.id||""} ${body.kind} ${body.value}（origin=human，自动 confirmed）`;
    $("#m-value").value="";$("#m-note").value="";
    loadOverview();loadAssets();loadFindings();loadLint();
  }catch(e){
    msg.style.color="var(--red)";
    msg.textContent="入库失败："+e.message;
  }
}

function tag(s){return `<span class="tag t-${s}">${s}</span>`}
function kindTag(k){return `<span class="tag t-kind">${k}</span>`}
function scopeTag(s){s=s||"unknown";return `<span class="tag scp-${s}">${s==="in"?"in-scope":(s==="out"?"OUT":"scope?")}</span>`}

async function loadOverview(){
  const d=await api("overview",{project:PROJECT});
  const sug=await api("suggestions",{project:PROJECT});
  $("#sug-list").innerHTML=(sug.suggestions||[]).map(r=>
    `<div class="fitem"><b>${esc(r.title||"建议")}</b> ${tag(r.status)} `+
    `<span class="muted">#${r.id} · ${r.created_at} · ${r.origin}</span>`+
    (r.value?`<div class="detail">${esc(r.value)}</div>`:"")+
    (r.note?`<div class="muted">依据：${esc(r.note)}</div>`:"")+
    `<div class="src">来源：${esc(r.source)}</div>`+
    (r.status==="new"?`<div><button class="btn-ok" onclick="doReview(${r.id},'confirmed')">采纳</button> <button class="btn-no" onclick="doReview(${r.id},'rejected')">忽略</button></div>`:"")+
    `</div>`).join("")||"<div class='muted'>暂无建议（AI 在采集/测试批次结束后生成）</div>";
  const st=d.by_status||{}, bk=d.by_kind||{};
  const card=(n,label,attrs)=>n>0
    ?`<div class="card click" ${attrs} title="点击查看明细"><b>${n}</b><span>${label}</span></div>`
    :`<div class="card"><b>${n}</b><span>${label}</span></div>`;
  $("#stat-cards").innerHTML=
    card((st.new||0)+(st.confirmed||0)+(st.rejected||0),"事件总数",'data-tab="assets"')+
    card(st.confirmed||0,"已确认",'data-tab="assets" data-status="confirmed"')+
    card(st.new||0,"待审核",'data-tab="review"')+
    card(bk.domain||0,"域名/子域",'data-tab="assets" data-kind="domain"')+
    card((bk.finding||0)+(bk.osint||0),"发现/情报",'data-tab="findings"')+
    Kinds.filter(k=>bk[k]&&k!=="domain"&&k!=="finding").map(k=>
      card(bk[k],k,`data-tab="assets" data-kind="${k}"`)).join("");
  $("#stat-cards").onclick=e=>{
    const c=e.target.closest(".card[data-tab]");
    if(!c)return;
    if(c.dataset.tab==="assets")gotoAssets(c.dataset.kind||"",c.dataset.status||"",c.dataset.q||"");
    else switchTab(c.dataset.tab);
  };
  const groups={};
  (d.domains||[]).forEach(r=>{
    const parts=r.value.split(".");
    const base=parts.length>2?parts.slice(-(parts[parts.length-2].length<=3?3:2)).join("."):r.value;
    (groups[base]=groups[base]||[]).push(r);
  });
  $("#domain-groups").innerHTML=Object.keys(groups).sort().map(base=>
    `<div class="grp"><h4 style="cursor:pointer" title="点击在资产明细中搜索该主域" onclick="gotoAssets('','','${base}')">${base}（${groups[base].length}）</h4><ul>`+
    groups[base].map(r=>`<li style="cursor:pointer" title="点击在资产明细中搜索" onclick="gotoAssets('','','${r.value}')">${r.value} ${tag(r.status)} ${scopeTag(r.scope)} `+
      `${r.tech?`<span class="tag t-kind">${esc(r.tech)}</span>`:""} `+
      `${r.note?`<span class="muted">— ${esc(r.note)}</span>`:""}</li>`).join("")+
    `</ul></div>`).join("");
}
const SEVS=[["crit","严重"],["high","高危"],["med","中危"],["low","低危"],["info","信息"],["","未分级"]];
const LIFES=[["open","待复测"],["reproduced","已复现"],["not-reproduced","未复现"],["fixed","已修复"],["reopened","重开"]];
let sevFilter=null, findStatus="", selFinding=null, findTab="packet";
const sevLabel=k=>(SEVS.find(s=>s[0]===(k||""))||["","未分级"])[1];
const lifeOf=r=>{try{return (JSON.parse(r.attrs||"{}").lifecycle)||""}catch(e){return ""}};
const lifeTag=l=>{const f=LIFES.find(x=>x[0]===l);return f?`<span class="tag life-${l}">${f[1]}</span>`:""};
function lastRetest(fid){
  const fids=new Set([String(fid)]);
  const rel=TESTS.filter(t=>(t.parent_ext||"").split(",").map(s=>s.trim()).some(s=>fids.has(s)))
    .sort((a,b)=>(b.created_at||"").localeCompare(a.created_at||""));
  return rel[0]||null;
}
const frow=r=>{
  const t=lastRetest(r.id);
  const tgt=r.value&&r.value!==r.title?r.value:"";
  const pend=r.status==="new";
  return `<div class="frow2 ${selFinding===r.id?"on":""}" data-fid="${r.id}">`+
    `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">`+
    `<span class="sev-dot sev-${r.severity||"none"}"></span><b>${esc(r.title||r.value)}</b> ${lifeTag(lifeOf(r))}`+
    (pend?`<span class="tag t-new">待审</span>`:"")+
    `<span style="flex:1"></span><span class="muted">#${r.id}</span></div>`+
    `<div class="muted" style="font-size:12px;margin-top:2px">`+
    (tgt?esc(tgt)+" · ":"")+
    (t?`最近复测：${esc((t.note||t.value||"").slice(0,40))} · `:"")+
    `${(r.created_at||"").slice(0,10)}</div>`+
    (pend?`<div style="margin-top:4px" onclick="event.stopPropagation()"><button class="btn-ok" onclick="doReview(${r.id},'confirmed')">确认</button> <button class="btn-no" onclick="doReview(${r.id},'rejected')">驳回</button></div>`:"")+
    `</div>`;
};
let ASSET_MAP = {};
function targetHtml(r){
  const link=(val,label)=>`<span class="muted" style="cursor:pointer;text-decoration:underline dotted" data-q="${esc(val)}" title="点击在资产明细中查看该条">${esc(label||val)}</span>`;
  const parts=(r.parent_ext||"").split(",").map(s=>s.trim()).filter(Boolean);
  const linked=parts.map(t=>{
    const a=ASSET_MAP[t]||ASSET_MAP[String(Number(t))];
    if(a)return link(a.value, `${a.kind}:${a.value}${a.status==="new"?"（待审）":""}`);
    if(/^\d+$/.test(t))return `<span class="muted">id ${t}（未找到资产记录）</span>`;
    return link(t, t);
  });
  if(linked.length)return linked.join("<br>");
  if(r.value&&r.value!==r.title)return link(r.value);
  return "";
}
let TESTS=[];
function relatedTests(f){
  const fids=new Set([String(f.id),...(f.parent_ext||"").split(",").map(s=>s.trim()).filter(Boolean)]);
  return TESTS.filter(t=>(t.parent_ext||"").split(",").map(s=>s.trim()).some(s=>fids.has(s)));
}
function secSplit(detail){
  const marks=["【描述】","【请求】","【payload】","【判据】","【原因】","【手工验证】","【修复】"];
  const parts=[];let cur={name:"前言",lines:[]};
  (detail||"").split(/\r?\n/).forEach(line=>{
    const s=line.trim();
    const m=marks.find(k=>s.startsWith(k));
    if(m){if(cur.lines.join("").trim())parts.push(cur);cur={name:m.slice(1,-1),lines:[s.slice(m.length)]};}
    else cur.lines.push(line);
  });
  if(cur.lines.join("").trim())parts.push(cur);
  return parts;
}
const FD_TABS=[["packet","复测包"],["timeline","时间轴"],["evid","证据链"],["retest","登记复测"]];
function httpToCurl(raw){
  const q=s=>"'"+String(s).replace(/'/g,"'\\''")+"'";
  const parts=raw.split(/\r?\n\r?\n/);
  const lines=(parts[0]||"").split(/\r?\n/);
  const rl=(lines.shift()||"").trim().split(/\s+/);
  const method=rl[0]||"GET", target=rl[1]||"/";
  let host="";
  lines.forEach(l=>{const h=l.match(/^Host:\s*(.+?)\s*$/i);if(h)host=h[1];});
  const url=/^https?:\/\//i.test(target)?target:"https://"+(host||"<host>")+target;
  let cmd=`curl -sk -X ${method} ${q(url)}`;
  lines.forEach(l=>{const i=l.indexOf(":");if(i>0)cmd+=` -H ${q(l.slice(0,i+1).trim()+" "+l.slice(i+1).trim())}`;});
  const body=parts.slice(1).join("\n\n").trim();
  if(body)cmd+=` --data-raw ${q(body)}`;
  return cmd;
}
function findingDetail(r){
  const isFinding=r.kind==="finding";
  const rel=isFinding?relatedTests(r).sort((a,b)=>(b.created_at||"").localeCompare(a.created_at||"")):[];
  const secs=secSplit(r.detail);
  const cases=secs.filter(p=>p.name==="请求"||p.name==="payload").map(p=>{
    const body=p.lines.join("\n").trim();
    return `<h4>【${esc(p.name)}】 <button class="mini" data-copy="${esc(body)}">复制</button>`+
      (p.name==="请求"?` <button class="mini" data-copycurl="${esc(body)}">复制为 curl</button>`:"")+`</h4>`+
      `<pre style="max-height:300px;overflow:auto">${esc(body)}</pre>`;
  }).join("");
  const prof=secs.filter(p=>p.name!=="请求"&&p.name!=="payload").map(p=>
    `<h4>【${esc(p.name)}】</h4><div style="white-space:pre-wrap">${esc(p.lines.join("\n").trim())}</div>`).join("");
  const packet=`<h4>目标</h4><div>${targetHtml(r)}</div>`+
    `<h4 style="margin-top:12px">事实报文 <span class="muted">（evidence 落库的 request/response）</span></h4>`+
    `<div id="fd-packets" class="muted">加载中…</div>`+
    (cases?`<h4 style="margin-top:12px">复测用例 <span class="muted">（detail 文本，非事实报文）</span></h4>`+cases:"")+
    (prof||(!secs.length?`<h4>描述 / 复测结论</h4><div style="white-space:pre-wrap">${esc(r.detail||"")}</div>`:""))+
    (r.note?`<h4>结论备注</h4><div style="white-space:pre-wrap">${esc(r.note)}</div>`:"")+
    `<h4>来源</h4><div class="src">${esc(r.source)}</div>`+
    `<div class="muted" style="margin-top:8px">${(r.created_at||"")} · scope=${esc(r.scope||"unknown")}</div>`;
  const life=lifeOf(r);
  const lifeSel=isFinding?`<select id="life-quick" class="mini" onchange="setLife(${r.id},this.value)" title="快捷改生命周期（写 changelog 留痕）">`+
    (life?"":`<option value="">生命周期?</option>`)+
    LIFES.map(([k,label])=>`<option value="${k}" ${life===k?"selected":""}>${label}</option>`).join("")+`</select>`:"";
  let html=`<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">`+
    `<span class="tag sev-${r.severity||"none"}">${sevLabel(r.severity)}</span>`+
    `<b style="font-size:15px">${esc(r.title||r.value)}</b> ${lifeSel} ${tag(r.status)} ${kindTag(r.kind)}`+
    `${r.ext_id?` <span class="muted">${esc(r.ext_id)}</span>`:""}<span style="flex:1"></span>`+
    `<span class="muted">#${r.id} · ${r.origin}${r.confidence?"/"+r.confidence:""}</span></div>`;
  if(isFinding){
    html+=`<div class="fd-tabs">${FD_TABS.map(([k,label])=>
      `<span class="fd-tab ${findTab===k?"on":""}" data-tab="${k}">${label}${k==="timeline"?`（${rel.length}）`:""}</span>`).join("")}</div>`;
    const timeline=rel.length?rel.map(t=>
      `<div class="rec"><div class="hd"><b>${esc(t.value)}</b> ${tag(t.status)}`+
      `<span style="flex:1"></span><span class="muted">${(t.created_at||"").slice(0,16)}</span></div>`+
      (t.note?`<div class="muted" style="margin-top:2px">结论: ${esc(t.note)}</div>`:"")+
      `<div class="src">归因: ${t.parent_ext?esc(t.parent_ext):"—"} ｜ 来源: ${esc(t.source)}</div></div>`).join("")
      :"<span class='muted'>暂无复测记录（「登记复测」页签登记第一轮；value=动作 · note=结论）</span>";
    html+=`<div id="fd-packet" class="${findTab!=="packet"?"hidden":""}">${packet}</div>`+
      `<div id="fd-timeline" class="${findTab!=="timeline"?"hidden":""}">${timeline}</div>`+
      `<div id="fd-evid" class="${findTab!=="evid"?"hidden":""}"><div id="ev-panel" class="muted">加载中…</div></div>`+
      `<div id="fd-retest" class="${findTab!=="retest"?"hidden":""}">
        <h4>登记本轮手工复测</h4>
        <div class="filters" style="margin-bottom:4px">
          <input id="rt-action" placeholder="动作（验证了什么/打了什么包）" style="flex:2;min-width:200px">
          <input id="rt-note" placeholder="结论（未复现·已修复 / 复现 / 部分修复…+依据）" style="flex:2;min-width:200px">
          <select id="rt-life" title="随本轮复测更新生命周期">`+
            LIFES.map(([k,label])=>`<option value="${k}" ${life===k?"selected":""}>${label}</option>`).join("")+
            `<option value="">不改生命周期</option></select>
          <input id="rt-source" value="面板手工复测" style="flex:1;min-width:120px">
          <button class="btn-ok" onclick="doRetest(${r.id})">登记复测</button>
        </div><div class="muted" id="rt-msg"></div></div>`;
  }else{
    html+=packet;
  }
  $("#finding-detail").innerHTML=html;
  if(isFinding){loadEvidencePanel(r,rel);}
}
async function setLife(fid,code){
  if(!code)return;
  const r=await fetch("/api/retest",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({finding_id:fid,lifecycle:code})});
  if(!r.ok){alert("生命周期更新失败："+await r.text());return;}
  loadFindings();
}
const evIsPkt=e=>e.etype==="request"||e.etype==="response"||(e.note&&(e.note.startsWith("request")||e.note.startsWith("response")));
async function fillPkt(id,ev){
  const pre=document.getElementById(id); if(!pre)return;
  try{
    const r=await fetch("/api/evidence/view?id="+ev.id); const v=await r.json();
    pre.textContent=r.ok?(v.binary?"（二进制内容，请下载查看）":v.content):("读取失败: "+(v.error||r.status));
  }catch(err){pre.textContent="读取失败: "+err.message;}
}
async function loadEvidencePanel(f,rel){
  const pkBox=$("#fd-packets"), box=$("#ev-panel");
  if(!pkBox&&!box)return;
  const ids=[f.id,...rel.map(t=>t.id)];
  const d=await api("evidence",{project:PROJECT,event_ids:ids.join(",")});
  const evs=(d.evidence||[]).slice().sort((a,b)=>a.id-b.id);
  const pkts=evs.filter(evIsPkt), files=evs.filter(e=>!evIsPkt(e));
  // —— 报文配对：request 开新组，response 归入最近一个缺响应的组（多次 add --update 得多组）——
  const groups=[];
  pkts.forEach(e=>{
    const isReq=e.etype==="request"||(e.note||"").startsWith("request");
    if(isReq){groups.push({req:e,resp:null});return;}
    const last=groups[groups.length-1];
    if(last&&!last.resp)last.resp=e;else groups.push({req:null,resp:e});
  });
  if(pkBox){
    pkBox.className="";
    pkBox.innerHTML=groups.length?groups.map((g,i)=>{
      const hdr=g.req||g.resp;
      const reqCls=!g.req?"hidden":"", respCls=(g.req||!g.resp)?"hidden":"";
      return `<div class="pkt-card">`+
        `<div class="hd"><b>第 ${i+1} 组</b><span class="muted">挂 #${hdr.event_id} · ${hdr.created_at} · sha256 ${(hdr.sha256||"").slice(0,16)}…</span>`+
        `</div>`+
        (g.req&&g.resp?`<div class="pkt-tabs"><span class="pkt-tab on" data-pkt="req">请求</span><span class="pkt-tab" data-pkt="resp">响应</span></div>`:"")+
        `<pre data-side="req" id="pkt-req-${i}" class="${reqCls}">${g.req?"加载中…":"（该组无请求报文）"}</pre>`+
        `<pre data-side="resp" id="pkt-resp-${i}" class="${respCls}">${g.resp?"加载中…":"（无响应报文）"}</pre></div>`;
    }).join("")
    :`<span class='muted'>暂无事实报文（add --req/--resp 或 evidence --text --note request 落库后在此成对展示）</span>`;
    if(!groups.length)pkBox.className="muted";
    const loads=[];
    groups.forEach((g,i)=>{
      if(g.req)loads.push(fillPkt("pkt-req-"+i,g.req));
      if(g.resp)loads.push(fillPkt("pkt-resp-"+i,g.resp));
    });
    await Promise.all(loads);
  }
  if(box){
    box.className="";
    box.innerHTML=files.length?files.map(e=>{
      const name=e.note||e.path.split(/[\\/]/).pop();
      return `<div class="rec"><div class="hd"><b>${esc(name)}</b>`+
        ` <span class="tag t-kind">挂 #${e.event_id}</span>`+
        (e.exists?` <button class="mini" data-ev="${e.id}">查看</button>`
                 :` <span class="tag sev-crit">文件缺失</span>`)+
        `<div class="src" title="${esc(e.path)}">${esc(e.path)} ｜ sha256 ${(e.sha256||"").slice(0,16)}… ｜ ${e.created_at}</div></div>`+
        `<pre class="hidden" id="evc-${e.id}"></pre></div>`;
    }).join("")
    :`<span class='muted'>报文类证据已移至「复测包」页签；此处放附件物料（截图/凭据表/报告等）</span>`;
    if(!files.length)box.className="muted";
  }
}
async function loadProjectEvidence(){
  const box=$("#proj-ev"); if(!box)return;
  const d=await api("evidence",{project:PROJECT,event_id:0});
  const evs=d.evidence||[];
  box.className=evs.length?"":"muted";
  box.innerHTML=evs.length?evs.map(e=>
    `<div class="rec"><div class="hd"><b>${esc(e.note||e.path.split(/[\\/]/).pop())}</b>`+
    (e.exists?` <button class="mini" data-ev="${e.id}">查看</button>`
             :` <span class="tag sev-crit">文件缺失</span>`)+
    `<div class="src">${esc(e.path)} ｜ ${e.created_at}</div></div>`+
    `<pre class="hidden" id="evc-${e.id}"></pre></div>`).join("")
  :"暂无项目级物料（凭据表/报告/访问说明用 evidence --event-id 0 挂到项目，不属于单个漏洞）";
}
$("#finding-detail").addEventListener("click",async e=>{
  const tb=e.target.closest("[data-tab]");
  if(tb){findTab=tb.dataset.tab;
    ["packet","timeline","evid","retest"].forEach(k=>{const el=$("#fd-"+k);if(el)el.classList.toggle("hidden",findTab!==k)});
    document.querySelectorAll("#finding-detail .fd-tab").forEach(x=>x.classList.toggle("on",x.dataset.tab===findTab));
    return;}
  const cp=e.target.closest("[data-copy]");
  if(cp){navigator.clipboard.writeText(cp.dataset.copy);cp.textContent="已复制 ✓";setTimeout(()=>cp.textContent="复制",1500);return;}
  const pt=e.target.closest("[data-pkt]");
  if(pt){const card=pt.closest(".pkt-card");
    card.querySelectorAll(".pkt-tab").forEach(x=>x.classList.toggle("on",x===pt));
    card.querySelectorAll("pre[data-side]").forEach(p=>p.classList.toggle("hidden",p.dataset.side!==pt.dataset.pkt));
    return;}
  const cc=e.target.closest("[data-copycurl]");
  if(cc){navigator.clipboard.writeText(httpToCurl(cc.dataset.copycurl));cc.textContent="已复制 ✓";setTimeout(()=>cc.textContent="复制为 curl",1500);return;}
  const ev=e.target.closest("[data-ev]");
  if(ev){
    const pre=$("#evc-"+ev.dataset.ev);
    if(!pre.classList.contains("hidden")){pre.classList.add("hidden");return;}
    const r=await fetch("/api/evidence/view?id="+ev.dataset.ev);
    const d=await r.json();
    if(!r.ok){pre.textContent="读取失败: "+(d.error||r.status);pre.classList.remove("hidden");return;}
    pre.textContent=d.binary?"（二进制内容，请按上方路径在资源管理器打开）":d.content;
    pre.classList.remove("hidden");return;
  }
});
async function doRetest(fid){
  const body={finding_id:fid,action:$("#rt-action").value.trim(),conclusion:$("#rt-note").value.trim(),
    source:$("#rt-source").value.trim()||"面板手工复测",
    lifecycle:$("#rt-life")?$("#rt-life").value:""};
  const msg=$("#rt-msg");
  if(!body.action){msg.style.color="var(--red)";msg.textContent="动作必填（只改生命周期用详情头部的快捷下拉）";return;}
  try{
    const r=await fetch("/api/retest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||r.status);
    msg.style.color="var(--teal)";
    msg.textContent=`已登记复测 #${d.id}${body.lifecycle?"（生命周期→"+body.lifecycle+"）":""} ✓`;
    findTab="timeline";
    loadAll();
  }catch(e2){
    msg.style.color="var(--red)";
    msg.textContent="登记失败："+e2.message;
  }
}
async function loadFindings(){
  const [d, ad, td]=await Promise.all([api("findings",{project:PROJECT}), api("events",{project:PROJECT,kinds:"domain,port,path,param"}), api("events",{project:PROJECT,kinds:"test"})]);
  ASSET_MAP={}; (ad.events||[]).forEach(a=>{ASSET_MAP[String(a.id)]=a});
  TESTS=td.events||[];
  const all=d.findings||[];
  const q=((($("#f-find-q")||{}).value)||"").trim().toLowerCase();
  const matchQ=r=>!q||[r.title,r.value,r.detail,r.note].some(x=>(x||"").toLowerCase().includes(q));
  const st=r=>!findStatus||r.status===findStatus;
  const fs=all.filter(r=>r.kind==="finding"&&st(r)&&matchQ(r)&&(sevFilter===null||(r.severity||"")===sevFilter));
  const os=all.filter(r=>r.kind==="osint"&&st(r)&&matchQ(r));
  const bySev={}; fs.forEach(r=>{(bySev[r.severity||""]=bySev[r.severity||""]||[]).push(r)});
  $("#sev-chips").innerHTML=SEVS.map(([k,label])=>{
    const n=(bySev[k]||[]).length;
    return `<span class="sev-chip sev-${k||"none"} ${sevFilter===k?"on":""}" data-sev="${k}">${label} ${n}</span>`;
  }).join("");
  $("#find-count").textContent=`${fs.length} 条`+(q?"（搜索命中）":"");
  const order=SEVS.map(s=>s[0]);
  $("#findings-list").innerHTML=fs.slice()
    .sort((a,b)=>order.indexOf(a.severity||"")-order.indexOf(b.severity||""))
    .map(frow).join("")||
    `<div class='muted'>无命中${q||findStatus||sevFilter!==null?"（当前筛选组合下）":""}${sevFilter!==null?"——级别 chips 再点一次取消":""}</div>`;
  $("#osint-list").innerHTML=os.length?os.map(frow).join(""):`<span class='muted'>无情报记录</span>`;
  const sel=all.find(r=>r.id===selFinding);
  if(sel)findingDetail(sel);
  else $("#finding-detail").innerHTML="<span class='muted'>← 点左侧条目，详情固定在右侧；筛选可组合：搜索 × 级别 × 人审态</span>";
  loadProjectEvidence();
}
$("#sev-chips").onclick=e=>{
  const c=e.target.closest(".sev-chip"); if(!c)return;
  sevFilter=(sevFilter===c.dataset.sev)?null:c.dataset.sev;
  loadFindings();
};
$("#findings-list").onclick=e=>findingListClick(e);
$("#osint-list").onclick=e=>findingListClick(e);
$("#finding-detail").onclick=e=>{
  const q=e.target.closest("[data-q]");
  if(q)gotoAssets("","",q.dataset.q);
};
function findingListClick(e){
  const q=e.target.closest("[data-q]");
  if(q){gotoAssets("","",q.dataset.q);return;}
  const row=e.target.closest("[data-fid]");
  if(row){selFinding=(selFinding===+row.dataset.fid)?null:+row.dataset.fid;loadFindings();}
}
function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}

let selAsset=null;
function reviewTag(r){
  return r==="pending"?`<span class="tag t-new">有待审</span>`
    :r==="confirmed"?`<span class="tag t-confirmed">已确认</span>`
    :`<span class="tag t-rejected">已驳回</span>`;
}
async function loadAssets(){
  const params={project:PROJECT,atype:$("#f-atype").value,status:$("#f-status").value,q:$("#f-q").value};
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
        `<td><b>${esc(a.akey)}</b></td><td>${kindTag(a.atype)}</td>`+
        `<td class="muted">${a.parent_akey?esc(a.parent_atype+" : "+a.parent_akey):"—"}</td>`+
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
async function renderAssetDetail(){
  const box=$("#asset-detail");
  if(!selAsset){box.innerHTML="<span class='muted'>← 点击资产行下钻原始观测</span>";return;}
  const i=selAsset.indexOf("/");
  const atype=selAsset.slice(0,i), akey=selAsset.slice(i+1);
  const all=(await api("assets",{project:PROJECT,atype})).assets.find(a=>a.akey===akey);
  if(!all){box.innerHTML="";return;}
  const d=await api("events",{project:PROJECT,ids:all.event_ids.join(",")});
  box.className="";
  box.innerHTML=`<div class="muted" style="margin-bottom:6px">${esc(akey)} ｜ 首见 ${(all.first_seen||"").slice(0,10)} ｜ 末见 ${(all.last_seen||"").slice(0,10)}</div>`+
    (d.events||[]).map(r=>
      `<div class="rec"><div class="hd"><b>#${r.id}</b> ${kindTag(r.kind)} <b>${esc(r.value)}</b> ${tag(r.status)}`+
      ` <span class="muted">${(r.created_at||"").slice(0,10)} · ${r.origin}${r.confidence?"/"+r.confidence:""}</span></div>`+
      (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
      `<div class="src">来源: ${esc(r.source)}</div></div>`).join("")
    ||"<span class='muted'>无观测记录</span>";
}

// ===== 资产树（左树右表）：单独拉全量资产，项目切换/loadAll 时刷新缓存 =====
const TREE={nodes:[],index:{},expanded:{},sel:null,selSet:null,q:"",hideStale:false};
const treeExpKey=()=>"pttree:"+PROJECT;
function saveTreeExp(){try{sessionStorage.setItem(treeExpKey(),JSON.stringify(TREE.expanded))}catch(e){}}
function treeFilter(){TREE.q=$("#tree-q").value.trim().toLowerCase();TREE.hideStale=$("#tree-hidestale").checked;renderAssetTree();}
const epLabel=k=>{if(k.startsWith("?"))return k.slice(1);const i=k.indexOf("/");return i>=0?k.slice(i):k};
function mkNode(atype,akey,asset,synth){
  return {id:atype+"/"+akey,atype,akey,asset:asset||null,synth:!!synth,parent:null,children:[],count:0,
    label:atype==="endpoint"?epLabel(akey):akey,
    title:synth?akey+"（合成根，非库内资产）":akey};
}
async function loadAssetTree(){
  try{
    const d=await api("assets",{project:PROJECT});
    try{TREE.expanded=JSON.parse(sessionStorage.getItem(treeExpKey())||"{}")}catch(e){TREE.expanded={}}
    buildAssetTree(d.assets||[]);
    syncTreeSel();
    renderAssetTree();
  }catch(e){$("#asset-tree").innerHTML="<span class='muted'>资产树加载失败："+esc(e.message)+"</span>";}
}
function buildAssetTree(assets){
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
  // 子树资产计数徽标 + 平铺索引（供锚定/展开定位）
  const idx={};
  const cnt=n=>{let s=n.synth?0:1;n.children.forEach(c=>{s+=cnt(c)});n.count=s;idx[n.id]=n;return s;};
  roots.forEach(cnt);
  const byLabel=(a,b)=>a.label.localeCompare(b.label);
  const sortAll=n=>{n.children.sort(byLabel);n.children.forEach(sortAll);};
  roots.sort(byLabel);roots.forEach(sortAll);
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
      const open=q||TREE.hideStale?true:(TREE.expanded[n.id]!==undefined?TREE.expanded[n.id]:depth===0); // 默认展开第一层；过滤态全展开
      const staleCls=hasFresh(n)?"":" tstale"; // 子树全部 30 天未见 → 灰显
      html+=`<div class="tnode${staleCls} ${TREE.sel===n.id?"on":""}" data-tid="${esc(n.id)}" style="padding-left:${depth*14+4}px" title="${esc(n.title)}">`+
        (n.children.length?`<span class="tcaret" data-caret="${esc(n.id)}">${open?"▾":"▸"}</span>`:`<span class="tcaret tleaf">·</span>`)+
        `<span class="tdot d-${n.atype}"></span><span class="tlabel">${esc(n.label)}</span>`+
        (n.count>1?`<span class="tcount">${n.count}</span>`:"")+
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

async function loadTimeline(){
  const d=await api("timeline",{project:PROJECT});
  $("#tl-events").innerHTML="<tr><th>时间</th><th>类型</th><th>值</th><th>状态</th><th>来源</th></tr>"+
    d.events.map(r=>`<tr><td class="muted" title="${esc(r.created_at)}">${r.created_at}</td><td>${kindTag(r.kind)}</td><td title="${esc(r.value)}">${esc(r.value)}</td><td>${tag(r.status)}</td><td class="src muted" title="${esc(r.source)}">${esc(r.source).slice(0,90)}</td></tr>`).join("");
  $("#tl-changes").innerHTML="<tr><th>时间</th><th>动作</th><th>操作者</th><th>明细</th></tr>"+
    d.changes.map(r=>`<tr><td class="muted" title="${esc(r.at)}">${r.at}</td><td title="${esc(r.action)}">${esc(r.action)}</td><td class="muted">${esc(r.actor||"hist")}</td><td title="${esc(r.detail)}">${esc(r.detail).slice(0,120)||"—"}</td></tr>`).join("");
}

function srcGroup(s){
  s=(s||"(无来源)").split("；")[0];
  const i=s.indexOf("证据"); if(i>0)s=s.slice(0,i);
  s=s.replace(/[,，、\s]+$/,"").trim();
  return s.slice(0,60)||"(无来源)";
}
async function loadReview(){
  const d=await api("pending",{project:PROJECT});
  const items=d.pending||[];
  if(!items.length){$("#review-table").innerHTML="<tr><td colspan=\"7\">队列已清空，全部处理完毕</td></tr>";updBatch();return;}
  // 成熟 inbox 模式：队列=资产决策面（分组批量确认/驳回）。finding/osint 待审不在队列
  // 重复展示——审核内联在发现页（看报文/判据后行内拍板），这里只放一行跳转横幅。
  const fin=items.filter(r=>r.kind==="finding"||r.kind==="osint");
  const ast=items.filter(r=>r.kind!=="finding"&&r.kind!=="osint");
  let html="<thead><tr><th style=\"width:32px\"></th><th style=\"width:56px\">ID</th><th style=\"width:64px\">类型</th>"+
    "<th>值</th><th style=\"width:24%\">备注（点行展开判据卡）</th><th style=\"width:96px\">属性</th><th style=\"width:128px\">操作</th></tr></thead><tbody>";
  if(fin.length){
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>发现 / 情报待审 × ${fin.length}</b> `+
      `<span class="muted">——不再在此重复展示，去发现页看报文/判据后行内拍板</span> `+
      `<button class="mini" onclick="gotoFindingsPending()">去发现页处理</button></td></tr>`;
  }
  if(!ast.length){
    html+=`<tr><td colspan="7" class="muted">资产类队列已空${fin.length?"（仅剩发现/情报待审，见上）":"，全部处理完毕"}</td></tr>`;
    $("#review-table").innerHTML=html+"</tbody>";updBatch();return;
  }
  const fresh=ast.filter(r=>!(r.dup_confirmed>0)), dup=ast.filter(r=>r.dup_confirmed>0);
  const groups={};
  fresh.forEach(r=>{const k=srcGroup(r.source);(groups[k]=groups[k]||[]).push(r)});
  Object.keys(groups).sort((a,b)=>groups[b].length-groups[a].length).forEach((src,gi)=>{
    const g=groups[src], gname="g"+gi;
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>${esc(src)}</b> `+
      `<span class="muted">× ${g.length}</span>`+
      ` <label class="muted" style="margin-left:10px"><input type="checkbox" onchange="tgGroup('${gname}',this.checked)"> 全选本组</label>`+
      ` <button class="mini" onclick="doGroup('${gname}','confirmed')">整组确认</button>`+
      ` <button class="mini" onclick="doGroup('${gname}','rejected')">整组驳回</button></td></tr>`;
    g.forEach(r=>{html+=rvRowHtml(r,gname)});
  });
  if(dup.length){
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>重复嫌疑（同值已有已确认记录）</b> `+
      `<span class="muted">× ${dup.length} · 默认建议驳回或合并到已有记录</span>`+
      ` <label class="muted" style="margin-left:10px"><input type="checkbox" onchange="tgGroup('gdup',this.checked)"> 全选本组</label>`+
      ` <button class="mini" onclick="doGroup('gdup','rejected')">整组驳回</button></td></tr>`;
    dup.forEach(r=>{html+=rvRowHtml(r,"gdup",r.dup_confirmed)});
  }
  $("#review-table").innerHTML=html+"</tbody>";
  updBatch();
}
function rvRowHtml(r,gname,dupN){
  const attr=`${r.origin||""}${r.confidence?"/"+r.confidence:""}`;
  const badge=dupN?`<span class="tag" style="background:#FAC775;color:#412402">同值已有 confirmed ×${dupN}</span> `:"";
  return `<tr class="rv-row" onclick="tgDetail(${r.id},this)">`+
    `<td onclick="event.stopPropagation()"><input type="checkbox" class="rv-check" data-g="${gname}" data-id="${r.id}" onchange="updBatch()"></td>`+
    `<td class="ell muted">#${r.id}</td>`+
    `<td>${kindTag(r.kind)}</td>`+
    `<td class="ell" title="${esc(r.value)}"><b>${esc(r.value)}</b></td>`+
    `<td class="ell muted" title="${esc(r.note)}">${badge}${esc((r.note||"").slice(0,50))||"—"}</td>`+
    `<td class="ell muted" title="${esc(attr)}">${esc(attr)}</td>`+
    `<td onclick="event.stopPropagation()"><button class="btn-ok" onclick="doReview(${r.id},'confirmed')">确认</button> <button class="btn-no" onclick="doReview(${r.id},'rejected')">驳回</button></td></tr>`+
    `<tr class="rv-detail hidden" data-did="${r.id}" data-q="${esc(r.value)}" data-note="${esc(r.note)}" data-kind="${esc(r.kind)}"><td colspan="7">`+
    `<div class="rv-inner"><span class='muted'>点行展开：判据卡（备注全文 + 同值历史 + 跳详情）</span></div></td></tr>`;
}
async function tgDetail(id,tr){
  const d=document.querySelector(`#review-table tr.rv-detail[data-did="${id}"]`);
  if(!d)return;
  const opening=d.classList.contains("hidden");
  d.classList.toggle("hidden");
  tr.classList.toggle("on");
  if(!opening||d.dataset.loaded)return;   // 收起或已加载过：不再请求
  d.dataset.loaded="1";
  const box=d.querySelector(".rv-inner");
  box.innerHTML="<span class='muted'>加载同值历史…</span>";
  try{
    const q=d.dataset.q||"";
    let rel=[];
    if(q){
      const rd=await api("events",{project:PROJECT,value:q});
      rel=(rd.events||[]).filter(r=>r.id!==id);
    }
    box.innerHTML=rvJudgeHtml(id,d.dataset.note||"",rel,q);
  }catch(err){d.dataset.loaded="";box.innerHTML="<span class='muted'>加载失败: "+esc(err.message)+"（再点行重试）</span>";}
}
function rvJudgeHtml(id,note,rel,q){
  const by={}; rel.forEach(r=>{(by[r.status]=by[r.status]||[]).push(r)});
  const cnt=`已确认 ${(by.confirmed||[]).length} · 已驳回 ${(by.rejected||[]).length} · 其他待审 ${(by.new||[]).length}`;
  let h=`<div class="muted" style="margin-bottom:4px"><b>备注全文</b></div>`+
    `<div style="white-space:pre-wrap;margin-bottom:8px">${esc(note)||"<span class='muted'>（无备注）</span>"}</div>`;
  h+=`<div class="muted" style="margin-bottom:4px"><b>同值历史</b>（${esc(q)} · 共 ${rel.length} 条：${cnt}）</div>`;
  h+=rel.length?rel.slice(0,8).map(r=>
      `<div class="rec"><div class="hd"><b>#${r.id}</b> ${kindTag(r.kind)} ${tag(r.status)}`+
      ` <span class="muted">${(r.created_at||"").slice(0,10)} · ${r.origin}${r.confidence?"/"+r.confidence:""}</span></div>`+
      (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
      `<div class="src">来源: ${esc(r.source)}</div></div>`).join("")+
    (rel.length>8?`<div class="muted">…其余 ${rel.length-8} 条略，完整历史见实体/详情页</div>`:"")
    :`<div class="muted">无同值历史（库内首见）</div>`;
  h+=`<div style="margin-top:8px"><span class="muted">报文/证据在详情页唯一渲染：</span> `+
    `<button class="mini" onclick="gotoQueueDetail(${id})">在详情页打开</button></div>`;
  return h;
}
function gotoQueueDetail(id){
  const d=document.querySelector(`#review-table tr.rv-detail[data-did="${id}"]`); if(!d)return;
  gotoAssets(d.dataset.kind||"","",d.dataset.q||"");
}
function gotoFindingsPending(){
  findStatus="new";$("#f-find-status").value="new";
  switchTab("findings");loadFindings();
}
function tgGroup(g,on){
  document.querySelectorAll(`#review-table input.rv-check[data-g="${g}"]`).forEach(c=>c.checked=on);
  updBatch();
}
async function doGroup(gname,action){
  const ids=[...document.querySelectorAll(`#review-table input.rv-check[data-g="${gname}"]`)].map(c=>+c.dataset.id);
  if(!ids.length)return;
  let note=$("#batch-note").value.trim();
  if(!note)note=prompt(`整组${action==="confirmed"?"确认":"驳回"} ${ids.length} 条 — 批注（写入每条留痕）：`,"")||"";
  if(!note){alert("批量操作必须留批注");return;}
  if(!confirm(`确定${action==="confirmed"?"确认":"驳回"} ${ids.length} 条？`))return;
  const r=await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ids,action,note})});
  if(!r.ok){alert(await r.text());return;}
  loadAll();
}
function updBatch(){
  const n=document.querySelectorAll("#review-table input.rv-check:checked").length;
  $("#batch-n").textContent=n;
  $("#batch-bar").style.display=n?"":"none";
}
async function doBatch(action){
  const ids=[...document.querySelectorAll("#review-table input.rv-check:checked")].map(c=>+c.dataset.id);
  if(!ids.length)return;
  const note=$("#batch-note").value.trim();
  if(!note){alert("批量操作必须填批注（写入每条留痕）");return;}
  if(!confirm(`确定${action==="confirmed"?"确认":"驳回"} ${ids.length} 条？`))return;
  const r=await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ids,action,note})});
  if(!r.ok){alert(await r.text());return;}
  $("#batch-note").value="";
  loadAll();
}
async function doReview(id,action){
  await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({id,action})});
  loadAll();
}

async function loadReport(){
  const tpl=$("#r-tpl").value;
  const d=await api("report",{project:PROJECT,template:tpl});
  $("#report-pre").textContent=d.report;
  $("#dl-link").download=(tpl==="pentest"?"pentest-report":"recon-report")+".md";
  $("#dl-link").href=URL.createObjectURL(new Blob([d.report],{type:"text/markdown"}));
}
function copyReport(){navigator.clipboard.writeText($("#report-pre").textContent)}

document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>switchTab(b.dataset.v));
function switchTab(v){
  document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("on",x.dataset.v===v));
  document.querySelectorAll("main section").forEach(s=>s.classList.add("hidden"));
  $("#v-"+v).classList.remove("hidden");
  if(v==="report")loadLint(); // Lint 门禁迁报告·收尾页：进页即查，不再随 loadAll 每次全量跑
}
function gotoAssets(kind,status,q){
  const MAP={domain:"domain",port:"service",path:"endpoint",param:"endpoint",
             host:"host",service:"service",endpoint:"endpoint"};
  $("#f-atype").value=(kind&&MAP[kind])||"";
  $("#f-status").value=status==="new"?"pending":(status||"");
  $("#f-q").value=q||"";
  // 深链跳转语义=按过滤看全量，清掉树锚定避免被子树过滤叠加
  TREE.sel=null;TREE.selSet=null;
  $("#tree-sel-bar").classList.add("hidden");
  renderAssetTree();
  switchTab("assets");
  loadAssets();
}
boot();
