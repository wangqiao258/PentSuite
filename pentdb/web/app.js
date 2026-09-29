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
function loadAll(){loadOverview();loadSop();loadLint();loadFindings();loadAssets();loadTimeline();loadReview();loadReport()}

const ST_TXT={done:"✓ 已测",registered:"◐ 已登记",missing:"○ 未测(提示)"};
let sopFilter=null;
async function loadSop(){
  const d=await api("sop",{project:PROJECT});
  const stages=Object.keys(d.stage.flags||{});
  const cur=d.stage.index;
  $("#sop-stage").innerHTML='<div class="stepper">'+stages.map((s,i)=>
    `<span class="step ${i<cur?'done':(i===cur?'cur':'')}">${i<cur?'✓ ':''}${s}</span>`).join("")+
    `<span class="muted" style="align-self:center;margin-left:8px">${d.stage.current}（${d.stage.index}/${d.stage.total}）</span></div>`;
  const ST_COLOR={done:"var(--teal)",registered:"var(--amber)",missing:"var(--red)"};
  const sc=(n,label,st)=>st
    ?`<div class="card click ${sopFilter===st?"on":""}" data-st="${st}" title="点击只看该状态，再点取消">`+
     `<b style="color:${ST_COLOR[st]||""}">${n}</b><span>${label}${sopFilter===st?" ●":""}</span></div>`
    :`<div class="card"><b>${n}</b><span>${label}</span></div>`;
  $("#sop-cards").innerHTML=
    sc(d.total,"提示项","")+sc(d.done,"✓ 已测","done")+
    sc(d.registered,"◐ 已登记","registered")+sc(d.missing,"○ 未测","missing");
  // 阶段视图：计划（菜单）× 执行（test 流水）；状态过滤时只留含匹配项的阶段
  const SV_TXT={done:"✓",registered:"◐",missing:"○"};
  $("#stage-view").innerHTML=(d.stage_view||[]).filter(v=>
    !sopFilter||v.menu.some(it=>it.state===sopFilter)).map(v=>{
    const menuItems=sopFilter?v.menu.filter(it=>it.state===sopFilter):v.menu;
    const menu=menuItems.map(it=>{
      let h=`<span class="sopitem st-${it.state}" title="${ST_TXT[it.state]}${it.when?"："+it.when:""}（提示层，非门禁）">${SV_TXT[it.state]} ${esc(it.term)}`;
      if(it.state==="missing"&&it.when)h+=` <span class="muted">${esc(it.when)}</span>`;
      if(it.state==="done"&&it.ev)h+=` <span class="muted">${it.ev}</span>`;
      return h+`</span>`;
    }).join("")||"<span class='muted'>该阶段无提示项</span>";
    const exe=v.executed.length?v.executed.map(t=>
      `<div class="rec"><div class="hd"><b>#${t.id}</b> ${esc(t.value)} ${tag(t.status)} `+
      `<span class="muted">${t.created_at}</span></div>`+
      (t.note?`<div class="muted">${esc(t.note)}</div>`:"")+
      `<div class="src">归因: ${t.parent_ext?esc(t.parent_ext):"—"} ｜ 来源: ${esc(t.source)}</div></div>`).join("")
      :"<span class='muted'>暂无执行流水（AI 执行后 add --kind test --stage "+esc(v.stage)+" 落库即在此聚合）</span>";
    const pend=(v.pending.length&&(!sopFilter||sopFilter==="registered"))?`<div class="muted" style="margin:2px 0">登记待执行：${v.pending.map(p=>esc(p.term)).join("、")}</div>`:"";
    return `<div class="grp"><h4>${v.complete?"✓ ":""}${esc(v.stage)}（${v.done}/${v.total} 参考 · 流水 ${v.executed.length} 条）</h4>`+
      `<div style="margin-bottom:4px">${menu}</div>${pend}`+
      `<details ${v.executed.length?"open":""}><summary class="muted" style="cursor:pointer">执行流水（${v.executed.length}）</summary>${exe}</details></div>`;
  }).join("")||(sopFilter?"<div class='muted'>当前状态过滤下无阶段菜单项</div>":"<div class='muted'>无阶段数据</div>");
}
$("#sop-cards").onclick=e=>{
  const c=e.target.closest(".card[data-st]"); if(!c)return;
  sopFilter=(sopFilter===c.dataset.st)?null:c.dataset.st;
  loadSop();
};
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
  return `<div class="frow2 ${selFinding===r.id?"on":""}" data-fid="${r.id}">`+
    `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">`+
    `<span class="sev-dot sev-${r.severity||"none"}"></span><b>${esc(r.title||r.value)}</b> ${lifeTag(lifeOf(r))}`+
    `<span style="flex:1"></span><span class="muted">#${r.id}</span></div>`+
    `<div class="muted" style="font-size:12px;margin-top:2px">`+
    (tgt?esc(tgt)+" · ":"")+
    (t?`最近复测：${esc((t.note||t.value||"").slice(0,40))} · `:"")+
    `${(r.created_at||"").slice(0,10)}</div></div>`;
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
      `<div class="rec"><div class="hd"><b>${esc(t.value)}</b> ${tag(t.status)} ${t.stage?`<span class="tag t-kind">${esc(t.stage)}</span>`:""}`+
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
          <select id="rt-stage"></select>
          <button class="btn-ok" onclick="doRetest(${r.id})">登记复测</button>
        </div><div class="muted" id="rt-msg"></div></div>`;
  }else{
    html+=packet;
  }
  $("#finding-detail").innerHTML=html;
  if(isFinding){loadEvidencePanel(r,rel);fillStageSelect();}
}
async function setLife(fid,code){
  if(!code)return;
  const r=await fetch("/api/retest",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({finding_id:fid,lifecycle:code})});
  if(!r.ok){alert("生命周期更新失败："+await r.text());return;}
  loadFindings();
}
let STAGES=[];
async function fillStageSelect(){
  const sel=$("#rt-stage"); if(!sel)return;
  if(!STAGES.length){
    try{const st=await api("stages",{project:PROJECT});STAGES=st.all||[];}catch(e){}
  }
  sel.innerHTML=STAGES.map(s=>{
    const pick=s.includes("利用")||s.includes("验证");
    return `<option ${pick?"selected":""}>${esc(s)}</option>`;}).join("")||"<option>利用验证</option>";
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
    source:$("#rt-source").value.trim()||"面板手工复测",stage:$("#rt-stage").value,
    lifecycle:$("#rt-life")?$("#rt-life").value:""};
  const msg=$("#rt-msg");
  if(!body.action){msg.style.color="var(--red)";msg.textContent="动作必填（只改生命周期用详情头部的快捷下拉）";return;}
  try{
    const r=await fetch("/api/retest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||r.status);
    msg.style.color="var(--teal)";
    msg.textContent=`已登记复测 #${d.id}（stage=${d.stage}${body.lifecycle?" · 生命周期→"+body.lifecycle:""}）✓`;
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
  const assets=d.assets||[], sum=d.summary||{};
  $("#asset-hint").textContent=`实体 ${assets.length} ｜ `+Object.keys(sum).sort().map(k=>`${k} ${sum[k]}`).join(" · ");
  $("#asset-table").innerHTML="<tr><th>实体（规范 key）</th><th>类型</th><th>上级</th><th>属性</th><th>观测 / 审</th><th>范围</th><th>首见 · 末见</th><th>生命周期</th></tr>"+
    assets.map(a=>{
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
    }).join("")||"<tr><td>无资产（rebuild-assets 可随时重建）</td></tr>";
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
      ` <span class="muted">${(r.created_at||"").slice(0,10)} · ${r.origin}${r.confidence?"/"+r.confidence:""}${r.stage?" · "+esc(r.stage):""}</span></div>`+
      (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
      `<div class="src">来源: ${esc(r.source)}</div></div>`).join("")
    ||"<span class='muted'>无观测记录</span>";
}

async function loadTimeline(){
  const d=await api("timeline",{project:PROJECT});
  $("#tl-events").innerHTML="<tr><th>时间</th><th>类型</th><th>值</th><th>状态</th><th>来源</th></tr>"+
    d.events.map(r=>`<tr><td class="muted" title="${esc(r.created_at)}">${r.created_at}</td><td>${kindTag(r.kind)}</td><td title="${esc(r.value)}">${esc(r.value)}</td><td>${tag(r.status)}</td><td class="src muted" title="${esc(r.source)}">${esc(r.source).slice(0,90)}</td></tr>`).join("");
  $("#tl-changes").innerHTML="<tr><th>时间</th><th>动作</th><th>明细</th></tr>"+
    d.changes.map(r=>`<tr><td class="muted" title="${esc(r.at)}">${r.at}</td><td title="${esc(r.action)}">${esc(r.action)}</td><td title="${esc(r.detail)}">${esc(r.detail).slice(0,120)||"—"}</td></tr>`).join("");
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
  // 成熟 inbox 模式：队列=决策面。同值已有 confirmed 的重复嫌疑剔除出正队列、置底默认折叠；
  // 展开只渲染判据卡（备注全文+同值历史），报文/证据在详情页唯一渲染，队列跳转过去。
  const fresh=items.filter(r=>!(r.dup_confirmed>0)), dup=items.filter(r=>r.dup_confirmed>0);
  const groups={};
  fresh.forEach(r=>{const k=srcGroup(r.source);(groups[k]=groups[k]||[]).push(r)});
  let html="<thead><tr><th style=\"width:32px\"></th><th style=\"width:56px\">ID</th><th style=\"width:64px\">类型</th>"+
    "<th>值</th><th style=\"width:24%\">备注（点行展开判据卡）</th><th style=\"width:96px\">属性</th><th style=\"width:128px\">操作</th></tr></thead><tbody>";
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
  const kind=d.dataset.kind||"", q=d.dataset.q||"";
  if(kind==="finding"||kind==="osint"){selFinding=id;switchTab("findings");loadFindings();}
  else gotoAssets(kind,"",q);
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
}
function gotoAssets(kind,status,q){
  const MAP={domain:"domain",port:"service",path:"endpoint",param:"endpoint",
             host:"host",service:"service",endpoint:"endpoint"};
  $("#f-atype").value=(kind&&MAP[kind])||"";
  $("#f-status").value=status==="new"?"pending":(status||"");
  $("#f-q").value=q||"";
  switchTab("assets");
  loadAssets();
}
boot();
