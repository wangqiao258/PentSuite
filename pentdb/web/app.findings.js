// PentDB 面板 · 发现·漏洞视图：列表/筛选/详情复测工作台/证据链（事件委托）
let DEDUP_MAP={};  // dedup_key -> 该指纹下 finding 条数（列表打「同指纹」标用，loadFindings 刷新）
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
    (DEDUP_MAP[r.dedup_key]>1?`<span class="tag" style="background:#FAC775;color:#412402">同指纹 ×${DEDUP_MAP[r.dedup_key]}</span>`:"")+
    `<span style="flex:1"></span><span class="muted">#${r.id}</span></div>`+
    `<div class="muted" style="font-size:12px;margin-top:2px">`+
    (tgt?esc(tgt)+" · ":"")+
    (t?`最近复测：${esc((t.note||t.value||"").slice(0,40))} · `:"")+
    `${(r.created_at||"").slice(0,10)}</div>`+
    (pend?`<div style="margin-top:4px" onclick="event.stopPropagation()"><button class="btn-ok" onclick="doReview(${r.id},'confirmed')">确认</button> <button class="btn-no" onclick="doReview(${r.id},'rejected')">驳回</button></div>`:"")+
    `</div>`;
};
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
    `<div class="muted" style="margin-top:8px">${(r.created_at||"")} · scope=${esc(r.scope||"unknown")}`+
    (r.dedup_key?` · 指纹 ${esc(r.dedup_key)}`:"")+"</div>";
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
  loadEvidencePanel(r,rel).catch(err=>{  // osint 同样加载（此前只 finding 加载，osint 的报文区永远卡"加载中…"）；任何异常降级为可见文案而非无限占位
    const pk=$("#fd-packets"); if(pk)pk.className="muted",pk.textContent="事实报文加载失败："+err.message;
    const ev=$("#ev-panel"); if(ev)ev.textContent="证据链加载失败："+err.message;
  });
}
async function setLife(fid,code){
  if(!code)return;
  const r=await fetch("/api/retest",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({finding_id:fid,lifecycle:code})});
  if(!r.ok){alert("生命周期更新失败："+await r.text());return;}
  loadFindings();
}
const evIsPkt=e=>e.etype==="request"||e.etype==="response"||(e.note&&(e.note.startsWith("request")||e.note.startsWith("response")));
// exec 类证据：cmd_exec 单通道落盘的 .log（note 以 "output" 开头）——经 /api/evidence/packet 只读解析成报文
const evIsExecLog=e=>e.etype==="file"&&e.note&&e.note.startsWith("output");
const EXEC_FLAG_HINTS=[
  ["response_inferred","（无 -i，状态行缺失，响应体原文）"],
  ["has_variables","（含未求值变量）"],
  ["inferred_method","（方法由参数推断）"],
  ["inferred_header","（Content-Type 为补全默认值）"],
  ["truncated","（多 URL 只取第一个）"],
  ["empty","（输出为空）"],
  ["data_from_file","（data 为文件引用，原文保留）"],
];
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
  const pkts=evs.filter(evIsPkt);
  // exec .log 证据：先并行调 /api/evidence/packet，解析成功升级为报文组，失败降级回文件卡
  const execEvs=evs.filter(e=>!evIsPkt(e)&&evIsExecLog(e));
  const files=evs.filter(e=>!evIsPkt(e)&&!evIsExecLog(e));
  const execResults=await Promise.all(execEvs.map(e=>
    fetch("/api/evidence/packet?id="+e.id).then(r=>r.ok?r.json():null).catch(()=>null)));
  const execGroups=[];
  execResults.forEach((v,i)=>{
    if(v&&v.ok&&typeof v.request==="string")execGroups.push({exec:execEvs[i],pkt:v});
    else files.push(execEvs[i]);
  });
  files.sort((a,b)=>a.id-b.id);
  // —— 报文配对：request 开新组，response 归入最近一个缺响应的组（多次 add --update 得多组）——
  const groups=[];
  pkts.forEach(e=>{
    const isReq=e.etype==="request"||(e.note||"").startsWith("request");
    if(isReq){groups.push({req:e,resp:null});return;}
    const last=groups[groups.length-1];
    if(last&&!last.resp)last.resp=e;else groups.push({req:null,resp:e});
  });
  const allGroups=groups.concat(execGroups);  // exec 解析组插在事实报文组之后
  if(pkBox){
    pkBox.className="";
    pkBox.innerHTML=allGroups.length?allGroups.map((g,i)=>{
      if(g.exec){  // exec 自动解析组：内容已随接口返回，无需再 fillPkt
        const e=g.exec,fl=g.pkt.flags||{};
        const hints=EXEC_FLAG_HINTS.filter(([k])=>fl[k]).map(([,s])=>s);
        return `<div class="pkt-card">`+
          `<div class="hd"><b>第 ${i+1} 组</b><span class="muted">exec 自动解析 · 挂 #${e.event_id} · sha256 ${(e.sha256||"").slice(0,16)}…</span>`+
          `<span style="flex:1"></span><button class="mini" data-ev="${e.id}">查看 .log 原文</button></div>`+
          `<div class="pkt-tabs"><span class="pkt-tab on" data-pkt="req">请求</span><span class="pkt-tab" data-pkt="resp">响应</span></div>`+
          `<pre data-side="req" id="pkt-req-${i}">${esc(g.pkt.request||"")}</pre>`+
          `<pre data-side="resp" id="pkt-resp-${i}" class="hidden">${esc(g.pkt.response||"")}</pre>`+
          (hints.length?`<div class="muted" style="font-size:12px;margin-top:2px">${hints.join(" ")}</div>`:"")+
          `<pre class="hidden" id="evc-${e.id}"></pre></div>`;
      }
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
    if(!allGroups.length)pkBox.className="muted";
    const loads=[];
    allGroups.forEach((g,i)=>{
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
  DEDUP_MAP={};all.forEach(r=>{if(r.dedup_key)DEDUP_MAP[r.dedup_key]=(DEDUP_MAP[r.dedup_key]||0)+1});
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
