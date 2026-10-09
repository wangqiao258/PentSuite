// PentDB 面板 · 壳层与共享内核：常量 / 全局状态 / 通用工具 / 总览视图 / 导航（boot() 在 app.report.js 尾部触发）
const $=s=>document.querySelector(s);
const Kinds=["domain","port","path","param","finding","osint","note","test"];
let PROJECT="";
const qs=o=>new URLSearchParams(o).toString();
async function api(path,params){const r=await fetch("/api/"+path+(params?"?"+qs(params):""));if(!r.ok)throw new Error(await r.text());return r.json()}

async function boot(){
  const d=await api("projects");
  const sel=$("#proj"), showArch=$("#show-arch");
  const visible=()=>d.projects.filter(p=>showArch.checked||!p.archived);
  const fillProj=()=>{
    const list=visible();
    sel.innerHTML=list.map(p=>`<option value="${p.name}">${p.name}${p.archived?"（已归档）":""}</option>`).join("");
    if(PROJECT&&list.some(p=>p.name===PROJECT))sel.value=PROJECT;
  };
  // 深链/当前项目已归档：自动勾上「含归档」，保证下拉能选中它（否则下拉显示与页面内容错位）
  const urlProj=new URLSearchParams(location.search).get("project")||"";
  if(urlProj&&d.projects.some(p=>p.name===urlProj&&p.archived))showArch.checked=true;
  fillProj();
  PROJECT=urlProj||sel.value;
  if(PROJECT)sel.value=PROJECT;
  sel.onchange=()=>{PROJECT=sel.value;location.search="?project="+encodeURIComponent(PROJECT)};
  showArch.onchange=()=>{fillProj();if(PROJECT&&!visible().some(p=>p.name===PROJECT)){PROJECT=sel.value;location.search="?project="+encodeURIComponent(PROJECT)}};
  $("#m-kind").innerHTML=Kinds.filter(k=>k!=="test").map(k=>`<option>${k}</option>`).join("");
  $("#m-kind").onchange=()=>$("#m-sev").classList.toggle("hidden",$("#m-kind").value!=="finding");
  loadAll();
}
function loadAll(){loadOverview();loadFindings();loadAssetTree();loadAssets();loadTimeline();loadReview();loadReport()}

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
function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}

async function loadOverview(){
  const d=await api("overview",{project:PROJECT});
  const sug=await api("suggestions",{project:PROJECT});
  // AI 建议卡（成熟产品式分层：结论摘要外露 → 全文 details 折叠 → CTA 悬停说明后果）
  // 批次计划正文在 detail（note 为空），旧版只渲染 value/note 导致卡片信息量≈0
  $("#sug-list").innerHTML=(sug.suggestions||[]).map(r=>{
    const body=(r.note&&r.note.trim())?r.note:(r.detail||"");
    const isPlan=/【(已做|结论|下一步)】/.test(body);
    return `<div class="fitem"><b>${esc(r.title||"建议")}</b> ${tag(r.status)} `+
    `<span class="muted">#${r.id} · ${r.created_at} · ${r.origin}</span>`+
    (isPlan
      ?`<div class="detail" style="margin-top:4px">${suggestDigest(body)}</div>`+
       `<details style="margin-top:4px"><summary class="muted" style="cursor:pointer">展开完整计划（已做 / 结论 / 下一步）</summary>`+
       `<div style="white-space:pre-wrap;margin-top:6px">${fmtSections(body)}</div></details>`
      :(r.value?`<div class="detail">${esc(r.value)}</div>`:"")+
       (r.note?`<div class="muted">依据：${esc(r.note)}</div>`:""))+
    `<div class="src">来源：${esc(r.source)}</div>`+
    (r.status==="new"?`<div><button class="btn-ok" title="采纳：该计划成为报告「复测计划」节引用的唯一最新计划" onclick="doReview(${r.id},'confirmed')">采纳</button> <button class="btn-no" title="忽略：报告将没有复测计划节，下次批次再出新计划可替代" onclick="doReview(${r.id},'rejected')">忽略</button></div>`:"")+
    `</div>`;}).join("")||"<div class='muted'>暂无建议（AI 在采集/测试批次结束后生成）</div>";
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
let ASSET_MAP = {};
let TESTS=[];
let selAsset=null;
// ===== 资产树（左树右表）：单独拉全量资产，项目切换/loadAll 时刷新缓存 =====
const TREE={nodes:[],index:{},expanded:{},sel:null,selSet:null,q:"",hideStale:false};
function gotoQueueDetail(id){
  const d=document.querySelector(`#review-table tr.rv-detail[data-did="${id}"]`); if(!d)return;
  gotoAssets(d.dataset.kind||"","",d.dataset.q||"");
}
function gotoFindingsPending(){
  findStatus="new";$("#f-find-status").value="new";
  switchTab("findings");loadFindings();
}
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>switchTab(b.dataset.v));
function switchTab(v){
  document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("on",x.dataset.v===v));
  document.querySelectorAll("main section").forEach(s=>s.classList.add("hidden"));
  $("#v-"+v).classList.remove("hidden");
  if(v==="report")loadLint(); // Lint 门禁迁报告·收尾页：进页即查，不再随 loadAll 每次全量跑
  if(v==="explore")loadExplore(); // 探索·计划页：进页即拉（只读视图，写走 CLI）
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
