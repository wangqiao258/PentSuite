// PentDB 面板 · 时间线 + 待审队列视图：复测结论平铺 / 资产按来源分组 / 判据卡展开 / 批量判定
// test 结论机读词（与后端 TEST_CONCLUSIONS 同序；复测时间轴聚合与生命周期联动依赖）
const TEST_WORDS=["复现","未复现","已修复","部分修复","仍存在","待复测"];
const testWord=n=>{n=(n||"").trim();return TEST_WORDS.find(w=>n.startsWith(w))||""};
// 审核动词表：动词是对象属性不是作用域属性——行级/组头/批量条/confirm/prompt 全从这取词，一处改处处改。
// 未列出的 kind（资产类 domain/host/port/path/param 等）走默认 确认/驳回。
const VERBS={test:{ok:"采信",no:"不采信"},suggestion:{ok:"采纳",no:"忽略"}};
const vFor=k=>VERBS[k]||{ok:"确认",no:"驳回"};
const vOk=(k,action)=>action==="confirmed"?vFor(k).ok:vFor(k).no;
const NOUNS={test:"复测结论",suggestion:"复测计划"};
const nounOf=k=>NOUNS[k]||"记录";
// 勾选集合 → kind 计数（组头/批量条/confirm 按 kind 拆分措辞；混选回退通用词，按钮不增殖——信息拆分进文案）
function kindMix(boxes){
  const kinds={};boxes.forEach(c=>{const k=c.dataset.kind||"asset";kinds[k]=(kinds[k]||0)+1});
  const ks=Object.keys(kinds);
  return {kinds,single:ks.length===1?ks[0]:null,total:boxes.length};
}
function mixDesc(mix,action){
  const word=mix.single?vOk(mix.single,action):(action==="confirmed"?"确认":"驳回");
  const parts=Object.keys(mix.kinds).map(k=>`${vOk(k,action)} ${mix.kinds[k]} 条${nounOf(k)}`).join("、");
  return {word,parts};
}
async function loadTimeline(){
  const d=await api("timeline",{project:PROJECT});
  $("#tl-events").innerHTML="<tr><th>时间</th><th>类型</th><th>值</th><th>状态</th><th>来源</th></tr>"+
    d.events.map(r=>`<tr><td class="muted" title="${esc(r.created_at)}">${fmtTime(r.created_at)}</td><td>${kindTag(r.kind)}</td><td title="${esc(r.value)}">${esc(r.value)}</td><td>${tag(r.status)}</td><td class="src muted" title="${esc(r.source)}">${esc(r.source).slice(0,90)}</td></tr>`).join("");
  $("#tl-changes").innerHTML="<tr><th>时间</th><th>动作</th><th>操作者</th><th>明细</th></tr>"+
    d.changes.map(r=>`<tr><td class="muted" title="${esc(r.at)}">${fmtTime(r.at)}</td><td title="${esc(r.action)}">${esc(r.action)}</td><td class="muted">${esc(r.actor||"hist")}</td><td title="${esc(r.detail)}">${esc(r.detail).slice(0,120)||"—"}</td></tr>`).join("");
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
  // 分流（每类待审一个决策面，互不重复展示）：
  //  - finding/osint：审核内联在发现页（看报文/判据后行内拍板），这里只放跳转横幅；
  //  - note 类（复盘/笔记）：是记录不是待办（plan-review 落库即自动确认），只放提示横幅；
  //  - test：复测结论待审——平铺展示（拍板：不做母 finding 分组），母发现链接即上下文，
  //    确认=该结论进入报告「复测记录」节（真下游），驳回=不进报告；
  //  - 资产类（domain/port/path/param）：按来源分组批量确认/驳回（recon 批量的 inbox 模式）。
  const fin=items.filter(r=>r.kind==="finding"||r.kind==="osint");
  const nt=items.filter(r=>r.kind==="note");
  const tests=items.filter(r=>r.kind==="test");
  const ast=items.filter(r=>r.kind!=="finding"&&r.kind!=="osint"&&r.kind!=="note"&&r.kind!=="test");
  let html="<thead><tr><th style=\"width:32px\"></th><th style=\"width:56px\">ID</th><th style=\"width:64px\">类型</th>"+
    "<th>值</th><th style=\"width:24%\">备注（点行展开判据卡）</th><th style=\"width:96px\">属性</th><th style=\"width:128px\">操作</th></tr></thead><tbody>";
  if(fin.length){
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>发现 / 情报待审 × ${fin.length}</b> `+
      `<span class="muted">——不再在此重复展示，去发现页看报文/判据后行内拍板</span> `+
      `<button class="mini" onclick="gotoFindingsPending()">去发现页处理</button></td></tr>`;
  }
  if(nt.length){
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>记录类 × ${nt.length}</b> `+
      `<span class="muted">——复盘/笔记是记录不是待审项（自动确认），去时间线查看即可</span></td></tr>`;
  }
  if(tests.length){
    html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>复测结论待审 × ${tests.length}</b> `+
      `<span class="muted">——平铺展示；点行展开看母发现与依据；采信=该结论进入报告「复测记录」节（漏洞记录在发现页审）</span> `+
      `<label class="muted" style="margin-left:10px"><input type="checkbox" onchange="tgGroup('gtest',this.checked)"> 全选本组</label>`+
      ` <button class="mini" onclick="doGroup('gtest','confirmed')">整组${vOk("test","confirmed")}</button>`+
      ` <button class="mini" onclick="doGroup('gtest','rejected')">整组${vOk("test","rejected")}</button></td></tr>`;
    tests.forEach(r=>{html+=rvRowHtml(r,"gtest")});
  }
  if(ast.length){
    const fresh=ast.filter(r=>!(r.dup_confirmed>0)), dup=ast.filter(r=>r.dup_confirmed>0);
    const groups={};
    fresh.forEach(r=>{const k=srcGroup(r.source);(groups[k]=groups[k]||[]).push(r)});
    Object.keys(groups).sort((a,b)=>groups[b].length-groups[a].length).forEach((src,gi)=>{
      const g=groups[src], gname="g"+gi;
      // 组头动词按组内 kind 推导：纯 kind 组用专属动词（如纯 suggestion 组=整组采纳/忽略），混合组回退通用词
      const gk=g.every(r=>r.kind===g[0].kind)?g[0].kind:null;
      html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>${esc(src)}</b> `+
        `<span class="muted">× ${g.length}</span>`+
        ` <label class="muted" style="margin-left:10px"><input type="checkbox" onchange="tgGroup('${gname}',this.checked)"> 全选本组</label>`+
        ` <button class="mini" onclick="doGroup('${gname}','confirmed')">整组${vOk(gk,"confirmed")}</button>`+
        ` <button class="mini" onclick="doGroup('${gname}','rejected')">整组${vOk(gk,"rejected")}</button></td></tr>`;
      g.forEach(r=>{html+=rvRowHtml(r,gname)});
    });
    if(dup.length){
      const dk=dup.every(r=>r.kind===dup[0].kind)?dup[0].kind:null;
      html+=`<tr style="background:var(--gray-bg)"><td colspan="7"><b>重复嫌疑（同值已有已确认记录）</b> `+
        `<span class="muted">× ${dup.length} · 默认建议驳回或合并到已有记录</span>`+
        ` <label class="muted" style="margin-left:10px"><input type="checkbox" onchange="tgGroup('gdup',this.checked)"> 全选本组</label>`+
        ` <button class="mini" onclick="doGroup('gdup','rejected')">整组${vOk(dk,"rejected")}</button></td></tr>`;
      dup.forEach(r=>{html+=rvRowHtml(r,"gdup",r.dup_confirmed)});
    }
  }
  if(!ast.length&&!tests.length){
    html+=`<tr><td colspan="7" class="muted">队列已清空${fin.length||nt.length?"（发现/记录类见上方横幅）":"，全部处理完毕"}</td></tr>`;
  }
  $("#review-table").innerHTML=html+"</tbody>";
  updBatch();
}
// suggestion(批次计划)行摘要：优先取【结论】+【下一步】段（决策所需），无段落标记则回退全文
function suggestDigest(body){
  const seg=(tag)=>{
    const m=body.match(new RegExp("【"+tag+"】([\\s\\S]*?)(?=【[^】]*】|$)"));
    return m?m[1].replace(/\s+/g," ").trim():"";
  };
  const concl=seg("结论"), next=seg("下一步");
  let s="";
  if(concl)s+="【结论】"+concl+"　";
  if(next)s+="【下一步】"+next;
  return esc((s||body.replace(/\s+/g," ")).slice(0,420))+(s.length>420?"…":"");
}
// 结论词徽标配色（语义色只表语义：teal=复现实锤，amber=待复测未定，gray=负向/已收敛）
const CW_STYLE={"复现":["#E1F5EE","#085041"],"待复测":["#FAEEDA","#854F0B"],
  "未复现":["#F1EFE8","#5F5E5A"],"已修复":["#F1EFE8","#5F5E5A"],"部分修复":["#F1EFE8","#5F5E5A"],"仍存在":["#F1EFE8","#5F5E5A"]};
function rvRowHtml(r,gname,dupN){
  const attr=`${r.origin||""}${r.confidence?"/"+r.confidence:""}`;
  // suggestion(批次计划)行：摘要取【结论】+【下一步】段并放宽，否则 120 字截断只露【已做】开头，用户无从决策
  const isSug=r.kind==="suggestion";
  const isTest=r.kind==="test";
  const badge=dupN?`<span class="tag" style="background:#FAC775;color:#412402">同值已有 confirmed ×${dupN}</span> `:"";
  const sugHint=isSug?`<span class="tag" style="background:#BDE3FF;color:#0B4A7A">AI 计划 · 点行展开看全文</span> `:"";
  // 复测结论行：机读结论词徽标（复现/待复测…）+ 母发现链接（被审对象=决策上下文）
  const cw=isTest?testWord(r.note):"";
  const cwTag=cw?`<span class="tag" style="background:${CW_STYLE[cw][0]};color:${CW_STYLE[cw][1]}" `+
    `title="机读结论词：母发现的生命周期联动与复测时间轴聚合依赖它">${cw}</span> `:"";
  const parentCell=!isTest?"":(r.parent
    ?`<div class="muted" style="font-size:12px;margin-top:2px">母发现 `+
      `<span style="cursor:pointer;text-decoration:underline dotted;color:var(--info)" `+
      `onclick="event.stopPropagation();gotoFinding(${r.parent.id})" `+
      `title="在发现页打开母发现：看报文/证据/七段详情">#${r.parent.id} ${esc(r.parent.title)}</span> `+
      `<span class="sev-dot sev-${r.parent.severity||"none"}"></span>${lifeTag(r.parent.lifecycle)}${tag(r.parent.status)}</div>`
    :`<div class="muted" style="font-size:12px;margin-top:2px">母发现 未解析（parent_ext=${esc(r.parent_ext||"—")}）</div>`);
  // 决策自足：正文优先备注，备注为空回退 detail（suggestion/计划类内容在 detail）
  const body=(r.note&&r.note.trim())?r.note:(r.detail||"");
  const digest=body?(isSug?suggestDigest(body):esc(body).replace(/\s+/g," ").slice(0,120)):"";
  // 动作语义（真下游写进 tooltip；动词从 VERBS 表取——行级/组头/批量条同一套词）
  const okTitle=isTest?"采信=该复测结论进入报告「复测记录」节，作为漏洞复现证据（批注必填）"
    :(isSug?"采纳：这条建议成为报告里引用的最新复测计划":"");
  const noTitle=isTest?"不采信=不进入报告；原因写：误报、依据不足、无法复现或重复（批注必填）"
    :(isSug?"忽略：报告将不含复测计划，下次批次会生成新计划":"");
  return `<tr class="rv-row" onclick="tgDetail(${r.id},this)">`+
    `<td onclick="event.stopPropagation()"><input type="checkbox" class="rv-check" data-g="${gname}" data-id="${r.id}" data-kind="${esc(r.kind)}" onchange="updBatch()"></td>`+
    `<td class="ell muted">#${r.id}</td>`+
    `<td>${kindTag(r.kind)}</td>`+
    (isTest?`<td title="${esc(r.value)}"><b>${esc(r.value)}</b>${parentCell}</td>`
           :`<td class="ell" title="${esc(r.value)}"><b>${esc(r.value)}</b></td>`)+
    `<td class="ell muted" title="${esc(isSug?body.slice(0,1200):body.slice(0,400))}">${sugHint}${cwTag}${badge}${digest||"—"}</td>`+
    `<td class="ell muted" title="${esc(attr)}">${esc(attr)}</td>`+
    `<td onclick="event.stopPropagation()"><button class="btn-ok" onclick="doReview(${r.id},'confirmed',undefined,'${r.kind}')" ${okTitle?`title="${okTitle}"`:''}>${vFor(r.kind).ok}</button> <button class="btn-no" onclick="doReview(${r.id},'rejected',undefined,'${r.kind}')" ${noTitle?`title="${noTitle}"`:''}>${vFor(r.kind).no}</button></td></tr>`+
    `<tr class="rv-detail hidden" data-did="${r.id}" data-q="${esc(r.value)}" data-note="${esc(body)}" data-kind="${esc(r.kind)}" data-pid="${r.parent?r.parent.id:''}" data-ptitle="${r.parent?esc(r.parent.title):''}" data-psev="${r.parent?esc(r.parent.severity):''}" data-pstatus="${r.parent?esc(r.parent.status):''}" data-plife="${r.parent?esc(r.parent.lifecycle):''}"><td colspan="7">`+
    `<div class="rv-inner"><span class='muted'>点行展开：判据卡（${isTest?"母发现 + 结论全文 + 同母发现复测 + 母发现详情入口":"备注全文 + 同值历史"}）</span></div></td></tr>`;
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
  const kind=d.dataset.kind||"";
  box.innerHTML="<span class='muted'>"+(kind==="test"?"加载母发现与同母发现复测…":"加载同值历史…")+"</span>";
  try{
    let rel=[],sib=[],parent=null;
    if(kind==="test"){
      // 正确的关联轴=母发现（test 的 value 天生唯一，同值历史恒为空）：拉全量 test 按 parent_ext 过滤
      const pid=d.dataset.pid||"";
      if(pid)parent={id:+pid,title:d.dataset.ptitle||"",severity:d.dataset.psev||"",
        status:d.dataset.pstatus||"",lifecycle:d.dataset.plife||""};
      const td=await api("events",{project:PROJECT,kinds:"test"});
      sib=(td.events||[]).filter(r=>r.id!==id&&pid&&
        (r.parent_ext||"").split(",").map(s=>s.trim()).includes(pid));
    }else{
      const q=d.dataset.q||"";
      if(q){
        const rd=await api("events",{project:PROJECT,value:q});
        rel=(rd.events||[]).filter(r=>r.id!==id);
      }
    }
    box.innerHTML=rvJudgeHtml(id,d.dataset.note||"",rel,d.dataset.q||"",kind,sib,parent);
  }catch(err){d.dataset.loaded="";box.innerHTML="<span class='muted'>加载失败: "+esc(err.message)+"（再点行重试）</span>";}
}
function fmtSections(s){
  if(!s)return"";
  return esc(s).replace(/【(已做|结论|下一步|描述|请求|payload|判据|原因|手工验证|修复)】/g,"\n<b>【$1】</b>");
}
function rvJudgeHtml(id,note,rel,q,kind,sib,parent){
  const by={}; rel.forEach(r=>{(by[r.status]=by[r.status]||[]).push(r)});
  const cnt=`已确认 ${(by.confirmed||[]).length} · 已驳回 ${(by.rejected||[]).length} · 其他待审 ${(by.new||[]).length}`;
  let h="";
  if(kind==="suggestion"){
    h+=`<div class="rec" style="margin-bottom:8px"><b>这是什么：</b>AI 的批次收尾计划。`+
      `<b>采纳</b>=该计划成为报告「复测计划」节引用的唯一最新计划；`+
      `<b>忽略</b>=报告将没有复测计划节，下次批次再出新计划可替代。</div>`;
  }
  if(kind==="test"){
    h+=`<div class="rec" style="margin-bottom:8px"><b>这是什么：</b>AI 的一条复测结论记录。`+
      `<b>采信</b>=该结论进入报告「复测记录」节，作为漏洞复现证据；`+
      `<b>不采信</b>=不进报告（误报/依据不足/无法复现/重复）。`+
      `母发现的生命周期已由结论词自动联动——这里审的是"要不要采信进报告"；漏洞记录本身的审核在发现页。</div>`;
  }
  h+=`<div class="muted" style="margin-bottom:4px"><b>备注/详情全文</b></div>`+
    `<div style="white-space:pre-wrap;margin-bottom:8px">${fmtSections(note)||"<span class='muted'>（无备注）</span>"}</div>`;
  if(kind==="test"){
    // 母发现卡：被审对象（title/severity/生命周期/人审态 + 跳发现页看报文证据）
    h+=`<div class="muted" style="margin-bottom:4px"><b>母发现</b>（这条复测结论支撑/推翻谁）</div>`;
    if(parent){
      h+=`<div class="rec"><div class="hd"><b>#${parent.id} ${esc(parent.title)}</b> `+
        `<span class="sev-dot sev-${parent.severity||"none"}"></span>${sevLabel(parent.severity)} `+
        `${lifeTag(parent.lifecycle)} ${tag(parent.status)}`+
        `<span style="flex:1"></span>`+
        `<button class="mini" onclick="gotoFinding(${parent.id})">在发现页打开</button></div>`+
        `<div class="src">报文/证据在此渲染：复测包=该发现及其全部复测的报文；证据链=截图等附件</div></div>`;
    }else{
      h+=`<div class="muted">母发现未解析（parent_ext 非数字 id 或指向非 finding 记录）——归因存疑，建议驳回或先修正归因</div>`;
    }
    // 同母发现的复测记录：替代对 test 无意义的"同值历史"（value 天生唯一）
    const sConf=sib.filter(r=>r.status==="confirmed").length;
    h+=`<div class="muted" style="margin:8px 0 4px"><b>同母发现的复测记录</b>（共 ${sib.length} 条：已确认 ${sConf}）</div>`;
    h+=sib.length?sib.slice(-6).reverse().map(r=>
        `<div class="rec"><div class="hd"><b>#${r.id}</b> ${kindTag(r.kind)} ${tag(r.status)}`+
        ` <span class="muted">${fmtTime(r.created_at)}</span></div>`+
        (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
        `<div class="src">归因: ${esc(r.parent_ext||"—")}</div></div>`).join("")
      :`<div class="muted">暂无其他复测记录（本条是该母发现下首条/唯一）</div>`;
  }else{
    h+=`<div class="muted" style="margin-bottom:4px"><b>同值历史</b>（${esc(q)} · 共 ${rel.length} 条：${cnt}）</div>`;
    h+=rel.length?rel.slice(0,8).map(r=>
        `<div class="rec"><div class="hd"><b>#${r.id}</b> ${kindTag(r.kind)} ${tag(r.status)}`+
        ` <span class="muted">${fmtTime(r.created_at)} · ${r.origin}${r.confidence?"/"+r.confidence:""}</span></div>`+
        (r.note?`<div class="muted">${esc(r.note)}</div>`:"")+
        `<div class="src">来源: ${esc(r.source)}</div></div>`).join("")+
      (rel.length>8?`<div class="muted">…其余 ${rel.length-8} 条略，完整历史见实体/详情页</div>`:"")
      :`<div class="muted">无同值历史（库内首见）</div>`;
  }
  if(kind==="suggestion"){
    // 批次计划全文已在判据卡展示，没有独立详情页——不渲染跳转块（原来跳资产页也是空）
  }else if(kind!=="test"){
    // test 的跳转入口已并进母发现卡（「在发现页打开」）——底部不再放重复按钮
    h+=`<div style="margin-top:8px"><span class="muted">报文/证据在详情页唯一渲染：</span> `+
      `<button class="mini" onclick="gotoQueueDetail(${id})">在详情页打开</button></div>`;
  }
  return h;
}
function tgGroup(g,on){
  document.querySelectorAll(`#review-table input.rv-check[data-g="${g}"]`).forEach(c=>c.checked=on);
  updBatch();
}
async function doGroup(gname,action){
  const boxes=[...document.querySelectorAll(`#review-table input.rv-check[data-g="${gname}"]`)];
  if(!boxes.length)return;
  const checked=boxes.filter(c=>c.checked);
  const use=checked.length?checked:boxes;   // 勾选感知（Gmail 模式）：组内有勾选只处理勾选项，无勾选才整组
  const ids=use.map(c=>+c.dataset.id);
  const mix=kindMix(use),d=mixDesc(mix,action);
  const scope=use.length<boxes.length?`（按勾选 ${use.length}/${boxes.length}）`:"";
  let note=$("#batch-note").value.trim();
  if(!note)note=prompt(mix.single
    ?reviewPrompt(action,mix.single)
    :`整组${d.word} ${ids.length} 条 — 批注（会记到每条记录上）：`,"")||"";
  if(!note){alert("批量操作必须留批注");return;}
  if(!confirm(mix.single
    ?`确定${d.word} ${ids.length} 条${scope}？`
    :`确定${d.word} ${ids.length} 条${scope}？（${d.parts}）`))return;
  const r=await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ids,action,note})});
  if(!r.ok){alert(await r.text());return;}
  loadAll();
}
function updBatch(){
  const sel=[...document.querySelectorAll("#review-table input.rv-check:checked")];
  const n=sel.length;
  $("#batch-n").textContent=n;
  $("#batch-bar").style.display=n?"":"none";
  const bOk=$("#batch-ok"),bNo=$("#batch-no");
  if(!bOk)return;
  // 批量条动词随所选 kind 动态换词（按钮数恒 2 不增殖）：同质勾选用专属动词，混选回退通用词
  const mix=kindMix(sel);
  if(mix.single){
    bOk.textContent=`${vOk(mix.single,"confirmed")}所选 (${n})`;
    bNo.textContent=`${vOk(mix.single,"rejected")}所选 (${n})`;
  }else{
    bOk.textContent=`确认所选 (${n})`;
    bNo.textContent=`驳回所选 (${n})`;
  }
}
async function doBatch(action){
  const sel=[...document.querySelectorAll("#review-table input.rv-check:checked")];
  if(!sel.length)return;
  const ids=sel.map(c=>+c.dataset.id);
  const note=$("#batch-note").value.trim();
  if(!note){alert("批量操作必须填批注（会记到每条记录上）");return;}
  const mix=kindMix(sel),d=mixDesc(mix,action);
  if(!confirm(mix.single
    ?`确定${d.word} ${ids.length} 条？`
    :`确定${d.word} ${ids.length} 条？（${d.parts}）`))return;
  const r=await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ids,action,note})});
  if(!r.ok){alert(await r.text());return;}
  $("#batch-note").value="";
  loadAll();
}
// 批注提示按 kind 分化（说真话：提示里写清这个动作的下游后果；动词与 VERBS 表同源）
function reviewPrompt(action,kind){
  if(kind==="test")return action==="confirmed"
    ?"批注（必填）：采信=该复测结论进入报告「复测记录」节——采信理由"
    :"批注（必填）：不采信=不进报告——原因（误报/依据不足/无法复现/重复 之一）";
  if(kind==="suggestion")return action==="confirmed"?"批注（必填）：采纳理由":"批注（必填）：忽略理由";
  return action==="confirmed"?"批注（必填）：采纳理由":"批注（必填）：驳回原因（误报/越界/无法复现/重复 之一）";
}
async function doReview(id,action,note,kind){
  if(note===undefined)note=prompt(reviewPrompt(action,kind||""))||"";
  note=(note||"").trim();
  if(!note){alert("人审必须填批注（会记到操作日志，不能空着盖章）");return;}
  await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({id,action,note})});
  loadAll();
}
