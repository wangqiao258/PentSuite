// PentDB 面板 · 时间线 + 待审队列视图：按来源分组 / 判据卡展开 / 批量判定
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
