// PentDB 面板 · 报告·收尾视图：Lint 门禁（只读仪表盘）+ Markdown 报告（本文件尾 boot() 启动应用，必须最后加载）
// 门禁页只看结果不做决定：豁免确认/作废、记录作废等决定统一在发现页对应记录上做（对齐 SonarQube gate 只读模式）
async function loadLint(btn){
  const t0=new Date().toLocaleTimeString();
  if(btn){btn.disabled=true;btn.textContent="检查中…";}
  try{
    const d=await api("lint",{project:PROJECT});
    const E=(d.items&&d.items.errors)||[];
    const W=(d.items&&d.items.warns)||[];
    const dw=d.draft_waives||[];
    const s=d.summary||{blocking:E.length,waive_pending:dw.length,health:W.length};
    $("#lint-sum").innerHTML=
      `<span class="tag ${s.blocking?"sev-crit":"t-confirmed"}">${s.blocking?("阻断 × "+s.blocking):"0 阻断 ✓"}</span>`+
      (s.waive_pending?` <span class="tag sev-med">豁免待确认 × ${s.waive_pending}</span>`:"")+
      (s.health?` <span class="tag sev-low">健康度 × ${s.health}</span>`:"");
    // 条目分层渲染：[code] #rid what — why ｜ 修复 ｜ 豁免提示（豁免是流程状态，不混进问题）
    const itemHtml=it=>`<div style="margin:2px 0">`+
      `<span style="color:var(--red)"><b>[${esc(it.code)}]${it.rid?" #"+it.rid:""} ${esc(it.what)}</b></span>`+
      (it.why?` <span style="color:var(--tx2)">— ${esc(it.why)}</span>`:"")+
      (it.fix?` <span style="color:var(--teal)">｜ 修复: ${esc(it.fix)}</span>`:"")+
      (it.waive?` <span style="color:var(--amber)">｜ ${esc(it.waive)}</span>`:"")+
      `</div>`;
    $("#lint-out").innerHTML=
      (E.length?`<div style="margin:6px 0 2px;font-weight:500;color:var(--tx2)">阻断（逐条修复；豁免/作废决定在发现页对应记录上做）`+
        ` <button class="mini" onclick="goFindingsWaive()">去处理 →</button></div>`+
        E.map(itemHtml).join(""):"")+
      (dw.length?`<div style="margin:6px 0 2px;font-weight:500;color:var(--tx2)">豁免待确认（确认=放行，作废=恢复阻断；均为人的决定，留痕不可逆）`+
        ` <button class="mini" onclick="goFindingsWaive()">去处理 →</button></div>`+
        dw.map(w=>`<div style="margin:2px 0;color:var(--amber)">⚠ wid=${w.id}（#${w.event_id} ${esc(w.term)}）：${esc(w.reason||"")}</div>`).join(""):"")+
      (W.length?`<div style="margin:6px 0 2px;font-weight:500;color:var(--tx2)">数据健康度（格式类提示，不阻断、不拦截报告）</div>`+
        W.map(w=>`<div style="margin:2px 0;color:var(--amber)">⚠ <b>${esc(w.code)}${w.rid?" #"+w.rid:""} ${esc(w.what)}</b> `+
          `<span style="color:var(--tx2)">— ${esc(w.why)}</span> <span style="color:var(--teal)">｜ 修复: ${esc(w.fix)}</span></div>`).join(""):"")||
      "<span style='color:var(--teal)'>全部记录通过门禁检查（溯源 / 状态 / 归因 / 证据链）</span>";
    $("#lint-at").textContent="检查于 "+t0;
  }catch(e){
    $("#lint-sum").innerHTML="";
    $("#lint-out").innerHTML=`<span style="color:var(--red)">检查失败：${esc(e.message)}</span>`;
  }finally{
    if(btn){btn.disabled=false;btn.textContent="重新检查";}
  }
}
async function loadReport(){
  const tpl=$("#r-tpl").value;
  const d=await api("report",{project:PROJECT,template:tpl});
  $("#report-pre").textContent=d.report;
  $("#dl-link").download=(tpl==="pentest"?"pentest-report":"recon-report")+".md";
  $("#dl-link").href=URL.createObjectURL(new Blob([d.report],{type:"text/markdown"}));
}
function copyReport(){navigator.clipboard.writeText($("#report-pre").textContent)}
boot();
