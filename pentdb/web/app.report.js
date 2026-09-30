// PentDB 面板 · 报告·收尾视图：Lint 门禁 + Markdown 报告（本文件尾 boot() 启动应用，必须最后加载）
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
async function loadReport(){
  const tpl=$("#r-tpl").value;
  const d=await api("report",{project:PROJECT,template:tpl});
  $("#report-pre").textContent=d.report;
  $("#dl-link").download=(tpl==="pentest"?"pentest-report":"recon-report")+".md";
  $("#dl-link").href=URL.createObjectURL(new Blob([d.report],{type:"text/markdown"}));
}
function copyReport(){navigator.clipboard.writeText($("#report-pre").textContent)}
boot();
