// PentDB 面板 · 探索·计划视图：意图血缘链 + 共享 todolist（只读仪表盘；写走 CLI intent/plan 命令）
// 门禁同款只读模式：面板看链路、CLI 做决定（add/exec --intent、plan add/next/done）
const EXPLORE_INTENT_MARK = {active:["进行中","var(--tx)"], done:["已产出","var(--teal)"], dead:["已作废","var(--tx2)"]};
const EXPLORE_PLAN_MARK = {
  blocked:["受阻","var(--amber)"], ready:["可执行","var(--red)"], doing:["执行中","var(--blue,#378ADD)"],
  done:["完成","var(--teal)"], skip:["跳过","var(--tx2)"]
};
function exTag(txt,color){return `<span class="tag" style="color:${color};border-color:${color}">${esc(txt)}</span>`}

async function loadExplore(){
  try{
    const [di,dp]=await Promise.all([
      api("intents",{project:PROJECT}),
      api("plan",{project:PROJECT}),
    ]);
    const ints=di.intents||[];
    const byId={}; ints.forEach(i=>byId[i.id]=i);
    // 意图链：根→…→叶 缩进渲染，父链一目了然（挂接数即该方向产出的观测量）
    $("#explore-intents").innerHTML=ints.length?ints.map(i=>{
      const [label,color]=EXPLORE_INTENT_MARK[i.status]||[i.status,"var(--tx2)"];
      const depth=(()=>{let d=0,cur=i,guard=0;
        while(cur&&cur.parent_id&&byId[cur.parent_id]&&guard++<10){d++;cur=byId[cur.parent_id];}
        return d;})();
      const par=i.parent_id?` <span class="muted">← 父 #${i.parent_id}</span>`:"";
      return `<div class="fitem" style="margin-left:${depth*24}px">`+
        `<b>${esc(i.goal)}</b> ${exTag(label,color)} `+
        `<span class="muted">#${i.id}${par} · ${i.created_at} · 挂接 ${i.event_n} 条观测</span>`+
        (i.hypothesis?`<div class="detail">假设：${esc(i.hypothesis)}</div>`:"")+
        (i.note&&i.status!=="active"?`<div class="muted">收尾：${esc(i.note)}</div>`:"")+
        `</div>`;
    }).join(""):"<div class='muted'>暂无意图（CLI：intent add --project P --goal '<方向>'；观测落库带 --intent N 挂血缘）</div>";
    // 计划看板：就绪/执行中在前，受阻其次，完成/跳过折叠收尾（对齐 inbox 置底折叠惯例）
    const steps=dp.steps||[];
    const open=steps.filter(s=>["ready","doing","blocked"].includes(s.status));
    const closed=steps.filter(s=>["done","skip"].includes(s.status));
    const order={ready:0,doing:1,blocked:2};
    open.sort((a,b)=>(order[a.status]-order[b.status])||(a.seq-b.seq));
    const stepHtml=s=>{
      const [label,color]=EXPLORE_PLAN_MARK[s.status]||[s.status,"var(--tx2)"];
      const deps=(s.depends_on||"").split(",").filter(x=>x.trim()).map(x=>"#"+x.trim()).join(" ");
      return `<div class="fitem">`+
        `<b>${esc(s.title)}</b> ${exTag(label,color)} `+
        `<span class="muted">#${s.id} · seq=${s.seq}${deps?" · 前置 "+deps:""}${s.intent_id?" · 意图 #"+s.intent_id:""}</span>`+
        (s.note?`<div class="muted">${esc(s.note)}</div>`:"")+
        `</div>`;
    };
    $("#explore-plan").innerHTML=
      (open.length?open.map(stepHtml).join(""):"<div class='muted'>无可执行步骤（CLI：plan next 领取；plan add 追加）</div>")+
      (closed.length?`<details style="margin-top:8px"><summary class="muted" style="cursor:pointer">已完成/跳过 ${closed.length} 步</summary>`+
        closed.map(stepHtml).join("")+"</details>":"");
  }catch(e){
    $("#explore-intents").innerHTML=`<span style="color:var(--red)">加载失败：${esc(e.message)}</span>`;
    $("#explore-plan").innerHTML="";
  }
}
