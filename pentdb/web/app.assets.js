// PentDB 面板 · 资产明细视图：左树右表 / 实体下钻 / 手动补录区联动（#asset-tree 事件委托）
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
