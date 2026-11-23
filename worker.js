const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json'}});
const hx=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const H=async(p,s)=>hx(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s+p)));
const rnd=()=>hx(crypto.getRandomValues(new Uint8Array(16)));
const ck=(x,y)=>x<0||y<0?[Math.min(x,y),Math.min(x,y)]:[Math.min(x,y),Math.max(x,y)];
const PUB='id,username,avatar,bio,status';
export default{async scheduled(ev,env,ctx){ctx.waitUntil(cleanup(env))},async fetch(req,env,ctx){const u=new URL(req.url);
if(req.method==='GET'&&u.pathname==='/robots.txt')return new Response('User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: '+u.origin+'/sitemap.xml\n',{headers:{'content-type':'text/plain; charset=utf-8','cache-control':'public, max-age=3600'}});
if(req.method==='GET'&&u.pathname==='/sitemap.xml'){const urls=['/','/privacy.html','/terms.html'].map(p=>'<url><loc>'+u.origin+p+'</loc></url>').join('');return new Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+urls+'</urlset>',{headers:{'content-type':'application/xml; charset=utf-8','cache-control':'public, max-age=3600'}})}
if(!u.pathname.startsWith('/api/'))return env.ASSETS.fetch(req);
try{return await api(req,env,u,ctx)}catch(e){console.error(e);return J({error:'സെർവർ പിശക്: D1 binding (DB) പരിശോധിക്കുക'},500)}}};
async function api(req,env,u,ctx){const db=env.DB,path=u.pathname.slice(5),now=Date.now(),ip=req.headers.get('cf-connecting-ip')||'-';let b={};
if(path=='stripe-webhook'&&req.method=='POST'){if(!env.STRIPE_WEBHOOK_SECRET)return J({error:'STRIPE_WEBHOOK_SECRET ഇല്ല'},503);
const raw=await req.text(),sh=(req.headers.get('stripe-signature')||'').split(','),t=(sh.find(x=>x.startsWith('t='))||'').slice(2),v1=sh.filter(x=>x.startsWith('v1=')).map(x=>x.slice(3));
const hk=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
const exp=hx(await crypto.subtle.sign('HMAC',hk,new TextEncoder().encode(t+'.'+raw)));
if(!t||Math.abs(now/1000-+t)>300||!v1.includes(exp))return J({error:'bad signature'},400);
let ev;try{ev=JSON.parse(raw)}catch{return J({error:'bad json'},400)}
if(await db.prepare('SELECT 1 x FROM stripe_events WHERE id=?').bind(ev.id).first())return J({ok:1,duplicate:1});
const o=ev.data?.object||{};
if(ev.type=='checkout.session.completed'&&o.mode=='subscription'&&+o.client_reference_id>0)await db.prepare("INSERT INTO subscriptions(uid,customer,sub_id,status,period_end,updated)VALUES(?,?,?,'active',0,?) ON CONFLICT(uid) DO UPDATE SET customer=excluded.customer,sub_id=excluded.sub_id,status='active',updated=excluded.updated").bind(+o.client_reference_id,String(o.customer||''),String(o.subscription||''),now).run();
else if(/^customer\.subscription\.(created|updated|deleted)$/.test(ev.type))await db.prepare('UPDATE subscriptions SET status=?,sub_id=?,period_end=?,updated=? WHERE customer=?').bind(ev.type.endsWith('deleted')?'canceled':String(o.status),String(o.id),(o.current_period_end||o.items?.data?.[0]?.current_period_end||0)*1000,now,String(o.customer)).run();
else if(ev.type=='invoice.payment_failed')await db.prepare("UPDATE subscriptions SET status='past_due',updated=? WHERE customer=?").bind(now,String(o.customer)).run();
await db.prepare('INSERT INTO stripe_events(id,created)VALUES(?,?)').bind(ev.id,now).run();return J({ok:1})}
if(req.method=='POST'&&req.headers.get('content-type')?.includes('application/json'))try{b=await req.json()}catch{}
if(path=='signup'||path=='login'){const n=String(b.username||'').toLowerCase(),p=String(b.password||'');
if(!/^[a-z0-9_]{3,20}$/.test(n))return J({error:'Username: 3-20 അക്ഷരം (a-z, 0-9, _)'},400);
if(p.length<6)return J({error:'Password കുറഞ്ഞത് 6 അക്ഷരം വേണം'},400);
if(path=='signup'){if(await lim(db,'su:'+ip,10,3600000,now))return J({error:'വളരെയധികം signup ശ്രമങ്ങൾ. പിന്നീട് ശ്രമിക്കുക'},429);const em=String(b.email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em))return J({error:'ശരിയായ ഇമെയിൽ നൽകുക'},400);if(await db.prepare('SELECT 1 x FROM users WHERE email=?').bind(em).first())return J({error:'ഈ ഇമെയിൽ ഉപയോഗത്തിലുണ്ട്'},409);const s=rnd();try{await db.prepare('INSERT INTO users(username,salt,pw,created,email)VALUES(?,?,?,?,?)').bind(n,s,await pbk(p,s),now,em).run()}catch{return J({error:'ഈ username എടുത്തിട്ടുണ്ട്'},409)}}
const us=await db.prepare('SELECT * FROM users WHERE username=?').bind(n).first();
const fr=await db.prepare('SELECT n,ts FROM fails WHERE k=?').bind(n).first();
if(fr&&fr.n>=5&&now-fr.ts<900000)return J({error:'വളരെയധികം ശ്രമങ്ങൾ. 15 മിനിറ്റ് കഴിഞ്ഞ് ശ്രമിക്കുക'},429);
if(!us||!await pwOk(us,p)){await db.prepare('INSERT OR REPLACE INTO fails(k,n,ts)VALUES(?,?,?)').bind(n,(fr&&now-fr.ts<900000?fr.n:0)+1,now).run();return J({error:'തെറ്റായ username / password'},401)}
await db.prepare('DELETE FROM fails WHERE k=?').bind(n).run();
if(!us.pw.startsWith('pb1:')){const s3=rnd();await db.prepare('UPDATE users SET pw=?,salt=? WHERE id=?').bind(await pbk(p,s3),s3,us.id).run()}
const t=rnd()+rnd();await db.prepare('INSERT INTO sessions(token,uid,ts)VALUES(?,?,?)').bind(t,us.id,now).run();
return J({token:t,user:{id:us.id,username:us.username,avatar:us.avatar,bio:us.bio,status:us.status}})}
if(path=='vapid')return J({key:env.VAPID_PUB||''});
if(path=='forgot'){if(await lim(db,'fg:'+ip,5,3600000,now))return J({error:'വളരെയധികം ശ്രമങ്ങൾ. പിന്നീട് ശ്രമിക്കുക'},429);if(!env.RESEND_KEY)return J({error:'ഇമെയിൽ സേവനം സജ്ജമാക്കിയിട്ടില്ല (RESEND_KEY)'},503);
const em=String(b.email||'').trim().toLowerCase();const u2=await db.prepare('SELECT id FROM users WHERE email=?').bind(em).first();
if(u2){const rr=await db.prepare('SELECT exp FROM resets WHERE uid=?').bind(u2.id).first();
if(!rr||rr.exp<now+540000){const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%900000+100000);
await db.prepare('INSERT OR REPLACE INTO resets(uid,code,exp,tries)VALUES(?,?,?,0)').bind(u2.id,await H(code,'rs'+u2.id),now+600000).run();
try{await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+env.RESEND_KEY,'content-type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM||'CHOLLU <onboarding@resend.dev>',to:[em],subject:'CHOLLU password reset code',text:'Your CHOLLU reset code: '+code+'\nValid for 10 minutes. Ignore this email if it was not you.'})})}catch{}}}
return J({ok:1})}
if(path=='reset'){const em=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');if(pw.length<6)return J({error:'Password കുറഞ്ഞത് 6 അക്ഷരം വേണം'},400);
const u2=await db.prepare('SELECT id,username FROM users WHERE email=?').bind(em).first();const rr=u2&&await db.prepare('SELECT code,exp,tries FROM resets WHERE uid=?').bind(u2.id).first();
if(!rr||rr.exp<now||rr.tries>=5)return J({error:'കോഡ് അസാധുവാണ് അല്ലെങ്കിൽ കാലാവധി കഴിഞ്ഞു'},400);
await db.prepare('UPDATE resets SET tries=tries+1 WHERE uid=?').bind(u2.id).run();
if(rr.code!=await H(String(b.code||'').trim(),'rs'+u2.id))return J({error:'തെറ്റായ കോഡ്'},400);
const s2=rnd();await db.prepare('UPDATE users SET pw=?,salt=? WHERE id=?').bind(await pbk(pw,s2),s2,u2.id).run();
await db.prepare('DELETE FROM resets WHERE uid=?').bind(u2.id).run();await db.prepare('DELETE FROM sessions WHERE uid=?').bind(u2.id).run();await db.prepare('DELETE FROM fails WHERE k=?').bind(u2.username).run();return J({ok:1})}
if(path=='download-file'&&req.method=='GET'){const token=u.searchParams.get('token')||'';const t=await db.prepare('SELECT uid,upload_id,exp FROM download_tokens WHERE token=?').bind(token).first();if(!t||t.exp<now)return J({error:'Download link കാലാവധി കഴിഞ്ഞു'},401);await db.prepare('DELETE FROM download_tokens WHERE token=?').bind(token).run();const f=await db.prepare("SELECT * FROM uploads WHERE id=? AND status='ready'").bind(t.upload_id).first();if(!f)return J({error:'ഫയൽ ലഭ്യമല്ല'},404);const obj=await env.BUCKET.get(f.object_key);if(!obj)return J({error:'ഫയൽ ഇല്ല'},404);const headers=new Headers();obj.writeHttpMetadata(headers);headers.set('content-disposition',`attachment; filename*=UTF-8''${encodeURIComponent(f.filename)}`);headers.set('cache-control','private, no-store');headers.set('content-length',String(f.size));headers.set('x-content-type-options','nosniff');return new Response(obj.body,{headers})}
if(path=='media'&&req.method=='GET'){const m=await db.prepare('SELECT * FROM media WHERE id=?').bind(u.searchParams.get('id')||'').first();if(!m||!env.BUCKET)return J({error:'x'},404);
const rg=req.headers.get('range'),o=await env.BUCKET.get(m.object_key,rg?{range:req.headers}:{});if(!o)return J({error:'x'},404);
const h=new Headers({'content-type':m.type,'x-content-type-options':'nosniff','cache-control':'private, max-age=3600','accept-ranges':'bytes','content-disposition':'inline','content-security-policy':"default-src 'none'"});
if(rg&&o.range){const off=o.range.offset??0,ln=o.range.length??m.size-off;h.set('content-range','bytes '+off+'-'+(off+ln-1)+'/'+m.size);h.set('content-length',String(ln));return new Response(o.body,{status:206,headers:h})}
h.set('content-length',String(m.size));return new Response(o.body,{headers:h})}
const tk=(req.headers.get('authorization')||'').slice(7);
const s=await db.prepare('SELECT uid FROM sessions WHERE token=? AND ts>?').bind(tk,now-2592000000).first();if(!s)return J({error:'auth'},401);
const me=s.uid;const AID=await aiUser(db);await db.prepare('UPDATE users SET seen=? WHERE id=?').bind(now,me).run();
if(path=='logout'){await db.prepare('DELETE FROM sessions WHERE token=?').bind(tk).run();return J({ok:1})}
if(path=='logout-all'){await db.prepare('DELETE FROM sessions WHERE uid=? AND token!=?').bind(me,tk).run();return J({ok:1})}
if(path=='premium-status'){const r=await db.prepare('SELECT status,period_end FROM subscriptions WHERE uid=?').bind(me).first();return J({premium:!!r&&['active','trialing'].includes(r.status),status:r?.status||'none',period_end:r?.period_end||0})}
if(path=='premium-portal'){if(!env.STRIPE_SECRET_KEY)return J({error:'Stripe key ഇല്ല'},503);const r=await db.prepare('SELECT customer FROM subscriptions WHERE uid=?').bind(me).first();if(!r?.customer)return J({error:'Subscription ഇല്ല'},404);
const o=await(await fetch('https://api.stripe.com/v1/billing_portal/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_SECRET_KEY,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({customer:r.customer,return_url:u.origin+'/premium.html'})})).json();return o.url?J({url:o.url}):J({error:'Payment provider error'},502)}
if(path=='media-upload'&&req.method=='POST'){if(!env.BUCKET)return J({error:'R2 binding ഇല്ല'},503);
const ty=(req.headers.get('content-type')||'').split(';')[0].trim().toLowerCase(),kind=u.searchParams.get('kind'),IMG=['image/jpeg','image/png','image/webp','image/gif'],VID=['video/mp4','video/webm','video/quicktime'];
if(!(IMG.includes(ty)||VID.includes(ty))||(kind=='reel'&&!VID.includes(ty)))return J({error:'ഈ ഫയൽ തരം അനുവദനീയമല്ല'},400);
const max=IMG.includes(ty)?10485760:94371840,len=+req.headers.get('content-length')||0;if(len<1||len>max)return J({error:'ഫോട്ടോ 10MB, വീഡിയോ 90MB വരെ'},413);
const used=(await db.prepare('SELECT COALESCE(SUM(size),0) n FROM media WHERE owner=?').bind(me).first()).n;if(used+len>524288000)return J({error:'Storage quota (500MB) കഴിഞ്ഞു'},413);
const id=rnd(),key='media/'+me+'/'+id;await env.BUCKET.put(key,req.body,{httpMetadata:{contentType:ty}});const hd=await env.BUCKET.head(key);
if(!hd||hd.size<1||hd.size>max){await env.BUCKET.delete(key);return J({error:'ഫയൽ വലുപ്പം അസാധുവാണ്'},413)}
await db.prepare('INSERT INTO media(id,owner,object_key,type,size,created)VALUES(?,?,?,?,?,?)').bind(id,me,key,ty,hd.size,now).run();return J({media_id:id})}
if(path=='users'){const q=(u.searchParams.get('q')||'').replace(/[%_\\]/g,'\\$&');
return J({users:(await db.prepare(`SELECT ${PUB} FROM users WHERE username LIKE ? ESCAPE '\\' AND id!=? LIMIT 20`).bind('%'+q.toLowerCase()+'%',me).all()).results})}
if(path=='chats'){const r=await db.prepare(`SELECT u.id,u.username,u.avatar,u.bio,u.status,u.seen,m.kind,m.ts,CASE WHEN m.kind='text' AND m.deleted=0 THEN m.body ELSE '' END body,(SELECT COUNT(*) FROM messages WHERE from_id=u.id AND to_id=?1 AND rd=0 AND deleted=0 AND (exp=0 OR exp>${now})) unread FROM users u JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE ((from_id=u.id AND to_id=?1) OR (from_id=?1 AND to_id=u.id)) AND (exp=0 OR exp>${now})) WHERE u.id!=?1 ORDER BY m.id DESC`).bind(me).all();const cs=r.results;cs.push(...(await db.prepare(`SELECT -g.id id,g.name username,'👥' avatar,'' bio,'' status,0 seen,1 grp,m.kind,COALESCE(m.ts,0) ts,CASE WHEN m.kind='text' AND m.deleted=0 THEN m.body ELSE '' END body,(SELECT COUNT(*) FROM messages WHERE to_id=-g.id AND id>gm.lr AND from_id!=?1 AND deleted=0 AND (exp=0 OR exp>${now})) unread FROM grps g JOIN gmembers gm ON gm.gid=g.id AND gm.uid=?1 LEFT JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE to_id=-g.id AND (exp=0 OR exp>${now}))`).bind(me).all()).results);if(me!=AID&&!cs.find(c=>c.id==AID))cs.push({id:AID,username:'chollu_ai',avatar:'🤖',bio:'',status:'ചോദിക്കൂ, ഞാൻ ഉത്തരം തരാം',seen:0,kind:'text',ts:0,body:'',unread:0});return J({chats:cs.sort((a,b)=>(b.ts||0)-(a.ts||0))})}
if(path=='messages'){const w=+u.searchParams.get('with'),a=+u.searchParams.get('after')||0;
const q=w<0?'(to_id=?2 AND ?1>0)':'((from_id=?1 AND to_id=?2) OR (from_id=?2 AND to_id=?1))';
if(w<0&&!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-w,me).first())return J({error:'x'},403);
if(w<0)await db.prepare('UPDATE gmembers SET lr=(SELECT COALESCE(MAX(id),0) FROM messages WHERE to_id=?1) WHERE gid=?2 AND uid=?3').bind(w,-w,me).run();
await db.prepare('UPDATE messages SET rd=1 WHERE from_id=? AND to_id=? AND rd=0').bind(w,me).run();
await db.prepare('DELETE FROM messages WHERE exp>0 AND exp<?').bind(now).run();
const m=(await db.prepare(`SELECT * FROM (SELECT id,from_id,kind,body,reply_to,ts,deleted,exp FROM messages WHERE ${q} AND id>?3 AND (exp=0 OR exp>?4) ORDER BY id DESC LIMIT 60) ORDER BY id`).bind(me,w,a,now).all()).results;
const del=(await db.prepare(`SELECT id FROM messages WHERE ${q} AND deleted=1 ORDER BY id DESC LIMIT 200`).bind(me,w).all()).results.map(x=>x.id);
const re=(await db.prepare(`SELECT r.msg_id,r.emoji FROM reactions r JOIN messages m ON m.id=r.msg_id WHERE ${q} LIMIT 500`).bind(me,w).all()).results;
const sn=await db.prepare('SELECT MAX(id) x FROM messages WHERE from_id=? AND to_id=? AND rd=1').bind(me,w).first();
const p=await db.prepare('SELECT seen,typ_to,typ_at FROM users WHERE id=?').bind(w).first()||{};
return J({names:w<0?Object.fromEntries((await db.prepare('SELECT u.id,u.username FROM users u JOIN gmembers g ON g.uid=u.id WHERE g.gid=?').bind(-w).all()).results.map(x=>[x.id,x.username])):{},m,del,re,ed:(await db.prepare(`SELECT id,body FROM messages WHERE ${q} AND edited=1 AND deleted=0 ORDER BY id DESC LIMIT 100`).bind(me,w).all()).results,ttl:(await db.prepare('SELECT ttl FROM chat_cfg WHERE a=? AND b=?').bind(...ck(me,w)).first())?.ttl||0,seen:sn?.x||0,peer:{online:now-p.seen<30000,typing:p.typ_to==me&&now-p.typ_at<4000}})}
if(path=='send'){const to=+b.to,kind=b.kind,body=String(b.body||'');
if(!['text','sticker','image','video','audio','file'].includes(kind)||!body||body.length>1000000)return J({error:'അസാധുവായ സന്ദേശം'},400);
if(to<0?!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-to,me).first():!await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())return J({error:'user ഇല്ല'},404);
if(to>0&&await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(to,me,me,to).first())return J({error:'ഈ chat-ൽ സന്ദേശം അയയ്ക്കാൻ കഴിയില്ല (Block)'},403);
const tl=(await db.prepare('SELECT ttl FROM chat_cfg WHERE a=? AND b=?').bind(...ck(me,to)).first())?.ttl||0;
const r=await db.prepare('INSERT INTO messages(from_id,to_id,kind,body,reply_to,ts,exp)VALUES(?,?,?,?,?,?,?)').bind(me,to,kind,body,+b.reply_to||0,now,tl?now+tl*1000:0).run();
const mid=r.meta.last_row_id;if(to!=AID)ctx?.waitUntil(pushTo(env,db,to>0?[to]:(await db.prepare('SELECT uid FROM gmembers WHERE gid=? AND uid!=?').bind(-to,me).all()).results.map(x=>x.uid)));
if(to==AID&&kind=='text'){let rep;try{const h=(await db.prepare("SELECT from_id,body FROM messages WHERE kind='text' AND deleted=0 AND body!='' AND ((from_id=?1 AND to_id=?2) OR (from_id=?2 AND to_id=?1)) ORDER BY id DESC LIMIT 10").bind(me,AID).all()).results.reverse();
const o=await env.AI.run('@cf/meta/llama-3.1-8b-instruct',{max_tokens:400,messages:[{role:'system',content:'You are CHOLLU AI, a friendly assistant inside the CHOLLU chat app. Always reply in the same language the user writes (Malayalam or English). Keep answers short and helpful.'},...h.map(x=>({role:x.from_id==me?'user':'assistant',content:x.body}))]});rep=o.response}catch{rep='AI ഇപ്പോൾ ലഭ്യമല്ല. Pages → Settings → Bindings → Workers AI (variable name: AI) ചേർത്ത് Redeploy ചെയ്യുക.'}
const n2=Date.now();await db.prepare('INSERT INTO messages(from_id,to_id,kind,body,ts,exp)VALUES(?,?,?,?,?,?)').bind(AID,me,'text',String(rep||'…').slice(0,4000),n2,tl?n2+tl*1000:0).run()}
return J({id:mid})}
if(path=='typing'){await db.prepare('UPDATE users SET typ_to=?,typ_at=? WHERE id=?').bind(+b.to,now,me).run();return J({ok:1})}
if(path=='react'){const id=+b.id,e=String(b.emoji).slice(0,8);
if(!await db.prepare('SELECT id FROM messages WHERE id=? AND (from_id=? OR to_id=? OR to_id IN (SELECT -gid FROM gmembers WHERE uid=?))').bind(id,me,me,me).first())return J({error:'x'},404);
const ex=await db.prepare('SELECT emoji FROM reactions WHERE msg_id=? AND uid=?').bind(id,me).first();
if(ex&&ex.emoji==e)await db.prepare('DELETE FROM reactions WHERE msg_id=? AND uid=?').bind(id,me).run();
else await db.prepare('INSERT OR REPLACE INTO reactions(msg_id,uid,emoji)VALUES(?,?,?)').bind(id,me,e).run();return J({ok:1})}
if(path=='edit'){const t=String(b.body||'').trim();if(!t||t.length>5000)return J({error:'x'},400);await db.prepare("UPDATE messages SET body=?,edited=1 WHERE id=? AND from_id=? AND kind='text' AND deleted=0").bind(t,+b.id,me).run();return J({ok:1})}
if(path=='delete'){const dm=await db.prepare('SELECT body FROM messages WHERE id=? AND from_id=?').bind(+b.id,me).first();
if(dm?.body?.startsWith('r2file:')){const fid=dm.body.slice(7),up=await db.prepare("SELECT object_key FROM uploads WHERE id=? AND owner=? AND status='ready'").bind(fid,me).first();if(up&&env.BUCKET){await env.BUCKET.delete(up.object_key);await db.prepare("UPDATE uploads SET status='deleted' WHERE id=?").bind(fid).run()}}
await db.prepare("UPDATE messages SET deleted=1,body='' WHERE id=? AND from_id=?").bind(+b.id,me).run();return J({ok:1})}
if(path=='disappear'){const w=+b.with,t=+b.ttl;if(![0,60,3600,86400,604800].includes(t))return J({error:'x'},400);
await db.prepare('INSERT OR REPLACE INTO chat_cfg(a,b,ttl)VALUES(?,?,?)').bind(...ck(me,w),t).run();return J({ok:1})}
if(path=='block'){if(b.all)await db.prepare('DELETE FROM blocks WHERE a=?').bind(me).run();else if(b.on)await db.prepare('INSERT OR IGNORE INTO blocks(a,b)VALUES(?,?)').bind(me,+b.id).run();else await db.prepare('DELETE FROM blocks WHERE a=? AND b=?').bind(me,+b.id).run();return J({ok:1})}
if(path=='report'){await db.prepare('INSERT INTO reports(by_id,target,reason,ts)VALUES(?,?,?,?)').bind(me,+b.id,String(b.reason||'').slice(0,300),now).run();return J({ok:1})}
if(path=='gcreate'){const nm=String(b.name||'').trim().slice(0,40);if(!nm)return J({error:'ഗ്രൂപ്പിന് പേര് വേണം'},400);
const r=await db.prepare('INSERT INTO grps(name,owner,created)VALUES(?,?,?)').bind(nm,me,now).run();const g=r.meta.last_row_id;const ids=new Set([me]);
for(const n of(b.members||[]).slice(0,49)){const x=await db.prepare('SELECT id FROM users WHERE username=?').bind(String(n).trim().toLowerCase()).first();if(x&&x.id!=AID)ids.add(x.id)}
for(const i of ids)await db.prepare('INSERT OR IGNORE INTO gmembers(gid,uid,lr)VALUES(?,?,0)').bind(g,i).run();return J({id:-g,count:ids.size})}
if(path=='pushsub'){const ep=String(b.endpoint||'');if(!/^https:\/\//.test(ep)||ep.length>1000)return J({error:'x'},400);await db.prepare('INSERT OR REPLACE INTO push_subs(uid,endpoint,ts)VALUES(?,?,?)').bind(me,ep,now).run();return J({ok:1})}
if(path=='ice'){const ic=[{urls:'stun:stun.l.google.com:19302'}];if(env.TURN_URL)ic.push({urls:env.TURN_URL.split(','),username:env.TURN_USER,credential:env.TURN_CRED});return J({iceServers:ic})}
if(path=='sig'){const to=+b.to,k=String(b.kind);if(!['invite','accept','offer','answer','ice','end'].includes(k))return J({error:'x'},400);
if(to==AID||!await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())return J({error:'x'},404);
if(await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(to,me,me,to).first())return J({error:'x'},403);
await db.prepare('INSERT INTO sigs(from_id,to_id,kind,data,ts)VALUES(?,?,?,?,?)').bind(me,to,k,String(b.data||'{}').slice(0,20000),now).run();
if(k=='invite')ctx?.waitUntil(pushTo(env,db,[to]));return J({ok:1})}
if(path=='sigpoll'){const a=+u.searchParams.get('after')||0;await db.prepare('DELETE FROM sigs WHERE ts<?').bind(now-120000).run();
return J({s:(await db.prepare('SELECT s.id,s.from_id,s.kind,s.data,s.ts,u.username FROM sigs s JOIN users u ON u.id=s.from_id WHERE s.to_id=? AND s.id>? AND s.ts>? ORDER BY s.id').bind(me,a,now-30000).all()).results})}
if(path=='gadd'){const g=-(+b.id);if(!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(g,me).first())return J({error:'x'},403);let n=0;
for(const nm of(b.members||[]).slice(0,49)){const x=await db.prepare('SELECT id FROM users WHERE username=?').bind(String(nm).trim().toLowerCase()).first();if(x&&x.id!=AID){await db.prepare('INSERT OR IGNORE INTO gmembers(gid,uid,lr)VALUES(?,?,(SELECT COALESCE(MAX(id),0) FROM messages WHERE to_id=?))').bind(g,x.id,-g).run();n++}}return J({added:n})}
if(path=='gleave'){await db.prepare('DELETE FROM gmembers WHERE gid=? AND uid=?').bind(-(+b.id),me).run();return J({ok:1})}
if(path=='upload-start'){
 if(!env.BUCKET)return J({error:'Cloudflare R2 binding BUCKET സജ്ജമാക്കുക'},503);
 const size=Number(b.size),to=Number(b.to),name=String(b.name||'file').replace(/[\\/\\\\\x00-\x1f]/g,'_').slice(0,180),type=String(b.type||'application/octet-stream').slice(0,120);
 if(!Number.isSafeInteger(size)||size<1||size>4*1024*1024*1024)return J({error:'ഫയൽ പരമാവധി 4GB ആയിരിക്കണം'},400);
 if(to<0&&!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-to,me).first())return J({error:'ഗ്രൂപ്പ് അംഗത്വം ആവശ്യമാണ്'},403);
 if(to>0&&to!==me&&!await db.prepare('SELECT 1 x FROM users WHERE id=?').bind(to).first())return J({error:'ചാറ്റ് കണ്ടെത്തിയില്ല'},404);
 const id=rnd(),key='uploads/'+me+'/'+id+'/'+name;
 const mp=await env.BUCKET.createMultipartUpload(key,{httpMetadata:{contentType:type}});
 await db.prepare('INSERT INTO uploads(id,owner,chat_id,object_key,upload_id,filename,content_type,size,status,created) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(id,me,to,key,mp.uploadId,name,type,size,'pending',now).run();
 return J({id,uploadId:mp.uploadId,key,partSize:8*1024*1024,parts:Math.ceil(size/(8*1024*1024))});
}
if(path=='upload-part'){
 if(!env.BUCKET)return J({error:'R2 binding ഇല്ല'},503);
 const id=u.searchParams.get('id'),part=Number(u.searchParams.get('part'));
 const up=await db.prepare("SELECT * FROM uploads WHERE id=? AND owner=? AND status='pending'").bind(id,me).first();
 if(!up||!Number.isInteger(part)||part<1||part>512)return J({error:'Upload session അസാധുവാണ്'},400);
 const data=await req.arrayBuffer();if(!data.byteLength||data.byteLength>8*1024*1024)return J({error:'ഓരോ ഭാഗവും 8MB വരെ മാത്രം'},400);
 const obj=env.BUCKET.resumeMultipartUpload(up.object_key,up.upload_id);const r=await obj.uploadPart(part,data);
 return J({partNumber:part,etag:r.etag});
}
if(path=='upload-complete'){
 if(!env.BUCKET)return J({error:'R2 binding ഇല്ല'},503);
 const up=await db.prepare("SELECT * FROM uploads WHERE id=? AND owner=? AND status='pending'").bind(String(b.id),me).first();if(!up)return J({error:'Upload session ഇല്ല'},404);
 const parts=Array.isArray(b.parts)?b.parts:[];const expected=Math.ceil(up.size/(8*1024*1024));
 if(!parts.length||parts.length!==expected||parts.some((x,i)=>Number(x.partNumber)!==i+1||!x.etag))return J({error:'എല്ലാ upload ഭാഗങ്ങളും വേണം'},400);
 const obj=env.BUCKET.resumeMultipartUpload(up.object_key,up.upload_id);await obj.complete(parts.map(x=>({partNumber:Number(x.partNumber),etag:String(x.etag)})));
 await db.prepare("UPDATE uploads SET status='ready',upload_id=NULL WHERE id=?").bind(up.id).run();
 return J({id:up.id,name:up.filename,size:up.size,type:up.content_type});
}
if(path=='upload-abort'){
 const up=await db.prepare("SELECT * FROM uploads WHERE id=? AND owner=? AND status='pending'").bind(String(b.id),me).first();if(up&&env.BUCKET){await env.BUCKET.resumeMultipartUpload(up.object_key,up.upload_id).abort();await db.prepare("UPDATE uploads SET status='aborted' WHERE id=?").bind(up.id).run()}return J({ok:1});
}
if(path=='upload-send'){
 const up=await db.prepare("SELECT * FROM uploads WHERE id=? AND owner=? AND status='ready'").bind(String(b.id),me).first();if(!up)return J({error:'ഫയൽ തയ്യാറായിട്ടില്ല'},404);
 const to=up.chat_id;if(to>0&&await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(to,me,me,to).first())return J({error:'Block'},403);if(to<0&&!await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-to,me).first())return J({error:'അംഗത്വം ഇല്ല'},403);
 const body='r2file:'+up.id;const r=await db.prepare('INSERT INTO messages(from_id,to_id,kind,body,ts)VALUES(?,?,?,?,?)').bind(me,to,'file',body,now).run();
 return J({id:r.meta.last_row_id});
}
if(path=='download'){
 if(!env.BUCKET)return J({error:'R2 binding ഇല്ല'},503);const id=u.searchParams.get('id');const f=await db.prepare("SELECT * FROM uploads WHERE id=? AND status='ready'").bind(id).first();if(!f)return J({error:'ഫയൽ ലഭ്യമല്ല'},404);
 const allowed=f.owner===me||(f.chat_id>0&&f.chat_id===me)||(f.chat_id<0&&await db.prepare('SELECT 1 x FROM gmembers WHERE gid=? AND uid=?').bind(-f.chat_id,me).first());if(!allowed)return J({error:'അനുമതിയില്ല'},403);
 const token=rnd()+rnd();await db.prepare('INSERT INTO download_tokens(token,uid,upload_id,exp)VALUES(?,?,?,?)').bind(token,me,id,now+600000).run();return J({url:'/api/download-file?token='+token,expires:now+600000});
}
if(path=='stories-create'){
 const media=await mediaUrl(db,me,b,'story');if(!/^(https:\/\/|\/api\/media\?id=)/.test(media)&&!/^data:image\//.test(media))return J({error:'Story media URL ആവശ്യമാണ്'},400);
 if(media.length>1500000)return J({error:'Story media വളരെ വലുതാണ്'},400);const caption=String(b.caption||'').slice(0,300);const r=await db.prepare('INSERT INTO stories(uid,media_url,caption,created,expires,audience)VALUES(?,?,?,?,?,?)').bind(me,media,caption,now,now+86400000,b.audience=='contacts'?'contacts':'everyone').run();return J({id:r.meta.last_row_id});
}
if(path=='stories'){
 await dropExpired(env,db,now);const rows=(await db.prepare('SELECT s.id,s.uid,s.media_url,s.caption,s.created,s.expires,u.username,u.avatar,(SELECT type FROM media WHERE id=substr(s.media_url,15)) mt,CASE WHEN s.uid=?1 THEN (SELECT COUNT(*) FROM story_views v WHERE v.story_id=s.id) END vc FROM stories s JOIN users u ON u.id=s.uid WHERE (s.audience=\'everyone\' OR s.uid=?1 OR EXISTS(SELECT 1 FROM messages m WHERE (m.from_id=s.uid AND m.to_id=?1) OR (m.from_id=?1 AND m.to_id=s.uid))) AND NOT EXISTS(SELECT 1 FROM blocks bl WHERE (bl.a=s.uid AND bl.b=?1) OR (bl.a=?1 AND bl.b=s.uid)) ORDER BY s.created DESC LIMIT 100').bind(me).all()).results;return J({stories:rows});
}
if(path=='story-delete'){{const s_=await db.prepare('SELECT media_url FROM stories WHERE id=? AND uid=?').bind(+b.id,me).first();if(s_)await dropMedia(env,db,s_.media_url)}await db.prepare('DELETE FROM stories WHERE id=? AND uid=?').bind(+b.id,me).run();return J({ok:1});}
if(path=='reel-create'){
 const media=await mediaUrl(db,me,b,'reel');if(!/^(https:\/\/|\/api\/media\?id=)/.test(media)&&!/^data:video\//.test(media))return J({error:'Reel video URL ആവശ്യമാണ്'},400);if(media.length>1500000)return J({error:'Reel വളരെ വലുതാണ്'},400);const r=await db.prepare('INSERT INTO reels(uid,media_url,caption,created)VALUES(?,?,?,?)').bind(me,media,String(b.caption||'').slice(0,500),now).run();return J({id:r.meta.last_row_id});
}
if(path=='reels'){const rows=(await db.prepare('SELECT r.id,r.uid,r.media_url,r.caption,r.created,r.likes,u.username,u.avatar,(SELECT type FROM media WHERE id=substr(r.media_url,15)) mt,(SELECT COUNT(*) FROM reel_comments c WHERE c.reel_id=r.id) cc,EXISTS(SELECT 1 FROM reel_likes l WHERE l.reel_id=r.id AND l.uid=?) liked FROM reels r JOIN users u ON u.id=r.uid WHERE NOT EXISTS(SELECT 1 FROM blocks bl WHERE (bl.a=r.uid AND bl.b=?) OR (bl.a=? AND bl.b=r.uid)) ORDER BY r.created DESC LIMIT 100').bind(me,me,me).all()).results;return J({reels:rows});}
if(path=='reel-like'){const id=+b.id,ex=await db.prepare('SELECT 1 x FROM reel_likes WHERE reel_id=? AND uid=?').bind(id,me).first();if(ex){await db.prepare('DELETE FROM reel_likes WHERE reel_id=? AND uid=?').bind(id,me).run();await db.prepare('UPDATE reels SET likes=MAX(0,likes-1) WHERE id=?').bind(id).run()}else{await db.prepare('INSERT OR IGNORE INTO reel_likes(reel_id,uid)VALUES(?,?)').bind(id,me).run();await db.prepare('UPDATE reels SET likes=likes+1 WHERE id=?').bind(id).run()}return J({ok:1});}
if(path=='device-register'){
 const id=String(b.device_id||'').slice(0,100),pub=String(b.public_key||'').slice(0,3000),label=String(b.label||'').slice(0,80);if(!/^[a-zA-Z0-9_-]{8,100}$/.test(id))return J({error:'Device ID അസാധുവാണ്'},400);await db.prepare('INSERT INTO device_keys(uid,device_id,label,public_key,created,last_seen)VALUES(?,?,?,?,?,?) ON CONFLICT(uid,device_id) DO UPDATE SET label=excluded.label,public_key=excluded.public_key,last_seen=excluded.last_seen').bind(me,id,label,pub,now,now).run();return J({ok:1});
}
if(path=='devices'){const rows=(await db.prepare('SELECT device_id,label,created,last_seen FROM device_keys WHERE uid=? ORDER BY last_seen DESC').bind(me).all()).results;return J({devices:rows});}
if(path=='device-revoke'){await db.prepare('DELETE FROM device_keys WHERE uid=? AND device_id=?').bind(me,String(b.device_id)).run();return J({ok:1});}
if(path=='e2ee-publish'){const key=String(b.public_key||'');if(key.length<40||key.length>3000)return J({error:'Public key അസാധുവാണ്'},400);await db.prepare('INSERT INTO e2ee_keys(uid,public_key,updated)VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET public_key=excluded.public_key,updated=excluded.updated').bind(me,key,now).run();return J({ok:1});}
if(path=='e2ee-key'){const id=+u.searchParams.get('uid');const row=await db.prepare('SELECT public_key FROM e2ee_keys WHERE uid=?').bind(id).first();return J({public_key:row?.public_key||null});}
if(path=='reel-comment'){const id=+b.id,t=String(b.body||'').trim();if(!t||t.length>500)return J({error:'Comment 1-500 അക്ഷരം'},400);
const rl=await db.prepare('SELECT uid FROM reels WHERE id=?').bind(id).first();if(!rl)return J({error:'ഇല്ല'},404);
if(await db.prepare('SELECT 1 x FROM blocks WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(rl.uid,me,me,rl.uid).first())return J({error:'Comment ചെയ്യാൻ കഴിയില്ല (Block)'},403);
if(await lim(db,'rc:'+me,30,3600000,now))return J({error:'വളരെയധികം comments'},429);
const r=await db.prepare('INSERT INTO reel_comments(reel_id,uid,body,created)VALUES(?,?,?,?)').bind(id,me,t,now).run();return J({id:r.meta.last_row_id})}
if(path=='reel-comments'){const id=+u.searchParams.get('id');return J({comments:(await db.prepare('SELECT c.id,c.uid,c.body,c.created,u.username,u.avatar FROM reel_comments c JOIN users u ON u.id=c.uid JOIN reels r ON r.id=c.reel_id WHERE c.reel_id=?1 AND NOT EXISTS(SELECT 1 FROM blocks bl WHERE (bl.a=?2 AND bl.b=c.uid) OR (bl.a=c.uid AND bl.b=?2)) ORDER BY c.id DESC LIMIT 100').bind(id,me).all()).results})}
if(path=='reel-comment-delete'){await db.prepare('DELETE FROM reel_comments WHERE id=?1 AND (uid=?2 OR reel_id IN (SELECT id FROM reels WHERE uid=?2))').bind(+b.id,me).run();return J({ok:1})}
if(path=='story-view'){await db.prepare("INSERT OR IGNORE INTO story_views(story_id,uid,ts) SELECT s.id,?2,?3 FROM stories s WHERE s.id=?1 AND s.uid!=?2 AND (s.audience='everyone' OR EXISTS(SELECT 1 FROM messages m WHERE (m.from_id=s.uid AND m.to_id=?2) OR (m.from_id=?2 AND m.to_id=s.uid))) AND NOT EXISTS(SELECT 1 FROM blocks bl WHERE (bl.a=s.uid AND bl.b=?2) OR (bl.a=?2 AND bl.b=s.uid))").bind(+b.id,me,now).run();return J({ok:1})}
if(path=='content-report'){const kind=b.kind=='reel'?'reel':'story',id=+b.id;if(await lim(db,'cr:'+me,20,86400000,now))return J({error:'വളരെയധികം reports'},429);
if(!await db.prepare('SELECT 1 x FROM '+(kind=='reel'?'reels':'stories')+' WHERE id=?').bind(id).first())return J({error:'ഇല്ല'},404);
await db.prepare('INSERT OR IGNORE INTO content_reports(by_id,kind,item_id,reason,ts)VALUES(?,?,?,?,?)').bind(me,kind,id,String(b.reason||'').slice(0,300),now).run();return J({ok:1})}
if(path=='reel-delete'){const r_=await db.prepare('SELECT media_url FROM reels WHERE id=? AND uid=?').bind(+b.id,me).first();if(r_){await dropMedia(env,db,r_.media_url);await db.prepare('DELETE FROM reels WHERE id=?').bind(+b.id).run();await db.prepare('DELETE FROM reel_likes WHERE reel_id=?').bind(+b.id).run()}return J({ok:1})}
if(path=='admin-content-action'){if(!String(env.ADMIN_USER_IDS||'').split(',').map(x=>x.trim()).includes(String(me)))return J({error:'Admin അനുമതി ഇല്ല'},403);
const cr=await db.prepare('SELECT * FROM content_reports WHERE id=?').bind(+b.id).first();if(!cr)return J({error:'ഇല്ല'},404);
if(b.action=='remove'){const t=cr.kind=='reel'?'reels':'stories',it=await db.prepare('SELECT media_url FROM '+t+' WHERE id=?').bind(cr.item_id).first();if(it)await dropMedia(env,db,it.media_url);
await db.prepare('DELETE FROM '+t+' WHERE id=?').bind(cr.item_id).run();if(cr.kind=='reel')await db.prepare('DELETE FROM reel_likes WHERE reel_id=?').bind(cr.item_id).run();await db.prepare('DELETE FROM content_reports WHERE kind=? AND item_id=?').bind(cr.kind,cr.item_id).run()}
else await db.prepare('DELETE FROM content_reports WHERE id=?').bind(cr.id).run();
await db.prepare('INSERT INTO admin_audit(admin_id,action,details,created)VALUES(?,?,?,?)').bind(me,'content-'+(b.action=='remove'?'remove':'dismiss'),cr.kind+':'+cr.item_id,now).run();return J({ok:1})}
if(path=='admin'){
 const admins=String(env.ADMIN_USER_IDS||'').split(',').map(x=>x.trim()).filter(Boolean);if(!admins.includes(String(me)))return J({error:'Admin அனുമതി ഇല്ല'},403);
 const users=await db.prepare('SELECT COUNT(*) n FROM users').first(),msgs=await db.prepare('SELECT COUNT(*) n FROM messages').first(),reports=(await db.prepare('SELECT r.id,r.by_id,r.target,r.reason,r.ts,u.username FROM reports r LEFT JOIN users u ON u.id=r.by_id ORDER BY r.ts DESC LIMIT 100').all()).results;return J({stats:{users:users.n,messages:msgs.n},reports,content_reports:(await db.prepare("SELECT cr.id,cr.kind,cr.item_id,cr.reason,cr.ts,COALESCE(s.media_url,r.media_url) media_url,COALESCE(s.caption,r.caption) caption,COALESCE(s.uid,r.uid) owner FROM content_reports cr LEFT JOIN stories s ON cr.kind='story' AND s.id=cr.item_id LEFT JOIN reels r ON cr.kind='reel' AND r.id=cr.item_id ORDER BY cr.ts DESC LIMIT 100").all()).results});
}
if(path=='admin-report-action'){
 const admins=String(env.ADMIN_USER_IDS||'').split(',').map(x=>x.trim()).filter(Boolean);if(!admins.includes(String(me)))return J({error:'Admin അനുമതി ഇല്ല'},403);await db.prepare('DELETE FROM reports WHERE id=?').bind(+b.id).run();await db.prepare('INSERT INTO admin_audit(admin_id,action,details,created)VALUES(?,?,?,?)').bind(me,'dismiss-report',String(b.id),now).run();return J({ok:1});
}
if(path=='premium-checkout'){
 if(!env.STRIPE_SECRET_KEY||!env.STRIPE_PRICE_ID)return J({error:'Premium payment activate ചെയ്യാൻ Stripe key, price ID വേണം'},503);
 {const ex=await db.prepare('SELECT status FROM subscriptions WHERE uid=?').bind(me).first();if(ex&&['active','trialing','past_due'].includes(ex.status))return J({error:'ഇതിനകം Premium ഉണ്ട്'},409)}
 const form=new URLSearchParams({mode:'subscription','line_items[0][price]':env.STRIPE_PRICE_ID,'line_items[0][quantity]':'1','success_url':u.origin+'/?premium=success','cancel_url':u.origin+'/?premium=cancel','client_reference_id':String(me)});const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{authorization:'Bearer '+env.STRIPE_SECRET_KEY,'content-type':'application/x-www-form-urlencoded'},body:form});const out=await r.json();if(!r.ok)return J({error:'Payment provider error'},502);return J({url:out.url});
}
if(path=='profile'){await db.prepare('UPDATE users SET avatar=?,bio=?,status=? WHERE id=?').bind(String(b.avatar||'').slice(0,8),String(b.bio||'').slice(0,150),String(b.status||'').slice(0,60),me).run();
{const em=String(b.email||'').trim().toLowerCase();if(/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)&&!await db.prepare('SELECT 1 x FROM users WHERE email=? AND id!=?').bind(em,me).first())await db.prepare('UPDATE users SET email=? WHERE id=?').bind(em,me).run()}
return J({user:await db.prepare(`SELECT ${PUB} FROM users WHERE id=?`).bind(me).first()})}
return J({error:'not found'},404)}

async function aiUser(db){const q="SELECT id FROM users WHERE username='chollu_ai'";let u=await db.prepare(q).bind().first();
if(!u){await db.prepare("INSERT OR IGNORE INTO users(username,salt,pw,avatar,bio,status,created)VALUES('chollu_ai','-','-','🤖','CHOLLU AI അസിസ്റ്റന്റ്','ചോദിക്കൂ, ഞാൻ ഉത്തരം തരാം',?)").bind(Date.now()).run();u=await db.prepare(q).bind().first()}return u.id}

async function pushTo(env,db,uids){if(!env.VAPID_JWK||!env.VAPID_PUB)return;let key;
try{key=await crypto.subtle.importKey('jwk',JSON.parse(env.VAPID_JWK),{name:'ECDSA',namedCurve:'P-256'},false,['sign'])}catch{return}
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),te=new TextEncoder();
for(const uid of uids){const subs=(await db.prepare('SELECT endpoint FROM push_subs WHERE uid=? LIMIT 5').bind(uid).all()).results;
for(const s of subs){try{const h=b64(te.encode(JSON.stringify({typ:'JWT',alg:'ES256'}))),p=b64(te.encode(JSON.stringify({aud:new URL(s.endpoint).origin,exp:Math.floor(Date.now()/1000)+43200,sub:env.VAPID_SUB||'mailto:admin@example.com'})));
const sg=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,te.encode(h+'.'+p)));
const r=await fetch(s.endpoint,{method:'POST',headers:{TTL:'60',Urgency:'high',Authorization:'vapid t='+h+'.'+p+'.'+sg+', k='+env.VAPID_PUB}});
if(r.status==404||r.status==410)await db.prepare('DELETE FROM push_subs WHERE endpoint=?').bind(s.endpoint).run()}catch{}}}}

const pbk=async(p,s)=>'pb1:'+hx(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:new TextEncoder().encode(s),iterations:100000},await crypto.subtle.importKey('raw',new TextEncoder().encode(p),'PBKDF2',false,['deriveBits']),256));
const pwOk=async(us,p)=>us.pw.startsWith('pb1:')?us.pw==await pbk(p,us.salt):us.pw==await H(p,us.salt);
async function lim(db,k,max,win,now){const r=await db.prepare('SELECT n,ts FROM fails WHERE k=?').bind(k).first(),live=r&&now-r.ts<win,n=live?r.n:0;if(n>=max)return true;
await db.prepare('INSERT OR REPLACE INTO fails(k,n,ts)VALUES(?,?,?)').bind(k,n+1,live?r.ts:now).run();return false}
async function cleanup(env){const db=env.DB,now=Date.now();
await dropExpired(env,db,now);
await db.batch([db.prepare('DELETE FROM stories WHERE expires<?').bind(now),db.prepare('DELETE FROM messages WHERE exp>0 AND exp<?').bind(now),db.prepare('DELETE FROM sessions WHERE ts<?').bind(now-2592000000),db.prepare('DELETE FROM download_tokens WHERE exp<?').bind(now),db.prepare('DELETE FROM sigs WHERE ts<?').bind(now-120000),db.prepare('DELETE FROM resets WHERE exp<?').bind(now),db.prepare('DELETE FROM fails WHERE ts<?').bind(now-86400000),db.prepare('DELETE FROM story_views WHERE story_id NOT IN (SELECT id FROM stories)'),db.prepare('DELETE FROM reel_comments WHERE reel_id NOT IN (SELECT id FROM reels)'),db.prepare('DELETE FROM stripe_events WHERE created<?').bind(now-7776000000)]);
if(env.BUCKET){const old=(await db.prepare("SELECT * FROM uploads WHERE status='pending' AND created<? LIMIT 20").bind(now-86400000).all()).results;
for(const up of old){try{await env.BUCKET.resumeMultipartUpload(up.object_key,up.upload_id).abort()}catch{}await db.prepare("UPDATE uploads SET status='aborted' WHERE id=?").bind(up.id).run()}}}

async function mediaUrl(db,me,b,kind){if(!b.media_id)return String(b.media_url||'');const m=await db.prepare('SELECT id,type FROM media WHERE id=? AND owner=?').bind(String(b.media_id),me).first();return!m||(kind=='reel'&&!m.type.startsWith('video/'))?'':'/api/media?id='+m.id}
async function dropMedia(env,db,url){const m=/^\/api\/media\?id=([0-9a-f]{32})$/.exec(url||'');if(!m)return;const r=await db.prepare('SELECT object_key FROM media WHERE id=?').bind(m[1]).first();if(r&&env.BUCKET)await env.BUCKET.delete(r.object_key);await db.prepare('DELETE FROM media WHERE id=?').bind(m[1]).run()}
async function dropExpired(env,db,now){for(const s of(await db.prepare('SELECT media_url FROM stories WHERE expires<? LIMIT 200').bind(now).all()).results)await dropMedia(env,db,s.media_url);await db.prepare('DELETE FROM stories WHERE expires<?').bind(now).run()}
