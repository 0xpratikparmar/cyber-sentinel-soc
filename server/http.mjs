import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { hashPassword, verifyPassword, normalizeEmail, tokenFromCookie, sessionCookie } from './auth.mjs';
import { parseLogs, detect } from '../engine.mjs';
const assets={'/':['console.html','text/html; charset=utf-8'],'/console.mjs':['console.mjs','text/javascript; charset=utf-8'],'/style.css':['style.css','text/css; charset=utf-8'],'/demo':['index.html','text/html; charset=utf-8'],'/app.mjs':['app.mjs','text/javascript; charset=utf-8'],'/engine.mjs':['engine.mjs','text/javascript; charset=utf-8']};
class HttpError extends Error{constructor(status,message){super(message);this.status=status;}}
async function body(req,limit){
  if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))throw new HttpError(415,'JSON required');
  const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>limit)throw new HttpError(413,'Request too large');chunks.push(chunk);}
  try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!value||typeof value!=='object'||Array.isArray(value))throw Error();return value;}catch{throw new HttpError(400,'Invalid JSON');}
}
export async function makeServer(store,{origin='http://127.0.0.1:8000'}={}){
  const secure=new URL(origin).protocol==='https:';
  const dummy=await hashPassword('placeholder-not-a-user-password');
  const attempts=new Map();let activeLogins=0;
  const server=createServer(async(req,res)=>{
    res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-store');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if(secure)res.setHeader('Strict-Transport-Security','max-age=31536000');
    const send=(code,payload)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(payload));};
    try{
      const url=new URL(req.url,'http://localhost'),path=url.pathname;
      if(req.method==='GET'&&Object.hasOwn(assets,path)){const [file,mime]=assets[path];res.writeHead(200,{'Content-Type':mime});res.end(await readFile(new URL('../'+file,import.meta.url)));return;}
      if(req.method==='GET'&&path==='/health')return send(200,{status:'ok'});
      if(req.method==='POST'&&path==='/api/collector/ingest'){
        if(req.headers.origin||req.headers.cookie)throw new HttpError(403,'Collector API requires a machine client');
        const match=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'');
        const collector=store.collector(match?.[1]);if(!collector)throw new HttpError(401,'Invalid collector credential');
        const requestId=req.headers['idempotency-key'];if(typeof requestId!=='string'||!/^[a-zA-Z0-9_-]{16,80}$/.test(requestId))throw new HttpError(400,'Idempotency-Key required');
        const data=await body(req,4200000);
        if(typeof data.jsonl!=='string'||Buffer.byteLength(data.jsonl)>2000000)throw new HttpError(400,'Provide up to 2 MB of JSONL');
        if(!store.collector(match[1]))throw new HttpError(401,'Invalid collector credential');
        const hash=createHash('sha256').update(data.jsonl).digest('hex'),previous=store.receipt(collector.id,requestId);
        if(previous){if(previous.body_hash!==hash)throw new HttpError(409,'Idempotency key already used');return send(200,{id:previous.batch_id,duplicate:true});}
        const {events,errors}=parseLogs(data.jsonl);if(!events.length||events.length>10000)throw new HttpError(400,'Provide 1–10000 valid events');
        const alerts=detect(events),id=store.save(collector.user_id,events,alerts,errors.length,{id:collector.id,requestId,hash});
        return send(201,{id,events:events.length,alerts:alerts.length,rejected:errors.length});
      }
      if(req.method==='POST'&&req.headers.origin!==origin)throw new HttpError(403,'Origin rejected');
      const token=tokenFromCookie(req.headers.cookie);
      if(req.method==='POST'&&path==='/api/login'){
        const now=Date.now(),ip=req.socket.remoteAddress||'unknown';
        for(const [key,v] of attempts)if(v.until<=now)attempts.delete(key);
        if(attempts.size>=10000&&!attempts.has(ip))throw new HttpError(429,'Try again later');
        const entry=attempts.get(ip)||{count:0,until:now+60000};
        if(entry.count>=10||activeLogins>=4)throw new HttpError(429,'Try again later');
        entry.count++;attempts.set(ip,entry);
        const data=await body(req,4096),user=store.user(normalizeEmail(data.email));
        let ok;activeLogins++;try{ok=await verifyPassword(data.password,user?.password_hash||dummy);}finally{activeLogins--;}
        if(!user||!ok)throw new HttpError(401,'Invalid credentials');
        store.revoke(token);store.audit(user.id,'auth.login');res.setHeader('Set-Cookie',sessionCookie(store.session(user.id),secure));return send(200,{email:user.email});
      }
      const identity=store.identity(token);
      if(!identity)throw new HttpError(401,'Authentication required');
      if(req.method==='GET'&&path==='/api/me')return send(200,{email:identity.email,role:identity.role});
      if(req.method==='POST'&&path==='/api/logout'){store.revoke(token);store.audit(identity.id,'auth.logout');res.setHeader('Set-Cookie',sessionCookie('',secure,0));return send(200,{ok:true});}
      if(req.method==='GET'&&path==='/api/summary')return send(200,store.summary(identity.id));
      if(req.method==='GET'&&path==='/api/events')return send(200,store.search(identity.id,(url.searchParams.get('q')||'').slice(0,200),(url.searchParams.get('type')||'').slice(0,50)));
      if(req.method==='GET'&&path==='/api/incidents')return send(200,store.incidents(identity.id));
      const incident=/^\/api\/incidents\/(\d+)$/.exec(path);
      if(req.method==='POST'&&incident){
        const d=await body(req,4096);if(!['open','investigating','resolved'].includes(d.status)||typeof d.note!=='string'||d.note.length>1000)throw new HttpError(400,'Invalid incident status or note');
        if(!store.updateIncident(identity.id,Number(incident[1]),d.status,d.note))throw new HttpError(404,'Incident not found');return send(200,{ok:true});
      }
      const collectorPath=/^\/api\/collectors\/(\d+)\/revoke$/.exec(path);
      if(path==='/api/collectors'||collectorPath||path==='/api/audit'){
        if(identity.role!=='admin')throw new HttpError(403,'Admin role required');
        if(req.method==='GET'&&path==='/api/audit')return send(200,store.auditList(identity.id));
        if(req.method==='GET'&&path==='/api/collectors')return send(200,store.collectors(identity.id));
        if(req.method==='POST'&&path==='/api/collectors'){const d=await body(req,4096);if(typeof d.name!=='string'||!d.name.trim()||d.name.length>100)throw new HttpError(400,'Invalid collector name');return send(201,store.createCollector(identity.id,d.name.trim()));}
        if(req.method==='POST'&&collectorPath){if(!store.revokeCollector(identity.id,Number(collectorPath[1])))throw new HttpError(404,'Collector not found');return send(200,{ok:true});}
      }
      if(req.method==='GET'&&path==='/api/batches')return send(200,store.batches(identity.id));
      if(req.method==='POST'&&path==='/api/batches'){
        const data=await body(req,4200000);
        if(typeof data.jsonl!=='string'||Buffer.byteLength(data.jsonl)>2000000)throw new HttpError(400,'Provide up to 2 MB of JSONL');
        const {events,errors}=parseLogs(data.jsonl);
        if(!events.length||events.length>10000)throw new HttpError(400,'Provide 1–10000 valid events');
        const alerts=detect(events),id=store.save(identity.id,events,alerts,errors.length);
        return send(201,{id,events:events.length,alerts:alerts.length,rejected:errors.length});
      }
      const m=/^\/api\/batches\/(\d+)\/alerts$/.exec(path);
      if(req.method==='GET'&&m){const alerts=store.alerts(identity.id,Number(m[1]));if(!alerts)throw new HttpError(404,'Batch not found');return send(200,alerts);}
      throw new HttpError(404,'Not found');
    }catch(e){if(!res.headersSent)send(e.status||500,{error:e.status?e.message:'Internal server error'});else res.destroy();}
  });
  server.requestTimeout=15000;server.headersTimeout=10000;return server;
}
