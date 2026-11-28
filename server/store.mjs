import { DatabaseSync } from 'node:sqlite';
import { hashPassword, normalizeEmail, validEmail, digestToken, newToken } from './auth.mjs';
export function openStore(path){
  const db=new DatabaseSync(path);
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created TEXT NOT NULL,events TEXT NOT NULL,alerts TEXT NOT NULL,rejected INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS batches_owner ON batches(user_id,id);
  CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);`);
  if(!db.prepare('PRAGMA table_info(users)').all().some(c=>c.name==='role'))db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst' CHECK(role IN ('admin','analyst'))");
  db.exec(`CREATE TABLE IF NOT EXISTS collectors(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created TEXT NOT NULL,last_seen TEXT,revoked INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),batch_id INTEGER NOT NULL REFERENCES batches(id),created TEXT NOT NULL,severity TEXT NOT NULL,rule TEXT NOT NULL,source TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',note TEXT NOT NULL DEFAULT '');
  CREATE INDEX IF NOT EXISTS incidents_owner ON incidents(user_id,id);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),created TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS audit_owner ON audit(user_id,id);
  CREATE TABLE IF NOT EXISTS normalized_events(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),batch_id INTEGER NOT NULL REFERENCES batches(id),timestamp TEXT NOT NULL,type TEXT NOT NULL,source TEXT NOT NULL,username TEXT NOT NULL,detail TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS event_owner_time ON normalized_events(user_id,timestamp);
  CREATE TABLE IF NOT EXISTS receipts(collector_id INTEGER NOT NULL REFERENCES collectors(id),request_id TEXT NOT NULL,body_hash TEXT NOT NULL,batch_id INTEGER NOT NULL REFERENCES batches(id),PRIMARY KEY(collector_id,request_id));`);
  const audit=(id,action,target='')=>db.prepare('INSERT INTO audit(user_id,created,action,target) VALUES (?,?,?,?)').run(id,new Date().toISOString(),action,String(target));
  return {
    close:()=>db.close(),
    async createUser(email,password,role='analyst'){if(!['admin','analyst'].includes(role))throw Error('Invalid role');email=normalizeEmail(email);if(!validEmail(email))throw Error('Invalid email');const hash=await hashPassword(password);db.prepare('INSERT INTO users(email,password_hash,role) VALUES (?,?,?)').run(email,hash,role);},
    user:email=>db.prepare('SELECT * FROM users WHERE email=?').get(email),
    session(userId,now=Date.now()){const token=newToken();db.prepare('DELETE FROM sessions WHERE expires<=?').run(now);db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(digestToken(token),userId,now+28800000);return token;},
    identity(token,now=Date.now()){if(!token)return null;return db.prepare('SELECT u.id,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?').get(digestToken(token),now)||null;},
    revoke(token){if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(digestToken(token));},
    save(userId,events,alerts,rejected,receipt=null){
      db.exec('BEGIN IMMEDIATE');
      try{
        const now=new Date().toISOString(),result=db.prepare('INSERT INTO batches(user_id,created,events,alerts,rejected) VALUES (?,?,?,?,?)').run(userId,now,JSON.stringify(events),JSON.stringify(alerts),rejected),id=Number(result.lastInsertRowid);
        const add=db.prepare('INSERT INTO normalized_events(user_id,batch_id,timestamp,type,source,username,detail) VALUES (?,?,?,?,?,?,?)');
        for(const e of events)add.run(userId,id,e.timestamp,e.type,e.source,e.user||'',e.detail||'');
        const incident=db.prepare('INSERT INTO incidents(user_id,batch_id,created,severity,rule,source) VALUES (?,?,?,?,?,?)');
        for(const a of alerts)if(a.severity==='high')incident.run(userId,id,now,a.severity,a.rule,a.source);
        if(receipt){db.prepare('INSERT INTO receipts VALUES (?,?,?,?)').run(receipt.id,receipt.requestId,receipt.hash,id);db.prepare('UPDATE collectors SET last_seen=? WHERE id=?').run(now,receipt.id);}
        audit(userId,receipt?'collector.ingest':'batch.import',id);
        db.exec('COMMIT');return id;
      }catch(e){db.exec('ROLLBACK');throw e;}
    },
    audit,
    auditList:id=>db.prepare('SELECT created,action,target FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 100').all(id),
    createCollector(id,name){const token=newToken();const r=db.prepare('INSERT INTO collectors(user_id,name,token_hash,created) VALUES (?,?,?,?)').run(id,name,digestToken(token),new Date().toISOString());audit(id,'collector.create',r.lastInsertRowid);return {id:Number(r.lastInsertRowid),token};},
    collectors:id=>db.prepare('SELECT id,name,created,last_seen,revoked FROM collectors WHERE user_id=? ORDER BY id DESC LIMIT 100').all(id),
    collector(token){if(!token)return null;return db.prepare('SELECT id,user_id FROM collectors WHERE token_hash=? AND revoked=0').get(digestToken(token))||null;},
    revokeCollector(id,cid){const n=db.prepare('UPDATE collectors SET revoked=1 WHERE user_id=? AND id=? AND revoked=0').run(id,cid).changes;if(n)audit(id,'collector.revoke',cid);return !!n;},
    receipt:(cid,requestId)=>db.prepare('SELECT body_hash,batch_id FROM receipts WHERE collector_id=? AND request_id=?').get(cid,requestId),
    summary(id){return {...db.prepare('SELECT count(*) AS batches,coalesce(sum(json_array_length(events)),0) AS events,coalesce(sum(json_array_length(alerts)),0) AS alerts FROM batches WHERE user_id=?').get(id),...db.prepare("SELECT count(*) AS open_incidents FROM incidents WHERE user_id=? AND status!='resolved'").get(id),...db.prepare('SELECT count(*) AS active_collectors FROM collectors WHERE user_id=? AND revoked=0').get(id)};},
    search(id,q,type){const pattern='%'+q.replace(/[!%_]/g,x=>'!'+x)+'%';return db.prepare("SELECT timestamp,type,source,username AS user,detail,batch_id FROM normalized_events WHERE user_id=? AND (?='' OR type=?) AND (source LIKE ? ESCAPE '!' OR username LIKE ? ESCAPE '!' OR detail LIKE ? ESCAPE '!') ORDER BY timestamp DESC,id DESC LIMIT 200").all(id,type,type,pattern,pattern,pattern);},
    incidents:id=>db.prepare('SELECT id,batch_id,created,severity,rule,source,status,note FROM incidents WHERE user_id=? ORDER BY id DESC LIMIT 100').all(id),
    updateIncident(id,i,status,note){const n=db.prepare('UPDATE incidents SET status=?,note=? WHERE user_id=? AND id=?').run(status,note,id,i).changes;if(n)audit(id,'incident.update',i);return !!n;},,
    batches:userId=>db.prepare('SELECT id,created,json_array_length(events) AS events,json_array_length(alerts) AS alerts,rejected FROM batches WHERE user_id=? ORDER BY id DESC LIMIT 100').all(userId),
    alerts(userId,id){const row=db.prepare('SELECT alerts FROM batches WHERE user_id=? AND id=?').get(userId,id);return row?JSON.parse(row.alerts):null;}
  };
}
