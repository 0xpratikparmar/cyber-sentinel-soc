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
  return {
    close:()=>db.close(),
    async createUser(email,password){email=normalizeEmail(email);if(!validEmail(email))throw Error('Invalid email');const hash=await hashPassword(password);db.prepare('INSERT INTO users(email,password_hash) VALUES (?,?)').run(email,hash);},
    user:email=>db.prepare('SELECT * FROM users WHERE email=?').get(email),
    session(userId,now=Date.now()){const token=newToken();db.prepare('DELETE FROM sessions WHERE expires<=?').run(now);db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(digestToken(token),userId,now+28800000);return token;},
    identity(token,now=Date.now()){if(!token)return null;return db.prepare('SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?').get(digestToken(token),now)||null;},
    revoke(token){if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(digestToken(token));},
    save(userId,events,alerts,rejected){const result=db.prepare('INSERT INTO batches(user_id,created,events,alerts,rejected) VALUES (?,?,?,?,?)').run(userId,new Date().toISOString(),JSON.stringify(events),JSON.stringify(alerts),rejected);return Number(result.lastInsertRowid);},
    batches:userId=>db.prepare('SELECT id,created,json_array_length(events) AS events,json_array_length(alerts) AS alerts,rejected FROM batches WHERE user_id=? ORDER BY id DESC LIMIT 100').all(userId),
    alerts(userId,id){const row=db.prepare('SELECT alerts FROM batches WHERE user_id=? AND id=?').get(userId,id);return row?JSON.parse(row.alerts):null;}
  };
}
