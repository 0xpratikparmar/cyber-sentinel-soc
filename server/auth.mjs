import { randomBytes, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const derive=promisify(scrypt);
const options={N:32768,r:8,p:1,maxmem:64*1024*1024};
export const normalizeEmail=v=>typeof v==='string'?v.trim().toLowerCase():'';
export const validEmail=v=>v.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
export const validPassword=v=>typeof v==='string'&&v.length>=12&&Buffer.byteLength(v)<=256;
export async function hashPassword(password){
  if(!validPassword(password)) throw new Error('Password must be 12+ characters and at most 256 bytes');
  const salt=randomBytes(16);
  const key=await derive(password,salt,64,options);
  return salt.toString('hex')+':'+key.toString('hex');
}
export async function verifyPassword(password,stored){
  if(typeof password!=='string'||Buffer.byteLength(password)>256||!stored||!/^([a-f0-9]{32}):([a-f0-9]{128})$/.test(stored))return false;
  const [salt,key]=stored.split(':');
  const actual=await derive(password,Buffer.from(salt,'hex'),64,options);
  return timingSafeEqual(actual,Buffer.from(key,'hex'));
}
export const newToken=()=>randomBytes(32).toString('hex');
export const digestToken=t=>createHash('sha256').update(t).digest('hex');
export const tokenFromCookie=header=>{const m=/(?:^|;\s*)cs_session=([a-f0-9]{64})(?:;|$)/.exec(header||'');return m?.[1]||null;};
export const sessionCookie=(token,secure,age=28800)=>'cs_session='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+age+(secure?'; Secure':'');
