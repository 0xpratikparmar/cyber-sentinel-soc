// Explicitly selected normalized JSONL only. Does not discover, collect or transmit other files.
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
const endpoint=new URL(process.env.SOC_URL||'http://127.0.0.1:8000');
if(endpoint.protocol!=='https:'&&!(endpoint.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname)))throw Error('Remote collectors require HTTPS');
if(endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw Error('Invalid SOC_URL');
const token=process.env.SOC_COLLECTOR_TOKEN;delete process.env.SOC_COLLECTOR_TOKEN;
if(!/^[a-f0-9]{64}$/.test(token||''))throw Error('Set SOC_COLLECTOR_TOKEN securely');
const file=process.argv[2];if(!file)throw Error('Usage: node agents/ship.mjs <authorized-jsonl-file>');
const rl=createInterface({input:createReadStream(file),crlfDelay:Infinity});
let lines=[],bytes=0;
async function flush(){
 if(!lines.length)return;
 const jsonl=lines.join('\n'),key=createHash('sha256').update(jsonl).digest('hex');
 for(let attempt=0;attempt<3;attempt++){
   let r;try{r=await fetch(new URL('/api/collector/ingest',endpoint),{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','Idempotency-Key':key},body:JSON.stringify({jsonl}),signal:AbortSignal.timeout(15000),redirect:'error'});}catch(e){if(attempt===2)throw e;}
   if(r?.ok){const result=await r.json();console.log('Batch '+result.id+(result.duplicate?' already received':' accepted'));lines=[];bytes=0;return;}
   if(r&&r.status<500&&r.status!==429)throw Error('Collector rejected: HTTP '+r.status);
   if(attempt<2)await new Promise(r=>setTimeout(r,1000*(attempt+1)));
 }
 throw Error('Collector delivery failed; rerun the same file safely');
}
for await(const line of rl){if(!line.trim())continue;const n=Buffer.byteLength(line)+1;if(n>1000000)throw Error('Oversized line');if(lines.length>=500||bytes+n>1000000)await flush();lines.push(line);bytes+=n;}
await flush();
