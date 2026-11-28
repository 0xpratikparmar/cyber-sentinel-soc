import { mkdirSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { openStore } from './store.mjs';
import { makeServer } from './http.mjs';
process.umask(0o077);
const dir=resolve(process.env.SOC_DATA_DIR||'data');mkdirSync(dir,{recursive:true,mode:0o700});if(process.platform!=='win32')chmodSync(dir,0o700);
const store=openStore(resolve(dir,'soc.sqlite'));
if(process.argv[2]==='create-user'){
  try{const email=process.argv[3],password=process.env.SOC_PASSWORD;delete process.env.SOC_PASSWORD;await store.createUser(email,password,process.argv[4]||'analyst');console.log('User created');}catch(e){console.error('User creation failed:',e.message);process.exitCode=1;}finally{store.close();}
}else{
  const port=Number(process.env.PORT||8000);
  const origin=process.env.SOC_ORIGIN||'http://127.0.0.1:'+port;
  const server=await makeServer(store,{origin});
  server.listen(port,process.env.SOC_BIND||'127.0.0.1',()=>console.log('CyberSentinel listening on '+origin));
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>{store.close();process.exit(0);}));
}
