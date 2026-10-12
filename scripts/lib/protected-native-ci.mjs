/** Generic native acceptance wrapper. Contains no product imports or private data. */
import {readFile,writeFile,mkdir,lstat,open,readdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomBytes,createCipheriv,createDecipheriv,createPublicKey,publicEncrypt,privateDecrypt,constants} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';

const MAX_DOWNLOAD=512*1024*1024,MAX_BUNDLE=128*1024*1024,MAX_EXTRACTED=512*1024*1024;
const SHA=/^[a-f0-9]{64}$/,PLATFORMS=new Set(['win32-x64','darwin-arm64','darwin-x64']);
const SIGNED_HOSTS=new Set(['release-assets.githubusercontent.com','objects.githubusercontent.com']);
const FORMAT='protected-native-result-v1';
const RESULT_CAPS=Object.freeze({'acceptance.json':8*1024*1024,'output.mp4':256*1024*1024,'last-frame.png':20*1024*1024,'stdout.log':32*1024*1024,'stderr.log':32*1024*1024});
const MAX_RESULTS=350*1024*1024;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{throw Error('PROTECTED_'+code);};
function exactKeys(value,keys){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('|')===keys.slice().sort().join('|');}
function wheelName(value){return typeof value==='string'&&/^[A-Za-z0-9_][A-Za-z0-9_.+-]*\.whl$/.test(value)&&value.length<=180&&!value.includes('..')&&value.split('-').length>=5;}
function checkedArtifact(value,wheel=false){
 if(!exactKeys(value,wheel?['url','sha256','bytes','filename']:['url','sha256','bytes'])||!SHA.test(value.sha256)||!Number.isSafeInteger(value.bytes)||value.bytes<1||value.bytes>MAX_DOWNLOAD||wheel&&!wheelName(value.filename))fail('PLAN_REJECTED');
 let url;try{url=new URL(value.url);}catch{fail('PLAN_REJECTED');}
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.port||!SIGNED_HOSTS.has(url.hostname))fail('PLAN_REJECTED');
 return {...value};
}
export function assertNotExpired(expiresAt,{now=Date.now(),minRemainingMs=60000}={}){
 const expiry=typeof expiresAt==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(expiresAt)?Date.parse(expiresAt):NaN;
 if(!Number.isFinite(expiry)||new Date(expiry).toISOString().replace('.000Z','Z')!==expiresAt.replace('.000Z','Z')||!Number.isFinite(now)||expiry-now<minRemainingMs)fail('SOURCE_EXPIRED');return expiry;
}
export function parseSourcePlan(input,{bundleSha,now=Date.now()}={}){
 let value;try{value=typeof input==='string'?JSON.parse(input):input;}catch{fail('PLAN_REJECTED');}
 if(!exactKeys(value,['bundle','wheels','expiresAt'])||!Array.isArray(value.wheels)||value.wheels.length>16)fail('PLAN_REJECTED');
 const bundle=checkedArtifact(value.bundle);if(bundle.bytes>MAX_BUNDLE)fail('PLAN_REJECTED');
 if(!SHA.test(bundleSha)||bundle.sha256!==bundleSha)fail('BUNDLE_SHA_MISMATCH');
 const wheels=value.wheels.map(x=>checkedArtifact(x,true));
 if(new Set(wheels.map(x=>x.filename.toLowerCase())).size!==wheels.length)fail('PLAN_REJECTED');
 assertNotExpired(value.expiresAt,{now});return {bundle,wheels,expiresAt:value.expiresAt};
}
export async function downloadExactArtifact(spec,{expiresAt,now=Date.now,fetch:fetcher=globalThis.fetch}={}){
 checkedArtifact(spec,Object.hasOwn(spec,'filename'));assertNotExpired(expiresAt,{now:now()});
 let response;try{response=await fetcher(spec.url,{redirect:'error',signal:AbortSignal.timeout(120000)});}catch{fail('DOWNLOAD_FAILED');}
 if(!response?.ok||response.redirected||response.url&&response.url!==spec.url)fail('DOWNLOAD_FAILED');
 const length=response.headers.get('content-length');if(length!==null&&(!/^\d+$/.test(length)||Number(length)!==spec.bytes))fail('DOWNLOAD_LENGTH_MISMATCH');
 if(!response.body)fail('DOWNLOAD_FAILED');let size=0;const parts=[];
 try{for await(const part of response.body){const bytes=Buffer.from(part);size+=bytes.length;if(size>spec.bytes||size>MAX_DOWNLOAD)fail('DOWNLOAD_SIZE_REJECTED');parts.push(bytes);}}catch{fail('DOWNLOAD_REJECTED');}
 assertNotExpired(expiresAt,{now:now()});if(size!==spec.bytes)fail('DOWNLOAD_LENGTH_MISMATCH');
 const bytes=Buffer.concat(parts,size);if(hash(bytes)!==spec.sha256)fail('DOWNLOAD_HASH_MISMATCH');return bytes;
}

export function childEnvironment(env=process.env){
 const allowed=new Set(['HOME','USERPROFILE','HOMEDRIVE','HOMEPATH','APPDATA','LOCALAPPDATA','PATH','TMP','TEMP','TMPDIR','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','OS','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','LANG','LC_ALL','LC_CTYPE','GITHUB_ACTIONS','RUNNER_ENVIRONMENT']);
 return Object.fromEntries(Object.entries(env).filter(([key,value])=>allowed.has(key.toUpperCase())&&typeof value==='string'));
}
export function assertWorkflowContext(env=process.env){
 if(env.GITHUB_EVENT_NAME!=='workflow_dispatch'||env.GITHUB_REF!=='refs/heads/main'||!/^[a-f0-9]{40}$/.test(env.EXPECTED_MAIN_SHA??'')||env.GITHUB_SHA!==env.EXPECTED_MAIN_SHA||env.GITHUB_WORKFLOW_SHA!==env.EXPECTED_MAIN_SHA)fail('WORKFLOW_CONTEXT_REJECTED');
}
async function noLinks(file){
 for(let current=path.resolve(file);;current=path.dirname(current)){
  try{if((await lstat(current)).isSymbolicLink())fail('PATH_REJECTED');}catch(error){if(error.code!=='ENOENT')throw error;}
  if(current===path.dirname(current))break;
 }
}
function safeRelative(name){
 if(typeof name!=='string'||!name||name.includes('\\')||name.startsWith('/')||/[\x00-\x1f\x7f:]/.test(name))fail('BUNDLE_REJECTED');
 const parts=name.endsWith('/')?name.slice(0,-1).split('/'):name.split('/');
 if(parts.some(part=>!part||part==='.'||part==='..'||/[ .]$/.test(part)||/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)))fail('BUNDLE_REJECTED');return parts.join('/');
}
function crc32(bytes){let crc=0xffffffff;for(const value of bytes){crc^=value;for(let n=0;n<8;n++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;}
function zipEntries(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_BUNDLE||bytes.length<22)fail('BUNDLE_REJECTED');
 let end=-1;for(let at=bytes.length-22;at>=Math.max(0,bytes.length-65557);at--)if(bytes.readUInt32LE(at)===0x06054b50&&at+22+bytes.readUInt16LE(at+20)===bytes.length){end=at;break;}
 if(end<0||bytes.readUInt16LE(end+4)||bytes.readUInt16LE(end+6)||bytes.readUInt16LE(end+8)!==bytes.readUInt16LE(end+10))fail('BUNDLE_REJECTED');
 const count=bytes.readUInt16LE(end+10),centralBytes=bytes.readUInt32LE(end+12),centralOffset=bytes.readUInt32LE(end+16);
 if(!count||count>20000||centralOffset+centralBytes!==end)fail('BUNDLE_REJECTED');
 const entries=[],seen=new Set(),ranges=[];let at=centralOffset,total=0;
 for(let index=0;index<count;index++){
  if(at+46>end||bytes.readUInt32LE(at)!==0x02014b50)fail('BUNDLE_REJECTED');
  const flags=bytes.readUInt16LE(at+8),method=bytes.readUInt16LE(at+10),crc=bytes.readUInt32LE(at+16),compressed=bytes.readUInt32LE(at+20),size=bytes.readUInt32LE(at+24),nameLength=bytes.readUInt16LE(at+28),extra=bytes.readUInt16LE(at+30),comment=bytes.readUInt16LE(at+32),disk=bytes.readUInt16LE(at+34),external=bytes.readUInt32LE(at+38),offset=bytes.readUInt32LE(at+42);
  if(flags&~0x800||![0,8].includes(method)||disk||at+46+nameLength+extra+comment>end||[compressed,size,offset].includes(0xffffffff))fail('BUNDLE_REJECTED');
  const nameBytes=bytes.subarray(at+46,at+46+nameLength),name=new TextDecoder('utf-8',{fatal:true}).decode(nameBytes),relative=safeRelative(name),directory=name.endsWith('/'),type=(external>>>16)&0xf000;
  if(type&&type!==(directory?0x4000:0x8000)||directory&&size||seen.has(relative.toLowerCase()))fail('BUNDLE_REJECTED');seen.add(relative.toLowerCase());
  if(offset+30>centralOffset||bytes.readUInt32LE(offset)!==0x04034b50||bytes.readUInt16LE(offset+6)!==flags||bytes.readUInt16LE(offset+8)!==method||bytes.readUInt32LE(offset+14)!==crc||bytes.readUInt32LE(offset+18)!==compressed||bytes.readUInt32LE(offset+22)!==size)fail('BUNDLE_REJECTED');
  const localNameLength=bytes.readUInt16LE(offset+26),localExtra=bytes.readUInt16LE(offset+28),dataOffset=offset+30+localNameLength+localExtra,endOffset=dataOffset+compressed;
  if(endOffset>centralOffset||localNameLength!==nameLength||!bytes.subarray(offset+30,offset+30+localNameLength).equals(nameBytes)||ranges.some(([start,end])=>offset<end&&endOffset>start))fail('BUNDLE_REJECTED');ranges.push([offset,endOffset]);
  total+=size;if(total>MAX_EXTRACTED)fail('BUNDLE_REJECTED');
  const packed=bytes.subarray(dataOffset,endOffset),content=method===0?Buffer.from(packed):inflateRawSync(packed,{maxOutputLength:Math.max(1,size)});
  if(content.length!==size||crc32(content)!==crc)fail('BUNDLE_REJECTED');entries.push({relative,directory,bytes:content});at+=46+nameLength+extra+comment;
 }
 if(at!==end)fail('BUNDLE_REJECTED');
 for(const entry of entries)if(entries.some(parent=>!parent.directory&&entry.relative.toLowerCase().startsWith(parent.relative.toLowerCase()+'/')))fail('BUNDLE_REJECTED');
 return entries;
}
export async function extractTrustedBundle(bytes,root){
 let entries;try{entries=zipEntries(bytes);}catch{fail('BUNDLE_REJECTED');}
 await noLinks(root);await mkdir(root,{recursive:true});if((await readdir(root)).length)fail('BUNDLE_REJECTED');
 for(const entry of entries){const destination=path.join(root,entry.relative);await noLinks(destination);if(entry.directory)await mkdir(destination,{recursive:true});else{await mkdir(path.dirname(destination),{recursive:true});await writeFile(destination,entry.bytes,{flag:'wx',mode:0o600});}}
}
async function readBounded(file,cap){await noLinks(file);const stat=await lstat(file);if(!stat.isFile()||stat.size>cap)fail('RESULT_REJECTED');return readFile(file);}
export async function verifySnapshotInputs({root,sourceSha,installKeySha,engineDigest}){
 if(![sourceSha,installKeySha,engineDigest].every(x=>SHA.test(x)))fail('SNAPSHOT_REJECTED');
 let manifest;try{manifest=JSON.parse(await readBounded(path.join(root,'.ci/installer-manifest.json'),8*1024*1024));}catch{fail('SNAPSHOT_REJECTED');}
 const source=manifest?.payload?.source;if(source?.sha256!==sourceSha||!Number.isSafeInteger(source.bytes)||source.bytes<1||source.bytes>MAX_BUNDLE||manifest?.payload?.engineBootstrap?.sourceDigest!==engineDigest)fail('SNAPSHOT_REJECTED');
 const bytes=await readBounded(path.join(root,'.ci/source.zip'),MAX_BUNDLE),key=await readBounded(path.join(root,'.ci/install-public-key.pem'),16384);
 if(bytes.length!==source.bytes||hash(bytes)!==sourceSha||hash(key)!==installKeySha)fail('SNAPSHOT_REJECTED');
 return {sourceSha,bytes:source.bytes,installKeySha,engineDigest};
}
export function verifyWheelAllowlist(wheels,allowlist){
 if(!Array.isArray(allowlist)||allowlist.length!==wheels.length)fail('WHEEL_ALLOWLIST_MISMATCH');
 const allowed=new Map();for(const item of allowlist){if(!exactKeys(item,['filename','sha256','bytes'])||!wheelName(item.filename)||!SHA.test(item.sha256)||!Number.isSafeInteger(item.bytes)||allowed.has(item.filename))fail('WHEEL_ALLOWLIST_MISMATCH');allowed.set(item.filename,item);}
 for(const item of wheels){const expected=allowed.get(item.filename);if(!expected||expected.sha256!==item.sha256||expected.bytes!==item.bytes)fail('WHEEL_ALLOWLIST_MISMATCH');}
}
export function neutralStatus(value){
 if(!exactKeys(value,['platform','passed','bundleSha','sourceSha','durationMs','exitCode'])||!PLATFORMS.has(value.platform)||typeof value.passed!=='boolean'||!SHA.test(value.bundleSha)||!SHA.test(value.sourceSha)||!Number.isSafeInteger(value.durationMs)||value.durationMs<0||!Number.isSafeInteger(value.exitCode)||value.exitCode<0||value.exitCode>255||value.passed&&value.exitCode!==0)fail('STATUS_REJECTED');return {...value};
}
export function publicFailure(){return 'PROTECTED_RUN_FAILED';}
export async function collectResults(root,platform,{caps={}}={}){
 if(!PLATFORMS.has(platform)||Object.keys(caps).some(key=>!Object.hasOwn(RESULT_CAPS,key)))fail('RESULT_REJECTED');
 const files=[];let size=0;for(const [name,cap] of Object.entries(RESULT_CAPS)){
  const file=path.join(root,name.endsWith('.log')?'.protected-private':'.ci-results/'+platform,name);
  try{const bytes=await readBounded(file,Math.min(cap,caps[name]??cap));size+=bytes.length;if(size>MAX_RESULTS)fail('RESULT_REJECTED');files.push({name,bytes});}catch(error){if(error.code!=='ENOENT')throw error;}
 }return files;
}
function checkedFiles(files){
 if(!Array.isArray(files)||files.length>5||new Set(files.map(x=>x.name)).size!==files.length)fail('RESULT_REJECTED');let total=0;
 for(const file of files){if(!exactKeys(file,['name','bytes'])||!Object.hasOwn(RESULT_CAPS,file.name)||!Buffer.isBuffer(file.bytes)||file.bytes.length>RESULT_CAPS[file.name])fail('RESULT_REJECTED');total+=file.bytes.length;if(total>MAX_RESULTS)fail('RESULT_REJECTED');}return files;
}
function recipient(publicKey,recipientSha){
 try{if(typeof publicKey!=='string'||hash(publicKey)!==recipientSha)fail('RECIPIENT_REJECTED');const key=createPublicKey(publicKey);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==3072)fail('RECIPIENT_REJECTED');return key;}catch{fail('RECIPIENT_REJECTED');}
}
const aad=value=>Buffer.from(JSON.stringify({format:FORMAT,platform:value.platform,bundleSha:value.bundleSha,sourceSha:value.sourceSha}));
export function sealResults({files,platform,bundleSha,sourceSha},{publicKey,recipientSha}){
 checkedFiles(files);if(!PLATFORMS.has(platform)||![bundleSha,sourceSha,recipientSha].every(x=>SHA.test(x)))fail('RESULT_REJECTED');
 const key=recipient(publicKey,recipientSha),dataKey=randomBytes(32),nonce=randomBytes(12);
 try{const cipher=createCipheriv('aes-256-gcm',dataKey,nonce);cipher.setAAD(aad({platform,bundleSha,sourceSha}));const clear=Buffer.from(JSON.stringify({files:files.map(({name,bytes})=>({name,bytes:bytes.toString('base64')}))}));
  const ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);clear.fill(0);
  return {format:FORMAT,platform,bundleSha,sourceSha,recipientSha,nonce:nonce.toString('base64'),tag:cipher.getAuthTag().toString('base64'),wrappedKey:publicEncrypt({key,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},dataKey).toString('base64'),ciphertext:ciphertext.toString('base64')};
 }finally{dataKey.fill(0);}
}
function decode(value,cap){if(typeof value!=='string'||value.length>Math.ceil(cap/3)*4||value.length%4||/[^A-Za-z0-9+/=]/.test(value))fail('RESULT_AUTH_FAILED');const bytes=Buffer.from(value,'base64');if(bytes.length>cap||bytes.toString('base64')!==value)fail('RESULT_AUTH_FAILED');return bytes;}
export function openResults(envelope,{privateKey,recipientSha}){
 let dataKey;
 try{
  if(!exactKeys(envelope,['format','platform','bundleSha','sourceSha','recipientSha','nonce','tag','wrappedKey','ciphertext'])||envelope.format!==FORMAT||!PLATFORMS.has(envelope.platform)||![envelope.bundleSha,envelope.sourceSha,envelope.recipientSha].every(x=>SHA.test(x))||envelope.recipientSha!==recipientSha)fail('RESULT_AUTH_FAILED');
  const nonce=decode(envelope.nonce,12),tag=decode(envelope.tag,16),wrapped=decode(envelope.wrappedKey,384),encrypted=decode(envelope.ciphertext,Math.ceil(MAX_RESULTS*4/3)+4096);
  if(nonce.length!==12||tag.length!==16||wrapped.length!==384)fail('RESULT_AUTH_FAILED');
  dataKey=privateDecrypt({key:privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},wrapped);if(dataKey.length!==32)fail('RESULT_AUTH_FAILED');
  const decipher=createDecipheriv('aes-256-gcm',dataKey,nonce);decipher.setAAD(aad(envelope));decipher.setAuthTag(tag);
  const clear=Buffer.concat([decipher.update(encrypted),decipher.final()]);let parsed;try{parsed=JSON.parse(clear.toString('utf8'));}finally{clear.fill(0);}
  if(!exactKeys(parsed,['files'])||!Array.isArray(parsed.files))fail('RESULT_AUTH_FAILED');
  const files=parsed.files.map(file=>{if(!exactKeys(file,['name','bytes'])||!Object.hasOwn(RESULT_CAPS,file.name))fail('RESULT_AUTH_FAILED');return {name:file.name,bytes:decode(file.bytes,RESULT_CAPS[file.name])};});checkedFiles(files);
  return {platform:envelope.platform,bundleSha:envelope.bundleSha,sourceSha:envelope.sourceSha,files};
 }catch{fail('RESULT_AUTH_FAILED');}finally{dataKey?.fill(0);}
}

async function terminateOwnedTree(child,env){
 if(!Number.isInteger(child?.pid)||child.pid<1||child.pid===process.pid)return;
 if(process.platform!=='win32'){try{process.kill(-child.pid,'SIGKILL');}catch{}try{child.kill('SIGKILL');}catch{}return;}
 // Only numeric descendants of this spawned PID are selected; command lines/credentials are never queried.
 const systemRoot=env.SYSTEMROOT??env.SystemRoot??process.env.SYSTEMROOT??process.env.SystemRoot;
 const commandOptions={env:childEnvironment(env),shell:false,windowsHide:true,timeout:1800,maxBuffer:256*1024};
 const owned=new Set([child.pid]);
 try{
  const script='Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress';
  const result=await promisify(execFile)(path.join(systemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoLogo','-NoProfile','-NonInteractive','-Command',script],commandOptions);
  const rows=JSON.parse(result.stdout),processes=Array.isArray(rows)?rows:[rows];let changed=true;
  while(changed){changed=false;for(const row of processes)if(Number.isInteger(row.ProcessId)&&row.ProcessId>0&&row.ProcessId!==process.pid&&owned.has(row.ParentProcessId)&&!owned.has(row.ProcessId)){owned.add(row.ProcessId);changed=true;}}
 }catch{}
 try{await promisify(execFile)(path.join(systemRoot,'System32/taskkill.exe'),['/T','/F',...Array.from(owned).flatMap(pid=>['/PID',String(pid)])],commandOptions);}catch{}
 try{child.kill('SIGKILL');}catch{}
}
export async function runVerifier({root,platform,env=process.env,timeoutMs=42*60*1000,spawnChild=spawn,terminateTree=terminateOwnedTree}){
 if(!PLATFORMS.has(platform))fail('VERIFIER_REJECTED');const file=path.join(root,'scripts/verify-cross-platform.mjs');await noLinks(file);if(!(await lstat(file)).isFile())fail('VERIFIER_REJECTED');
 const captureRoot=path.join(root,'.protected-private');await noLinks(captureRoot);await mkdir(captureRoot,{recursive:true});
 const stdout=await open(path.join(captureRoot,'stdout.log'),'wx',0o600),stderr=await open(path.join(captureRoot,'stderr.log'),'wx',0o600);
 let child,timedOut=false,timer,cleanupPromise;
 const terminate=()=>cleanupPromise??=Promise.resolve().then(()=>terminateTree(child,env)).catch(()=>{});
 const cleanup=async()=>{try{await terminate();}finally{child?.stdout?.destroy();child?.stderr?.destroy();}};
 try{
  child=spawnChild(process.execPath,[file,'--run','--expected-platform',platform],{cwd:root,env:childEnvironment(env),shell:false,windowsHide:true,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});
  const completion=new Promise(resolve=>{child.once('error',()=>resolve(1));child.once('close',code=>resolve(Number.isInteger(code)&&code>=0&&code<=255?code:1));});
  // Exit may precede pipe closure when a grandchild still owns an inherited descriptor.
  child.once('exit',()=>{void terminate();});
  async function capture(stream,handle,cap){let size=0;for await(const chunk of stream){size+=chunk.length;if(size>cap){await cleanup();fail('CAPTURE_LIMIT');}await handle.writeFile(chunk);}}
  const deadline=new Promise(resolve=>{timer=setTimeout(async()=>{timedOut=true;await cleanup();resolve(null);},timeoutMs);timer.unref();});
  const settled=Promise.allSettled([completion,capture(child.stdout,stdout,RESULT_CAPS['stdout.log']),capture(child.stderr,stderr,RESULT_CAPS['stderr.log'])]);
  const results=await Promise.race([settled,deadline]);
  if(!results)return {exitCode:1};await cleanupPromise;
  if(timedOut||results.some(x=>x.status==='rejected'))return {exitCode:1};return {exitCode:results[0].value};
 }catch{return {exitCode:1};}finally{clearTimeout(timer);await stdout.close();await stderr.close();}
}
export async function verifyPublicOutput({outputRoot,statusBytes,encryptedBytes,status,recipientSha}){
 await noLinks(outputRoot);if((await readdir(outputRoot)).sort().join('|')!=='result.enc.json|status.json')fail('RESULT_REJECTED');
 const actualStatus=await readBounded(path.join(outputRoot,'status.json'),4096),actualEncrypted=await readBounded(path.join(outputRoot,'result.enc.json'),Math.ceil(MAX_RESULTS*16/9)+16384);
 if(hash(actualStatus)!==hash(statusBytes)||hash(actualEncrypted)!==hash(encryptedBytes))fail('RESULT_REJECTED');
 let parsed,envelope;try{parsed=JSON.parse(actualStatus);envelope=JSON.parse(actualEncrypted);}catch{fail('RESULT_REJECTED');}
 neutralStatus(parsed);if(JSON.stringify(parsed)!==JSON.stringify(status)||!exactKeys(envelope,['format','platform','bundleSha','sourceSha','recipientSha','nonce','tag','wrappedKey','ciphertext'])||envelope.format!==FORMAT||envelope.platform!==status.platform||envelope.sourceSha!==status.sourceSha||envelope.bundleSha!==status.bundleSha||envelope.recipientSha!==recipientSha)fail('RESULT_REJECTED');
 try{if(decode(envelope.nonce,12).length!==12||decode(envelope.tag,16).length!==16||decode(envelope.wrappedKey,384).length!==384||decode(envelope.ciphertext,Math.ceil(MAX_RESULTS*4/3)+8192).length<1)fail('RESULT_REJECTED');}catch{fail('RESULT_REJECTED');}
 return true;
}
export async function executeProtectedAcceptance({sourcePlan,bundleSha,sourceSha,installKeySha,engineDigest,recipientSha,publicKey,platform,workRoot,outputRoot,githubOutput,env=process.env,now=Date.now,fetch:fetcher=globalThis.fetch}){
 const started=Date.now();recipient(publicKey,recipientSha);if(!PLATFORMS.has(platform)||![sourceSha,installKeySha,engineDigest].every(x=>SHA.test(x)))fail('RUN_REJECTED');
 const plan=parseSourcePlan(sourcePlan,{bundleSha,now:now()});await noLinks(workRoot);await noLinks(outputRoot);
 const bundle=await downloadExactArtifact(plan.bundle,{expiresAt:plan.expiresAt,now,fetch:fetcher});await extractTrustedBundle(bundle,workRoot);
 await verifySnapshotInputs({root:workRoot,sourceSha,installKeySha,engineDigest});
 let allowlist;try{allowlist=JSON.parse(await readBounded(path.join(workRoot,'.ci/wheel-allowlist.json'),65536));}catch{fail('WHEEL_ALLOWLIST_MISMATCH');}verifyWheelAllowlist(plan.wheels,allowlist);
 for(const wheel of plan.wheels){const bytes=await downloadExactArtifact(wheel,{expiresAt:plan.expiresAt,now,fetch:fetcher}),packageName=wheel.filename.split('-')[0],file=path.join(workRoot,'.ci/wheel-builds',packageName,'wheels',wheel.filename);await noLinks(file);await mkdir(path.dirname(file),{recursive:true});await writeFile(file,bytes,{flag:'wx',mode:0o600});}
 const {exitCode}=await runVerifier({root:workRoot,platform,env});let files;try{files=await collectResults(workRoot,platform);}catch{fail('RESULT_REJECTED');}
 const report=files.find(x=>x.name==='acceptance.json');let passed=false;try{passed=exitCode===0&&JSON.parse(report?.bytes.toString('utf8')).passed===true;}catch{}
 const status=neutralStatus({platform,passed,bundleSha,sourceSha,durationMs:Date.now()-started,exitCode});
 const encrypted=sealResults({files,platform,bundleSha,sourceSha},{publicKey,recipientSha});
 await mkdir(outputRoot,{recursive:true});if((await readdir(outputRoot)).length)fail('RESULT_REJECTED');
 const encryptedBytes=Buffer.from(JSON.stringify(encrypted)+'\n'),statusBytes=Buffer.from(JSON.stringify(status)+'\n');
 await writeFile(path.join(outputRoot,'result.enc.json'),encryptedBytes,{flag:'wx',mode:0o600});await writeFile(path.join(outputRoot,'status.json'),statusBytes,{flag:'wx',mode:0o600});
 await verifyPublicOutput({outputRoot,statusBytes,encryptedBytes,status,recipientSha});
 if(githubOutput){await noLinks(githubOutput);if(!(await lstat(githubOutput)).isFile())fail('RESULT_REJECTED');await writeFile(githubOutput,'upload_ready=true\n',{flag:'a'});}return status;
}

async function main(){
 assertWorkflowContext();const publicKey=await readFile(path.resolve('ci/recipient-public.pem'),'utf8');
 const status=await executeProtectedAcceptance({sourcePlan:process.env.SOURCE_PLAN,bundleSha:process.env.BUNDLE_SHA,sourceSha:process.env.SOURCE_SHA,installKeySha:process.env.INSTALL_KEY_SHA,engineDigest:process.env.ENGINE_DIGEST,recipientSha:process.env.RECIPIENT_SHA,publicKey,platform:process.env.EXPECTED_PLATFORM,workRoot:path.resolve('.protected-work'),outputRoot:path.resolve('.protected-public'),githubOutput:process.env.GITHUB_OUTPUT});
 console.log(JSON.stringify(neutralStatus(status)));if(!status.passed)process.exitCode=1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error(publicFailure());process.exitCode=1;});
