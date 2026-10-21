import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const fail = message => { throw new Error(message); };
const read = file => fs.readFileSync(file, 'utf8');
const json = file => JSON.parse(read(file));
const write = (file, value) => { fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, value); };
const save = (file, value) => write(file, JSON.stringify(value, null, 2) + '\n');
const run = (command, args, options = {}) => execFileSync(command, args, {encoding:'utf8', maxBuffer:64*1024*1024, ...options}).trim();
const git = (...args) => run('git', args);
const gh = (...args) => run('gh', args);
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const shaPattern = /^[a-f0-9]{40}$/;
const reserved = ['release-integrity.json', 'release-integrity.sig'];

export function semver(version) {
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(version);
  if (!m || m[4]?.split('.').some(x => /^\d+$/.test(x) && x.length > 1 && x[0] === '0')) fail(`Invalid canonical SemVer: ${version}`);
  return {numbers:m.slice(1,4).map(BigInt), pre:m[4]?.split('.') ?? []};
}
export function compare(a, b) {
  const x=semver(a), y=semver(b);
  for(let i=0;i<3;i++) if(x.numbers[i]!==y.numbers[i]) return x.numbers[i]>y.numbers[i]?1:-1;
  if(!x.pre.length || !y.pre.length) return x.pre.length===y.pre.length?0:!x.pre.length?1:-1;
  for(let i=0;i<Math.max(x.pre.length,y.pre.length);i++) {
    const p=x.pre[i], q=y.pre[i];
    if(p===undefined || q===undefined) return p===q?0:p===undefined?-1:1;
    if(p===q) continue;
    const pn=/^\d+$/.test(p), qn=/^\d+$/.test(q);
    if(pn && qn) return BigInt(p)>BigInt(q)?1:-1;
    if(pn!==qn) return pn?-1:1;
    return p>q?1:-1;
  }
  return 0;
}
export function safePath(value, flat=false) {
  if(typeof value!=='string' || !value || value.includes('\\') || value.includes('\0') || /[\r\n]/.test(value) || path.posix.isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.split('/').some(x=>!x||x==='.'||x==='..') || (flat && value.includes('/'))) fail(`Unsafe path: ${value}`);
  return value;
}
const expand = (value, app, version) => value.replaceAll('{app}',app).replaceAll('{version}',version);
const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const expandPattern = (value, app, version) => expand(value,escapeRegex(app),escapeRegex(version));
const get = (value, key) => key.split('.').reduce((v,k)=>v?.[k],value);
function versionValue(entry, reader) {
  safePath(entry.path);
  const content=reader(entry.path);
  if(entry.format==='json' && typeof entry.key==='string') return get(JSON.parse(content),entry.key);
  if(entry.format==='text' && typeof entry.pattern==='string') {
    const matches=[...content.matchAll(new RegExp(entry.pattern,'gm'))];
    if(matches.length!==1 || !matches[0].groups?.version) fail(`Expected one named version capture: ${entry.path}`);
    return matches[0].groups.version;
  }
  fail(`Invalid versionFiles entry: ${entry.path}`);
}
export function validate(manifest, config, reader=read) {
  if(!object(manifest) || manifest.schemaVersion!==1 || !object(manifest.apps) || !Object.keys(manifest.apps).length) fail('Invalid release.json');
  if(!object(config) || config.schemaVersion!==1 || !object(config.apps) || !['every-main-change','affected-only'].includes(config.bumpPolicy)) fail('Invalid .release/config.json');
  const ids=Object.keys(manifest.apps).sort();
  if(Object.values(config.apps).filter(c=>c.legacyLatest).length>1)fail('Only one primary app can retain the latest-release alias');
  if(JSON.stringify(ids)!==JSON.stringify(Object.keys(config.apps).sort())) fail('Manifest/config app IDs differ');
  const prefixes=[];
  for(const id of ids) {
    const app=manifest.apps[id], c=config.apps[id];
    if(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id) || !object(app) || typeof app.title!=='string' || !app.title.trim() || /[\r\n]/.test(app.title)) fail(`Invalid app: ${id}`);
    semver(app.version);
    if(!object(c) || typeof c.tagPrefix!=='string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(c.tagPrefix) || c.tagPrefix.includes('..')) fail(`Invalid tagPrefix: ${id}`);
    if(prefixes.some(p=>p===c.tagPrefix || (p.startsWith(c.tagPrefix)&&/^\d/.test(p.slice(c.tagPrefix.length))) || (c.tagPrefix.startsWith(p)&&/^\d/.test(c.tagPrefix.slice(p.length))))) fail(`Overlapping tag namespace: ${id}`);
    prefixes.push(c.tagPrefix);
    if(!Array.isArray(c.paths) || !c.paths.length || c.paths.some(p=>typeof p!=='string' || (p!=='**' && (!p || p.includes('..') || /[\\\[\]?]/.test(p) || p.replace(/\/\*\*$/,'').includes('*'))))) fail(`Invalid paths: ${id}`);
    if(!Array.isArray(c.versionFiles) || !Array.isArray(c.assets) || !c.assets.length) fail(`Missing versionFiles/assets: ${id}`);
    const assets=c.assets.map(a=>safePath(expand(a,id,app.version),true));
    if(new Set(assets).size!==assets.length || assets.some(a=>reserved.includes(a) || a===(c.checksumFile??'SHA256SUMS.txt'))) fail(`Duplicate/reserved assets: ${id}`);
    safePath(c.checksumFile??'SHA256SUMS.txt',true);
    for(const rule of c.optionalAssets??[]) {
      if(!object(rule)||typeof rule.pattern!=='string'||!rule.pattern.startsWith('^')||!rule.pattern.endsWith('$')||!Number.isInteger(rule.min)||!Number.isInteger(rule.max)||rule.min<0||rule.max<rule.min)fail(`Invalid bounded asset rule: ${id}`);
      new RegExp(expandPattern(rule.pattern,id,app.version));
    }
    safePath(expand(c.notes,id,app.version));
    if(c.notesAsset && !assets.includes(safePath(c.notesAsset,true)))fail(`Additional notes must be a required asset: ${id}`);
    if(!['standard','strict'].includes(c.security)) fail(`Unknown security profile: ${id}`);
    if(c.security==='strict') {
      safePath(c.publicKey);
      if(crypto.createPublicKey(reader(c.publicKey)).asymmetricKeyType!=='ed25519') fail(`Expected Ed25519 public key: ${id}`);
    }
    for(const file of c.versionFiles) if(versionValue(file,reader)!==app.version) fail(`Embedded version differs for ${id}: ${file.path}`);
  }
  return true;
}
function matches(file, scope) { return scope==='**' || (scope.endsWith('/**')?file.startsWith(scope.slice(0,-2)):file===scope); }
export function checkAdvances(base, previousConfig, proposed, config, changed) {
  if(!base) return;
  for(const id of Object.keys(base.apps)) {
    if(!proposed.apps[id]) fail(`App removal needs a migration: ${id}`);
    const delta=compare(proposed.apps[id].version,base.apps[id].version);
    if(delta<0) fail(`Version decreased: ${id}`);
    const infrastructure=changed.some(f=>f==='.release/config.json'||f.startsWith('.github/workflows/'));
    const affected=changed.filter(f=>f!=='release.json' && (!f.startsWith('.release/notes/') || f.startsWith(`.release/notes/${id}/`))).some(f=>[...(previousConfig.apps[id]?.paths??[]),...(config.apps[id]?.paths??[])].some(p=>matches(f,p)));
    if((infrastructure||affected) && delta<=0) fail(`Advance ${id} for the changed source/workflows`);
  }
  if(previousConfig.bumpPolicy==='every-main-change' && changed.length && !Object.keys(proposed.apps).some(id=>!base.apps[id]||compare(proposed.apps[id].version,base.apps[id].version)>0)) fail('Every main change requires a version advance');
}
export function select(manifest, config, releases, channel='stable', requested='') {
  if(!['stable','preview'].includes(channel)) fail(`Invalid channel: ${channel}`);
  if(requested && !manifest.apps[requested]) fail(`Unknown app: ${requested}`);
  const selected=[], skipped=[];
  for(const [id,app] of Object.entries(manifest.apps)) {
    if(requested && requested!==id) continue;
    const c=config.apps[id]; const preview=semver(app.version).pre.length>0;
    if(preview!==(channel==='preview')) {skipped.push({app:id,version:app.version,reason:'other channel'});continue;}
    const versions=releases.filter(r=>!r.draft && r.tag_name.startsWith(c.tagPrefix)).flatMap(r=>{
      const v=r.tag_name.slice(c.tagPrefix.length);try{const parsed=semver(v);return channel==='stable'&&(parsed.pre.length||r.prerelease)?[]:[v];}catch{return [];}
    });
    const latest=versions.sort(compare).at(-1);
    if(latest && compare(app.version,latest)<0) fail(`${id} ${app.version} is behind published ${latest}`);
    if(latest && compare(app.version,latest)===0) {skipped.push({app:id,version:app.version,reason:'already published'});continue;}
    selected.push({app:id,title:app.title,version:app.version,tag:c.tagPrefix+app.version,security:c.security,since:latest??null});
  }
  return {selected,skipped};
}
// One line per app, so a dispatch that releases nothing says why instead of skipping every job.
export function describe(selection, channel) {
  const why={
    'other channel':s=>channel==='stable'?`${s.version} is a pre-release; commit the release version to main, or dispatch the preview channel`:`${s.version} is not a pre-release; dispatch the stable channel`,
    'already published':s=>`${s.version} is already published; advance the version to release again`
  };
  return [...selection.selected.map(s=>`${s.app}: releasing ${s.tag} on the ${channel} channel`),...selection.skipped.map(s=>`${s.app}: skipped, ${why[s.reason]?.(s)??s.reason}`)];
}
// The notes of every version after `since` (the latest published one) up to the release, newest
// first: versions advance on every main change, and only some of them are released.
export function notesFor(app, manifest, config, since=null) {
  const version=manifest.apps[app].version, c=config.apps[app];
  const wanted=v=>{try{return compare(v,version)<=0 && (since===null || compare(v,since)>0);}catch{return false;}};
  let parts=[];
  if(c.notesSection) {
    const file=expand(c.notes,app,version), content=read(file);
    const headings=[...content.matchAll(/^##\s+\[?v?([^\s\]]+)\]?[^\r\n]*$/gm)];
    headings.forEach((h,i)=>{if(wanted(h[1]))parts.push({version:h[1],heading:h[0],body:content.slice(h.index+h[0].length,headings[i+1]?.index??content.length).trim()});});
    if(!parts.some(p=>p.version===version)) fail(`Missing ${version} changelog section in ${file}`);
  } else {
    const template=expand(c.notes,app,'\0'), dir=path.posix.dirname(template), pieces=path.posix.basename(template).split('\0');
    if(dir.includes('\0') || pieces.length>2)fail(`{version} must appear at most once, in the notes file name: ${c.notes}`);
    const [prefix,suffix]=pieces;
    const versions=suffix===undefined?[version]:fs.readdirSync(dir).filter(n=>n.startsWith(prefix)&&n.endsWith(suffix)&&n.length>prefix.length+suffix.length).map(n=>n.slice(prefix.length,n.length-suffix.length)).filter(wanted);
    if(!versions.includes(version)) fail(`Missing release notes: ${expand(c.notes,app,version)}`);
    parts=versions.map(v=>({version:v,body:read(expand(c.notes,app,v)).trim()}));
  }
  parts.sort((a,b)=>compare(b.version,a.version));
  for(const p of parts) if(!p.body || /DESCRIBE_CHANGES|TODO_RELEASE_NOTES/.test(p.body)) fail(`Write real release notes for ${app} ${p.version}`);
  return parts.length===1?parts[0].body:parts.map(p=>p.heading?`${p.heading}\n\n${p.body}`:p.body).join('\n\n');
}
export async function hashFile(file) {
  const hash=crypto.createHash('sha256');
  for await(const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
async function inventory(app, manifest, config, bundle, sha) {
  const c=config.apps[app]; const version=manifest.apps[app].version;
  if(!shaPattern.test(sha)) fail('An exact source SHA is required');
  const assets=c.assets.map(a=>expand(a,app,version));
  const checksum=c.checksumFile??'SHA256SUMS.txt';
  if(fs.existsSync(path.join(bundle,checksum)) && !fs.lstatSync(path.join(bundle,checksum)).isFile())fail('Checksum must be a regular file');
  const found=fs.readdirSync(bundle).filter(n=>n!==checksum).sort();
  for(const rule of c.optionalAssets??[]) {
    const re=new RegExp(expandPattern(rule.pattern,app,version));
    const matched=found.filter(n=>!assets.includes(n)&&!reserved.includes(n)&&re.test(n));
    if(matched.length<rule.min||matched.length>rule.max||(rule.allOrNone&&matched.length!==0&&matched.length!==rule.max))fail(`Incomplete bounded asset group for ${app}: ${rule.pattern}`);
    assets.push(...matched);
  }
  const expected=[...assets,...(c.security==='strict'?reserved:[])].sort();
  if(JSON.stringify(found)!==JSON.stringify(expected)) fail(`Asset set differs for ${app}; expected ${expected.join(', ')}; found ${found.join(', ')}`);
  for(const name of found) {
    safePath(name,true);const stat=fs.lstatSync(path.join(bundle,name));
    if(!stat.isFile() || stat.size===0) fail(`Asset must be a nonempty regular file: ${name}`);
  }
  const files={}; for(const name of assets.sort()) files[name]=await hashFile(path.join(bundle,name));
  return {schemaVersion:1,app,version,sourceSha:sha,files};
}
export async function verifyBundle(app, manifest, config, bundle, sha) {
  const inv=await inventory(app,manifest,config,bundle,sha);
  if(config.apps[app].security==='strict') {
    const bytes=fs.readFileSync(path.join(bundle,reserved[0]));
    if(!crypto.verify(null,bytes,read(config.apps[app].publicKey),fs.readFileSync(path.join(bundle,reserved[1])))) fail('Invalid release inventory signature');
    if(JSON.stringify(JSON.parse(bytes))!==JSON.stringify(inv)) fail('Signed inventory identity/hashes differ');
  }
  return inv;
}
export async function signBundle(app, manifest, config, bundle, sha, privateKey) {
  if(config.apps[app].security!=='strict') fail('Signing requires the strict profile');
  // Existing signature files must never enter the payload inventory.
  const unsigned={...config,apps:{...config.apps,[app]:{...config.apps[app],security:'standard'}}};
  const inv=await inventory(app,manifest,unsigned,bundle,sha);
  const bytes=Buffer.from(JSON.stringify(inv,null,2)+'\n');
  const signature=crypto.sign(null,bytes,privateKey);
  if(!crypto.verify(null,bytes,read(config.apps[app].publicKey),signature)) fail('Signing key does not match public key');
  write(path.join(bundle,reserved[0]),bytes);write(path.join(bundle,reserved[1]),signature);
  return inv;
}
function api(endpoint) { return JSON.parse(gh('api',endpoint)); }
function repoName() {
  const repo=process.env.GITHUB_REPOSITORY;
  if(!repo || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) fail('GITHUB_REPOSITORY must be owner/repo');
  return repo;
}
function releaseList(repo) {
  const all=[];for(let page=1;;page++) {const entries=api(`repos/${repo}/releases?per_page=100&page=${page}`);all.push(...entries);if(entries.length<100)return all;}
}
function tagTarget(repo,tag) {
  // Listing refs distinguishes absence from authentication/network failure.
  const refs=api(`repos/${repo}/git/matching-refs/tags/${encodeURIComponent(tag)}`);
  const ref=refs.find(r=>r.ref===`refs/tags/${tag}`);if(!ref)return null;
  let object=ref.object;
  for(let depth=0;object.type==='tag'&&depth<10;depth++)object=api(`repos/${repo}/git/tags/${object.sha}`).object;
  if(object.type!=='commit')fail('Tag does not resolve to a commit');
  return object.sha;
}
export async function publish(plan, app, manifest, config, bundle, client) {
  const selected=plan.selected.find(a=>a.app===app);
  if(!selected || !shaPattern.test(plan.sourceSha))fail('App is absent from the captured release plan');
  const c=config.apps[app], m=manifest.apps[app];
  if(selected.version!==m.version || selected.tag!==c.tagPrefix+m.version || selected.security!==c.security || selected.title!==m.title)fail('Plan differs from captured manifest/config');
  const releases=client.releases();
  const chosen=select(manifest,config,releases,plan.channel,app).selected;
  if(!chosen.length)fail('Version is already published');
  const notes=notesFor(app,manifest,config,chosen[0].since);
  if(selected.notes!==notes)fail('Release notes differ from captured plan');
  const inv=await verifyBundle(app,manifest,config,bundle,plan.sourceSha);
  const checksum=c.checksumFile??'SHA256SUMS.txt';
  const files=Object.keys(inv.files).concat(c.security==='strict'?reserved:[]).sort();
  const sums={};for(const name of files)sums[name]=await hashFile(path.join(bundle,name));
  const checksumNames=files.filter(n=>!(c.checksumExclusions??[]).includes(n));
  const checksumPath=path.join(bundle,checksum);
  if(c.preserveChecksum && fs.existsSync(checksumPath)) {
    const stat=fs.lstatSync(checksumPath);if(!stat.isFile()||!stat.size)fail('Invalid pre-signed checksum file');
    const entries=read(checksumPath).trim().split(/\r?\n/).map(line=>{
      const m=/^([a-fA-F0-9]{64}) [ *](.+)$/.exec(line);if(!m)fail('Invalid checksum line');return [m[2],m[1].toLowerCase()];
    });
    if(entries.length!==checksumNames.length || new Set(entries.map(e=>e[0])).size!==entries.length || entries.some(([n,h])=>!checksumNames.includes(n)||sums[n]!==h))fail('Existing checksum does not cover the complete final payload');
  } else write(checksumPath,checksumNames.map(n=>`${sums[n]}  ${n}`).join('\n')+'\n');
  sums[checksum]=await hashFile(path.join(bundle,checksum));files.push(checksum);
  let existing=releases.find(r=>r.tag_name===selected.tag);
  if(existing && !existing.draft)fail('Never replace a published release');
  let target=client.tagTarget(selected.tag);
  if(target && target!==plan.sourceSha)fail('Existing tag points to different source');
  if(existing && (!target || existing.body?.includes(`<!-- release-source:${plan.sourceSha} -->`)!==true))fail('Draft is not bound to this original source');
  let publishedNotes=notes;
  if(c.notesAsset) {
    safePath(c.notesAsset,true);
    if(!Object.hasOwn(inv.files,c.notesAsset))fail('Additional release notes must be part of the verified payload');
    publishedNotes+='\n\n'+read(path.join(bundle,c.notesAsset)).trim();
  }
  if(!target)client.createTag(selected.tag,plan.sourceSha);
  if(existing)client.updateDraft?.(selected,plan,publishedNotes);
  if(!existing)existing=client.createDraft(selected,plan,publishedNotes);
  const unexpected=(existing.assets??[]).filter(a=>!files.includes(a.name));
  if(unexpected.length)fail('Draft contains unexpected assets; inspect it before retrying');
  client.upload(selected.tag,files.map(f=>path.join(bundle,f)));
  const uploaded=client.getRelease(selected.tag);
  if(!uploaded.draft)fail('Release became public before verification');
  if(JSON.stringify(uploaded.assets.map(a=>a.name).sort())!==JSON.stringify([...files].sort()))fail('Uploaded asset set differs');
  for(const asset of uploaded.assets)if(asset.digest!==`sha256:${sums[asset.name]}` || asset.size!==fs.statSync(path.join(bundle,asset.name)).size)fail(`Uploaded digest/size differs: ${asset.name}`);
  if(client.tagTarget(selected.tag)!==plan.sourceSha)fail('Tag changed during upload');
  client.publish(selected,plan,Boolean(c.legacyLatest && plan.channel==='stable'));
  return selected.tag;
}
// GET releases/tags/{tag} only returns published releases, so a draft has to be found in the list.
// The list can lag a release created moments ago, so a lookup that expects one waits and tries again.
const LIST_WAITS=[1000,2000,4000,8000];
const pause=ms=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,ms);
function releaseByTag(repo, tag, waits=[]) {
  for(let i=0;;i++) {
    const release=releaseList(repo).find(r=>r.tag_name===tag);
    if(release)return release;
    if(i>=waits.length)fail(`No release found for ${tag}`);
    pause(waits[i]);
  }
}
export function githubClient(repo) {
  return {
    releases:()=>releaseList(repo),tagTarget:tag=>tagTarget(repo,tag),
    createTag:(tag,sha)=>gh('api',`repos/${repo}/git/refs`,'-X','POST','-f',`ref=refs/tags/${tag}`,'-f',`sha=${sha}`),
    createDraft:(selected,plan,notes)=>{
      const file=path.join(process.env.RUNNER_TEMP??'.release-tmp',`notes-${selected.app}.md`);
      write(file,notes+`\n\n<!-- release-source:${plan.sourceSha} -->\n`);
      gh('release','create',selected.tag,'--repo',repo,'--verify-tag','--draft','--title',`${selected.title} ${selected.version}`,'--notes-file',file,'--latest=false',...(plan.channel==='preview'?['--prerelease']:[]));
      return releaseByTag(repo,selected.tag,LIST_WAITS);
    },
    updateDraft:(selected,plan,notes)=>{
      const file=path.join(process.env.RUNNER_TEMP??'.release-tmp',`notes-${selected.app}.md`);
      write(file,notes+`\n\n<!-- release-source:${plan.sourceSha} -->\n`);
      gh('release','edit',selected.tag,'--repo',repo,'--title',`${selected.title} ${selected.version}`,'--notes-file',file);
    },
    upload:(tag,files)=>gh('release','upload',tag,...files,'--repo',repo,'--clobber'),
    getRelease:tag=>releaseByTag(repo,tag),
    publish:(selected,plan,latest)=>gh('release','edit',selected.tag,'--repo',repo,'--draft=false',`--prerelease=${plan.channel==='preview'}`,`--latest=${latest}`)
  };
}
function load() {const manifest=json('release.json'),config=json('.release/config.json');validate(manifest,config);return {manifest,config};}
function output(name,value) {if(process.env.GITHUB_OUTPUT)fs.appendFileSync(process.env.GITHUB_OUTPUT,`${name}=${typeof value==='string'?value:JSON.stringify(value)}\n`);}
export async function cli(args) {
  const command=args.shift(), options={};for(let i=0;i<args.length;i+=2){if(!args[i].startsWith('--')||args[i+1]===undefined)fail('Options require --name value');options[args[i].slice(2)]=args[i+1];}
  const {manifest,config}=load();
  if(command==='validate') {
    const base=options.base??process.env.BASE_SHA;
    if(base && !/^0+$/.test(base)) {
      if(!shaPattern.test(base))fail('Invalid validation base SHA');
      // A first adoption is permitted only when the base tree lacks release.json.
      const names=git('ls-tree','--name-only',base).split('\n');
      if(names.includes('release.json')) {
        const old=JSON.parse(git('show',`${base}:release.json`));const oldConfig=JSON.parse(git('show',`${base}:.release/config.json`));
        const changed=git('diff','--name-only',base,'HEAD').split('\n').filter(Boolean);
        checkAdvances(old,oldConfig,manifest,config,changed);
      }
    }
    return;
  }
  if(command==='bump') {
    const id=options.app;if(!manifest.apps[id])fail('Choose an app with --app');
    const previous=manifest.apps[id].version,p=semver(previous);
    let next=options.version;
    if(!next) {const n=p.numbers;const kind=options.kind??'patch';if(!['major','minor','patch'].includes(kind))fail('Invalid bump kind');const index=['major','minor','patch'].indexOf(kind);n[index]++;for(let i=index+1;i<3;i++)n[i]=0n;next=n.join('.');}
    if(compare(next,previous)<=0)fail('A bump must advance precedence');
    for(const entry of config.apps[id].versionFiles) {
      if(entry.format==='json') {const value=json(entry.path);const keys=entry.key.split('.'),last=keys.pop();let obj=value;for(const key of keys)obj=obj[key];obj[last]=next;save(entry.path,value);}
      else {const re=new RegExp(entry.pattern,'gm');write(entry.path,read(entry.path).replace(re,(match,...rest)=>match.replace(rest.at(-1).version,next)));}
    }
    manifest.apps[id].version=next;save('release.json',manifest);
    const c=config.apps[id];if(!c.notesSection){const file=expand(c.notes,id,next);if(!fs.existsSync(file))write(file,`# ${manifest.apps[id].title} ${next}\n\nDESCRIBE_CHANGES\n`);}
    else {
      // A new section above the newest one, for the change that needs this version.
      const file=expand(c.notes,id,next),text=read(file),at=text.search(/^## /m),entry=`## ${next}\n\nDESCRIBE_CHANGES\n`;
      write(file,at<0?text.trimEnd()+'\n\n'+entry:text.slice(0,at)+entry+'\n'+text.slice(at));
    }
    return;
  }
  if(command==='plan') {
    if(process.env.GITHUB_REF!=='refs/heads/main')fail('Release must be dispatched from main');
    const repo=repoName(),sourceSha=git('rev-parse','HEAD');
    if(sourceSha!==process.env.GITHUB_SHA)fail('Checkout differs from dispatch source SHA');
    const channel=options.channel??'stable';const selection=select(manifest,config,releaseList(repo),channel,options.app??'');
    const plan={schemaVersion:1,repository:repo,sourceSha,channel,...selection};
    const lines=describe(selection,channel);console.log(lines.join('\n'));
    if(process.env.GITHUB_STEP_SUMMARY)fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,`### Release plan\n\n${lines.map(l=>`- ${l}`).join('\n')}\n`);
    if(!plan.selected.length)fail(`Nothing to release on the ${channel} channel:\n${lines.join('\n')}`);
    for(const item of plan.selected)item.notes=notesFor(item.app,manifest,config,item.since);
    save('release-plan.json',plan);output('selected',String(plan.selected.length>0));output('sha',sourceSha);
    const apps={};for(const [id,m]of Object.entries(manifest.apps))apps[id]={...m,tag:config.apps[id].tagPrefix+m.version,selected:plan.selected.some(x=>x.app===id)};
    output('apps',apps);output('matrix',{include:plan.selected});
    return;
  }
  const id=options.app,bundle=options.bundle??'release-bundle';if(!manifest.apps[id])fail('Choose an app with --app');
  const sha=options.sha??process.env.RELEASE_SOURCE_SHA??git('rev-parse','HEAD');
  if(command==='stage') {
    const c=config.apps[id],version=manifest.apps[id].version;
    const exact=new Set(c.assets.map(a=>expand(a,id,version)));
    if(c.preserveChecksum)exact.add(c.checksumFile??'SHA256SUMS.txt');
    const rules=(c.optionalAssets??[]).map(r=>new RegExp(expandPattern(r.pattern,id,version)));
    if(fs.existsSync(bundle))fail('Use a fresh empty destination for staging');
    fs.mkdirSync(bundle,{recursive:true});
    const walk=async directory=>{
      for(const name of fs.readdirSync(directory)) {
        const file=path.join(directory,name),stat=fs.lstatSync(file);
        if(stat.isDirectory())await walk(file);
        else if(exact.has(name)||rules.some(r=>r.test(name))) {
          if(!stat.isFile())fail(`Refuse non-regular staged asset: ${file}`);
          const dest=path.join(bundle,name);
          if(fs.existsSync(dest)){if(await hashFile(dest)!==await hashFile(file))fail(`Conflicting artifact filename: ${name}`);}
          else fs.copyFileSync(file,dest);
        }
      }
    };
    await walk(options.from??'artifacts');
    const unsigned={...config,apps:{...config.apps,[id]:{...c,security:'standard'}}};
    await verifyBundle(id,manifest,unsigned,bundle,sha);
  }
  else if(command==='verify')await verifyBundle(id,manifest,config,bundle,sha);
  else if(command==='sign')await signBundle(id,manifest,config,bundle,sha,process.env.RELEASE_SIGNING_KEY_PEM??fail('Missing RELEASE_SIGNING_KEY_PEM'));
  else if(command==='publish') {
    const plan=json(options.plan??'release-plan.json');const repo=repoName();
    if(plan.repository!==repo || git('rev-parse','HEAD')!==plan.sourceSha || sha!==plan.sourceSha)fail('Repository/checkout differs from release plan');
    await publish(plan,id,manifest,config,bundle,githubClient(repo));
  } else fail(`Unknown command: ${command}`);
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url))cli(process.argv.slice(2)).catch(error=>{console.error(error.message);process.exitCode=1;});
