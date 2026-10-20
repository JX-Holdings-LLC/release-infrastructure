import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {compare,semver,validate,checkAdvances,select,verifyBundle,signBundle,publish,hashFile,safePath} from '../src/release.mjs';

const source='a'.repeat(40);
function fixture(strict=false) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'release-system-'));
  const manifest={schemaVersion:1,apps:{app:{title:'Example',version:'1.2.3'}}};
  const config={schemaVersion:1,bumpPolicy:'every-main-change',apps:{app:{tagPrefix:'v',paths:['src/**'],versionFiles:[],notes:'notes.md',assets:['app-{version}.zip'],security:strict?'strict':'standard'}}};
  fs.writeFileSync(path.join(root,'notes.md'),'A concrete change.\n');
  if(strict){const pair=crypto.generateKeyPairSync('ed25519');config.apps.app.publicKey='key.pem';fs.writeFileSync(path.join(root,'key.pem'),pair.publicKey.export({type:'spki',format:'pem'}));return {root,manifest,config,pair};}
  return {root,manifest,config};
}
function withRoot(f,fn) {const old=process.cwd();process.chdir(f.root);return Promise.resolve().then(fn).finally(()=>{process.chdir(old);fs.rmSync(f.root,{recursive:true,force:true});});}
function payload(root){const bundle=path.join(root,'bundle');fs.mkdirSync(bundle);fs.writeFileSync(path.join(bundle,'app-1.2.3.zip'),'final packaged bytes');return bundle;}

test('numeric SemVer and prerelease precedence',()=>{
  assert.equal(compare('0.10.0','0.9.0'),1);
  const ordered=['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta','1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0'];
  for(let i=1;i<ordered.length;i++)assert.equal(compare(ordered[i-1],ordered[i]),-1);
  assert.equal(compare('999999999999999999999.0.0','999999999999999999998.0.0'),1);
  for(const v of ['v1.0.0','01.0.0','1.0.0-01','1.0.0+build.1','1.0','1.0.0-'])assert.throws(()=>semver(v));
});
test('path traversal and unsafe asset paths fail',()=>{
  for(const v of ['../file','a/../file','/file','C:/file','a\\file','a\nfile','a//file'])assert.throws(()=>safePath(v));
  assert.throws(()=>safePath('dir/file',true));
});
test('shape, IDs, profiles, prefixes and reserved assets are validated',async()=>{
  const f=fixture();await withRoot(f,()=>{
    assert.equal(validate(f.manifest,f.config),true);
    for(const mutate of [c=>c.apps.app.security='unknown',c=>c.apps.app.assets=['../x'],c=>c.apps.app.assets=['SHA256SUMS.txt'],c=>c.apps.app.paths=[],c=>c.apps.other={...c.apps.app}]) {
      const c=structuredClone(f.config);mutate(c);assert.throws(()=>validate(f.manifest,c));
    }
  });
});
test('embedded JSON and named text versions must agree',async()=>{
  const f=fixture();await withRoot(f,()=>{
    fs.writeFileSync('package.json',JSON.stringify({version:'1.2.3'}));fs.writeFileSync('VERSION','1.2.3\n');
    f.config.apps.app.versionFiles=[{path:'package.json',format:'json',key:'version'},{path:'VERSION',format:'text',pattern:'^(?<version>[^\\r\\n]+)$'}];
    validate(f.manifest,f.config);fs.appendFileSync('VERSION','1.2.3\n');assert.throws(()=>validate(f.manifest,f.config),/one named/);
    fs.writeFileSync('VERSION','1.2.4\n');assert.throws(()=>validate(f.manifest,f.config),/Embedded version/);
  });
});
test('source advances, docs advances, no scope/policy bypass, and no removal',()=>{
  const f=fixture();const next=structuredClone(f.manifest);next.apps.app.version='1.2.4';
  checkAdvances(f.manifest,f.config,next,f.config,['src/app.js']);
  assert.throws(()=>checkAdvances(f.manifest,f.config,f.manifest,f.config,['README.md']),/Every main/);
  const narrow=structuredClone(f.config);narrow.bumpPolicy='affected-only';narrow.apps.app.paths=['other/**'];
  assert.throws(()=>checkAdvances(f.manifest,f.config,f.manifest,narrow,['src/app.js']),/Advance app/);
  assert.throws(()=>checkAdvances(f.manifest,f.config,{apps:{}},f.config,['README.md']),/removal/);
  assert.throws(()=>checkAdvances(next,f.config,f.manifest,f.config,[]),/decreased/);
  fs.rmSync(f.root,{recursive:true,force:true});
});
test('selection ignores drafts, isolates namespaces/channels, refuses downgrades',()=>{
  const f=fixture();const releases=[{tag_name:'v1.2.2',draft:false},{tag_name:'v9.0.0',draft:true},{tag_name:'agent-v9.0.0',draft:false},{tag_name:'v2.0.0-rc.1',draft:false,prerelease:true}];
  assert.equal(select(f.manifest,f.config,releases).selected.length,1);
  assert.equal(select(f.manifest,f.config,[{tag_name:'v1.2.3'}]).selected.length,0);
  assert.throws(()=>select(f.manifest,f.config,[{tag_name:'v1.2.4'}]),/behind/);
  f.manifest.apps.app.version='1.2.3-rc.1';assert.throws(()=>select(f.manifest,f.config,[{tag_name:'v1.2.3'}],'preview'),/behind/);
  assert.equal(select(f.manifest,f.config,[],'stable').selected.length,0);
  fs.rmSync(f.root,{recursive:true,force:true});
});
test('independent manifest advances do not force unrelated apps to bump',()=>{
  const f=fixture();const m=structuredClone(f.manifest),c=structuredClone(f.config);
  m.apps.agent={title:'Agent',version:'1.2.3'};c.apps.agent={...c.apps.app,tagPrefix:'agent-v',paths:['agent/**']};
  const next=structuredClone(m);next.apps.agent.version='1.2.4';
  checkAdvances(m,c,next,c,['release.json','agent/VERSION','.release/notes/agent/1.2.4.md']);
  fs.rmSync(f.root,{recursive:true,force:true});
});
test('a primary v namespace can coexist with vendor package namespaces',async()=>{
  const f=fixture();await withRoot(f,()=>{
    f.manifest.apps.vendor={title:'Vendor',version:'0.1.0'};
    f.config.apps.vendor={...f.config.apps.app,tagPrefix:'vendor-v'};
    validate(f.manifest,f.config);
    f.config.apps.vendor.tagPrefix='v';assert.throws(()=>validate(f.manifest,f.config),/namespace/);
  });
});
test('exact complete bundle rejects missing, extra, empty and symbolic assets',async()=>{
  const f=fixture();const bundle=payload(f.root);
  await verifyBundle('app',f.manifest,f.config,bundle,source);
  fs.writeFileSync(path.join(bundle,'extra'),'x');await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/Asset set/);fs.unlinkSync(path.join(bundle,'extra'));
  fs.truncateSync(path.join(bundle,'app-1.2.3.zip'));await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/nonempty/);
  fs.unlinkSync(path.join(bundle,'app-1.2.3.zip'));fs.symlinkSync('../notes.md',path.join(bundle,'app-1.2.3.zip'));await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/regular/);
  fs.rmSync(f.root,{recursive:true,force:true});
});
test('strict signatures bind app, version, source, and all payload bytes',async()=>{
  const f=fixture(true);await withRoot(f,async()=>{
    const bundle=payload(f.root);await signBundle('app',f.manifest,f.config,bundle,source,f.pair.privateKey);
    await verifyBundle('app',f.manifest,f.config,bundle,source);
    await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,'b'.repeat(40)),/identity/);
    fs.appendFileSync(path.join(bundle,'app-1.2.3.zip'),'tampered');await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/identity/);
    fs.writeFileSync('key.pem',crypto.generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'}));await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/signature/);
  });
});
test('bounded alternatives enforce whole groups and treat versions literally',async()=>{
  const f=fixture(),bundle=payload(f.root);
  f.config.apps.app.optionalAssets=[{pattern:'^extra-{version}-(?:one|two)\\.zip$',min:0,max:2,allOrNone:true}];
  fs.writeFileSync(path.join(bundle,'extra-1.2.3-one.zip'),'one');
  await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/Incomplete/);
  fs.writeFileSync(path.join(bundle,'extra-1.2.3-two.zip'),'two');
  await verifyBundle('app',f.manifest,f.config,bundle,source);
  fs.writeFileSync(path.join(bundle,'extra-1x2x3-one.zip'),'wrong');
  await assert.rejects(verifyBundle('app',f.manifest,f.config,bundle,source),/Asset set/);
  fs.rmSync(f.root,{recursive:true,force:true});
});
test('pre-signed checksums retain their bytes only with complete final coverage',async()=>{
  const f=fixture();await withRoot(f,async()=>{
    const bundle=payload(f.root),plan={sourceSha:source,channel:'stable',selected:[{app:'app',title:'Example',version:'1.2.3',tag:'v1.2.3',security:'standard',notes:'A concrete change.'}]};
    f.config.apps.app.preserveChecksum=true;
    const bytes=(await hashFile(path.join(bundle,'app-1.2.3.zip')))+'  app-1.2.3.zip\r\n';
    fs.writeFileSync(path.join(bundle,'SHA256SUMS.txt'),bytes);
    await publish(plan,'app',f.manifest,f.config,bundle,fakeClient(plan));
    assert.equal(fs.readFileSync(path.join(bundle,'SHA256SUMS.txt'),'utf8'),bytes);
    fs.appendFileSync(path.join(bundle,'app-1.2.3.zip'),'changed');
    await assert.rejects(publish(plan,'app',f.manifest,f.config,bundle,fakeClient(plan)),/checksum/);
  });
});
function fakeClient(plan) {
  let tag=null, release=null; const calls=[];
  return {calls,releases:()=>release?[release]:[],tagTarget:()=>tag,createTag:(t,s)=>{calls.push('tag');tag=s;},
    createDraft:(item,p)=>{calls.push('draft');release={tag_name:item.tag,draft:true,body:`<!-- release-source:${p.sourceSha} -->`,assets:[]};return release;},
    upload:(_tag,files)=>{calls.push('upload');release.assets=files.map(file=>({name:path.basename(file),size:fs.statSync(file).size,digest:'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}));},
    getRelease:()=>release,publish:()=>{calls.push('publish');release.draft=false;},
    setTag:sha=>{tag=sha;},setRelease:r=>{release=r;}
  };
}
test('publication stages all files and checks remote digests before exposure',async()=>{
  const f=fixture();await withRoot(f,async()=>{
    const bundle=payload(f.root);const plan={sourceSha:source,channel:'stable',selected:[{app:'app',title:'Example',version:'1.2.3',tag:'v1.2.3',security:'standard',notes:'A concrete change.'}]};
    const c=fakeClient(plan);assert.equal(await publish(plan,'app',f.manifest,f.config,bundle,c),'v1.2.3');assert.deepEqual(c.calls,['tag','draft','upload','publish']);
    fs.unlinkSync(path.join(bundle,'SHA256SUMS.txt'));await assert.rejects(publish(plan,'app',f.manifest,f.config,bundle,c),/published/);
  });
});
test('publication refuses retargets, wrong plans, unexpected draft assets, and bad remote digests',async()=>{
  const f=fixture();await withRoot(f,async()=>{
    const plan={sourceSha:source,channel:'stable',selected:[{app:'app',title:'Example',version:'1.2.3',tag:'v1.2.3',security:'standard',notes:'A concrete change.'}]};
    for(const scenario of ['retarget','plan','extra','digest']) {
      const dir=path.join(f.root,scenario);fs.mkdirSync(dir);fs.writeFileSync(path.join(dir,'app-1.2.3.zip'),'bytes');const c=fakeClient(plan),p=structuredClone(plan);
      if(scenario==='retarget')c.setTag('b'.repeat(40));
      if(scenario==='plan')p.selected[0].security='strict';
      if(scenario==='extra'){c.setTag(source);c.setRelease({draft:true,tag_name:'v1.2.3',body:`<!-- release-source:${source} -->`,assets:[{name:'untrusted'}]});}
      if(scenario==='digest'){const upload=c.upload;c.upload=(...args)=>{upload(...args);c.getRelease().assets[0].digest='sha256:wrong';};}
      await assert.rejects(publish(p,'app',f.manifest,f.config,dir,c));assert.ok(!c.calls.includes('publish'));
    }
  });
});
test('original-source draft retries work after interrupted upload',async()=>{
  const f=fixture();await withRoot(f,async()=>{
    const bundle=payload(f.root),plan={sourceSha:source,channel:'stable',selected:[{app:'app',title:'Example',version:'1.2.3',tag:'v1.2.3',security:'standard',notes:'A concrete change.'}]};
    const c=fakeClient(plan),upload=c.upload;c.upload=()=>{throw new Error('interrupted');};
    await assert.rejects(publish(plan,'app',f.manifest,f.config,bundle,c),/interrupted/);assert.equal(c.getRelease().draft,true);
    fs.unlinkSync(path.join(bundle,'SHA256SUMS.txt'));c.upload=upload;
    await publish(plan,'app',f.manifest,f.config,bundle,c);assert.equal(c.getRelease().draft,false);
  });
});
test('CLI validates real Git base comparisons and synchronizes patch bumps',async()=>{
  const f=fixture();await withRoot(f,()=>{
    const cli=path.resolve(import.meta.dirname,'../src/release.mjs');
    fs.mkdirSync('.release');fs.writeFileSync('release.json',JSON.stringify(f.manifest));fs.writeFileSync('.release/config.json',JSON.stringify(f.config));
    const git=(...args)=>execFileSync('git',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
    git('init','-q');git('config','user.email','test@example.invalid');git('config','user.name','Test');git('add','.');git('commit','-qm','initial');const base=git('rev-parse','HEAD');
    execFileSync(process.execPath,[cli,'bump','--app','app']);fs.writeFileSync('notes.md','A patch.');git('add','.');git('commit','-qm','patch');execFileSync(process.execPath,[cli,'validate','--base',base]);
    assert.equal(JSON.parse(fs.readFileSync('release.json')).apps.app.version,'1.2.4');
    const unbumped=git('rev-parse','HEAD');fs.writeFileSync('README.md','docs');git('add','.');git('commit','-qm','docs');assert.throws(()=>execFileSync(process.execPath,[cli,'validate','--base',unbumped],{stdio:'pipe'}));
  });
});
