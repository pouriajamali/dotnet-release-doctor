"""Execute only the extracted Doctor apphost, against fresh synthetic metadata."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--local-candidate',action='store_true');a=p.parse_args()
 package=a.package.resolve();work=a.work.resolve();work.mkdir(parents=True,exist_ok=False)
 m=json.loads((package/'BUILD-MANIFEST.json').read_text());assert m['sourceCommit']==a.commit and m['selfContained'] and m['originalLicense']=='present'
 assert m['rid']==('win-x64' if os.name=='nt' else 'linux-x64')
 if not a.local_candidate:assert not m['localCandidate']
 expected={f['path'] for f in m['files']}|{'BUILD-MANIFEST.json'};actual={f.relative_to(package).as_posix() for f in package.rglob('*') if f.is_file()};assert actual==expected
 for item in m['files']:
  f=package/item['path'];assert not f.is_symlink() and f.stat().st_size==item['bytes'] and sha(f)==item['sha256']
 assert a.commit.encode() in (package/'doctor.dll').read_bytes() and (package/'LICENSE').read_text().startswith('MIT License')
 config=json.loads((package/'doctor.runtimeconfig.json').read_text())['runtimeOptions'];assert 'includedFrameworks' in config and 'frameworks' not in config
 exe=package/('doctor.exe' if os.name=='nt' else 'doctor');assert exe.is_file()
 assert exe.read_bytes()[:2]==b'MZ' if os.name=='nt' else exe.read_bytes()[:4]==b'\x7fELF'
 env=dict(os.environ,DOTNET_ROOT=str(work/'no-dotnet-install'),DOTNET_ROOT_X64=str(work/'no-dotnet-install'),DOTNET_MULTILEVEL_LOOKUP='0');checks=[]
 def run(name,args,code):
  r=subprocess.run([str(exe),*map(str,args)],cwd=work,env=env,text=True,capture_output=True,timeout=90)
  (work/(name+'.json')).write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'command':[str(exe),*map(str,args)]},indent=2)+'\n',encoding='utf-8')
  assert r.returncode==code and not r.stderr,(name,r.returncode,r.stderr);checks.append(name);return r
 assert m['version'] in run('version',['--version'],0).stdout
 demo=work/'demo with spaces';assert 'DEMO PASS' in run('demo',['demo',demo],0).stdout
 for name,code in [('valid',0),('missing-config',1),('duplicate-json',2),('wrong-rid',2),('changed-inventory',2)]:
  r=json.loads((demo/(name+' report')/'summary.json').read_text());assert r['exitCode']==code and r['inputProvenance']=='UNVERIFIED' and r['startup']=='NOT_EXECUTED' and r['installedRuntime']=='NOT_CHECKED' and r['safety']=='NOT_ASSESSED'
  text=(demo/(name+' report')/'report.txt').read_text();assert str(work) not in json.dumps(r) and str(work) not in text and '>=' not in text
  checks.append('report-'+name)
 target=demo/'valid';before={f.name:sha(f) for f in target.iterdir() if f.is_file()}
 r=json.loads(run('inspect',['inspect',target,work/'single report','--entry','Sample.dll','--rid',m['rid'],'--manifest','BUILD-MANIFEST.json','--expected-version',m['version']],0).stdout);assert r['complete'] and r['outcome']=='pass' and r['managedArchitecture'] in {'anycpu','x64'}
 assert before=={f.name:sha(f) for f in target.iterdir() if f.is_file()};checks.append('target-content-preserved')
 existing=work/'existing';existing.mkdir();(existing/'sentinel').write_text('untouched')
 r=json.loads(run('existing-report',['inspect',target,existing,'--entry','Sample.dll','--rid',m['rid']],1).stdout);assert r['reason']=='OUTPUT_EXISTS' and (existing/'sentinel').read_text()=='untouched'
 r=json.loads(run('expected-version',['inspect',target,work/'wrong version report','--entry','Sample.dll','--rid',m['rid'],'--expected-version','9.9.9'],2).stdout);assert r['reason']=='EXPECTED_VERSION_MISMATCH'
 changed=work/'changed inventory';shutil.copytree(target,changed);(changed/'Sample.runtimeconfig.json').write_text((changed/'Sample.runtimeconfig.json').read_text()+' ')
 r=json.loads(run('changed-inventory',['inspect',changed,work/'changed report','--entry','Sample.dll','--rid',m['rid'],'--manifest','BUILD-MANIFEST.json'],2).stdout);assert r['reason']=='INVENTORY_MISMATCH'
 scd=work/'unsupported self-contained';shutil.copytree(target,scd);(scd/'Sample.runtimeconfig.json').write_text('{"runtimeOptions":{"includedFrameworks":[]}}')
 r=json.loads(run('self-contained-target',['inspect',scd,work/'unsupported report','--entry','Sample.dll','--rid',m['rid']],1).stdout);assert not r['complete'] and r['reason']=='SELF_CONTAINED_UNSUPPORTED'
 r=json.loads(run('no-target-execution-option',['--execute','not-a-command'],1).stdout);assert r['reason']=='CLI_INVALID'
 assert len(checks)==14
 receipt={'status':'ACTUAL_SELF_CONTAINED_DOCTOR_PACKAGE_PASS','commit':a.commit,'rid':m['rid'],'checkCount':len(checks),'checks':checks,'manifestSha256':sha(package/'BUILD-MANIFEST.json'),'scope':'Own shipped apphost/metadata child; synthetic metadata-only targets; existing host, not clean OS; no target startup, runtime compatibility or malicious-PE safety proof.'}
 (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':receipt['status'],'checks':len(checks),'rid':m['rid']}))
if __name__=='__main__':main()
