"""Assemble candidate templates from two verified source-built native artifacts."""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, zipfile
from pathlib import Path
from build_android_16kb_engine import GODOT, LLVM, NDK, FLAGS

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ['inputs','work','sdk','output']:p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args(); a.output=a.output.resolve(); a.output.mkdir(parents=True,exist_ok=True)
    if a.work.exists():p.error('Refusing to reuse build directory')
    sources={}; receipts={}
    for arch,abi in [('arm64','arm64-v8a'),('x86_64','x86_64')]:
        folder=a.inputs/f'engine16kb-{arch}'
        r=json.loads((folder/'native-build-receipt.json').read_text())
        assert (r['godot_source'],r['llvm_source'],r['ndk'],r['page_link_flags'])==(GODOT,LLVM,NDK,FLAGS)
        assert r['abi']==abi
        receipts[abi]=r
        notices=folder/'licenses'
        assert notices.is_dir(), 'Official source notices missing'
        shutil.copytree(notices,a.output/'licenses'/abi,dirs_exist_ok=True)
        for name in ['libgodot_android.so','libc++_shared.so']:
            file=folder/'native'/abi/name
            assert sha(file)==r['native'][name]['sha256']
            sources[f'lib/{abi}/{name}']=file
    a.work.mkdir(parents=True)
    def run(args,cwd=None):
        with (a.output/'assembly.log').open('a') as f:
            f.write(json.dumps([str(x) for x in args])+'\n');f.flush()
            subprocess.run([str(x) for x in args],cwd=cwd,stdout=f,stderr=subprocess.STDOUT,check=True)
    run(['git','init',a.work]);run(['git','remote','add','origin','https://github.com/godotengine/godot.git'],a.work)
    run(['git','fetch','--depth=1','origin',GODOT],a.work);run(['git','checkout','--detach','FETCH_HEAD'],a.work)
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.work,text=True).strip()==GODOT
    for n,source in sources.items():
        target=a.work/'platform/android/java/lib/libs/release'/Path(n).relative_to('lib')
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
    os.environ['ANDROID_HOME']=str(a.sdk.resolve())
    gradle=a.work/'platform/android/java/gradlew';gradle.chmod(0o755)
    run([gradle.resolve(),'generateGodotTemplates','-PdoNotStrip=true','--no-daemon','--console=plain'],gradle.parent)
    products=['android_release.apk','android_source.zip','godot-lib.template_release.aar']
    hashes={}
    for name in products:
        source=a.work/'bin'/name; assert source.is_file(),f'Missing expected product {name}'
        shutil.copy2(source,a.output/name);hashes[name]=sha(a.output/name)
    # Preserve exact source-built native bytes; verify again after packaging.
    spec=importlib.util.spec_from_file_location('layout',Path(__file__).with_name('inspect_relro_layout.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    alignment={}
    with zipfile.ZipFile(a.output/'android_release.apk') as z:
        names={n for n in z.namelist() if n.endswith('.so')}
        assert names==set(sources),f'Unexpected native libraries: {names}'
        for name in names:
            result=module.inspect(z.read(name)); assert result['strict_modulo_passed'] and result['relro']
            assert all(x['alignment']>=16384 and (x['address']-x['offset'])%16384==0 for x in result['load_segments'])
            assert all(not r['writable_section_rounding_hazards'] for r in result['relro'])
            result['input_sha256']=sha(sources[name]);result['packaged_bytes_identical']=result['sha256']==result['input_sha256']
            assert result['packaged_bytes_identical'], f'Gradle replaced or altered native bytes: {name}'
            alignment[name]=result
    run([a.sdk/'build-tools/36.1.0/zipalign','-c','-P','16','-v','4',a.output/'android_release.apk'])
    report={'candidate_only':True,'godot_source':GODOT,'llvm_source':LLVM,'ndk':NDK,
            'products':hashes,'packaged_native':alignment,'native_receipts':receipts,
            'strict_native_alignment_verified':True,'runtime_16kb_verified':False,
            'game_exported':False,'production_signing_used':False}
    (a.output/'template-build-receipt.json').write_text(json.dumps(report,indent=2))

if __name__=='__main__':main()
