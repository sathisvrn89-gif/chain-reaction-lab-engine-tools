"""Build isolated full-quality Godot4.7.2 Android candidates; never export a game.

Linux only. Use a disposable SDK and a fresh work directory for each architecture.
Candidate outputs require installed testing and are not production approvals.
"""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, urllib.request, zipfile
from pathlib import Path

GODOT='ed1daf0bf001b61586d9930840f2f1394092c079'
LLVM='5e96669f06077099aa41290cdb4c5e6fa0f59349'
ANDROID_BUILD='19756bd1d4ffca122636e553ab43b4befe827183'
NDK='29.0.14206865'
FLAGS='-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384'
SWAPPY_SHA='2dd05484de29a3040106658d6f95915778fd71abc3261130eada6090ed1c153d'
ARCHES={'arm64':('arm64-v8a','aarch64-linux-android','aarch64'),
        'x86_64':('x86_64','x86_64-linux-android','x86_64')}

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

class Build:
    def __init__(self, args):
        self.a=args; self.work=args.work.resolve(); self.out=args.output.resolve()
        self.out.mkdir(parents=True, exist_ok=True); self.commands=[]
    def run(self, args, cwd=None):
        args=[str(x) for x in args]; self.commands.append(args)
        log=self.out/f'command-{len(self.commands):03}.log'
        with log.open('w',encoding='utf-8') as f:
            f.write(json.dumps(args)+'\n'); f.flush()
            result=subprocess.run(args,cwd=cwd,stdout=f,stderr=subprocess.STDOUT)
        if result.returncode: raise RuntimeError(f'Command failed: see {log}')
    def source(self, name, url, sha, sparse=None):
        path=self.work/name
        if path.exists(): raise RuntimeError(f'Refusing reused source directory {path}')
        path.mkdir(parents=True); self.run(['git','init',path])
        self.run(['git','remote','add','origin',url],path)
        self.run(['git','fetch','--depth=1','--filter=blob:none','origin',sha],path)
        if sparse:
            self.run(['git','sparse-checkout','init','--cone'],path)
            self.run(['git','sparse-checkout','set',*sparse],path)
        self.run(['git','checkout','--detach','FETCH_HEAD'],path)
        actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=path,text=True).strip()
        if actual!=sha: raise RuntimeError('Exact source SHA mismatch')
        return path
    def notices(self, source, label, include_thirdparty=False):
        destination=self.out/'licenses'/label
        files=[p for p in source.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','COPYRIGHT','COPYING','NOTICE'))]
        if include_thirdparty:
            files.extend(p for p in (source/'thirdparty').rglob('*') if p.is_file() and p.name.upper().startswith(('LICENSE','COPYRIGHT','COPYING','NOTICE')))
        if not files: raise RuntimeError(f'Missing official source notices for {label}')
        for file in files:
            target=destination/file.relative_to(source); target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(file,target)
    def inspect(self, path, tools):
        spec=importlib.util.spec_from_file_location('layout',Path(__file__).with_name('inspect_relro_layout.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        result=module.inspect(path.read_bytes())
        assert result['strict_modulo_passed'], f'Raw RELRO end fails 16KB: {path}'
        assert result['relro'], f'Missing RELRO security protection: {path}'
        assert all(x['alignment']>=16384 and (x['address']-x['offset'])%16384==0 for x in result['load_segments'])
        assert all(not r['writable_section_rounding_hazards'] for r in result['relro'])
        self.run([tools/'llvm-readelf','--program-headers','--sections','--dynamic','--wide',path])
        dynamic=subprocess.check_output([tools/'llvm-readelf','--dynamic','--wide',path],text=True)
        assert f'[{path.name}]' in dynamic and '(SONAME)' in dynamic
        assert 'libunwind.so' not in dynamic and 'libc++abi.so' not in dynamic
        return result
    def native(self):
        abi,triple,processor=ARCHES[self.a.arch]
        sdk=self.a.sdk.resolve(); ndk=sdk/'ndk'/NDK
        tools=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin'; sysroot=tools.parent/'sysroot'
        if not tools.is_dir(): raise RuntimeError('Install the exact pinned NDK first')
        properties=(ndk/'source.properties').read_text(); assert NDK in properties
        self.run([tools/'clang','--version'])
        compiler_version=subprocess.check_output([tools/'clang','--version'],text=True)
        if LLVM not in compiler_version:
            raise RuntimeError('Actual NDK compiler source SHA differs from inspected release templates')
        self.run([tools/'ld.lld','--version'])
        source_info=tools.parent/'clang_source_info.md'
        if not source_info.is_file(): raise RuntimeError('Missing NDK compiler provenance')
        info=source_info.read_text()
        shutil.copy2(source_info,self.out/'clang_source_info.md')
        # Keep auxiliary source-info verbatim. Its omission of the final source
        # SHA does not prove a compiler mismatch: the running compiler's own
        # --version must identify the pinned patched source SHA.
        (self.out/'compiler-provenance.json').write_text(json.dumps({
            'expected_source_sha':LLVM,'compiler_version':compiler_version,
            'source_info_sha256':digest(source_info),'source_sha_in_source_info':LLVM in info},indent=2))
        llvm=self.source('llvm','https://android.googlesource.com/toolchain/llvm-project',LLVM,
                         ['libcxx','libcxxabi','libunwind','runtimes','cmake','llvm','third-party'])
        for component in ['libcxx','libcxxabi','libunwind']:
            self.notices(llvm/component,component)
        # Public installed NDK compiler/sysroot; preserve Android DeviceLibcxxBuilder
        # ABI options without bootstrapping the entire compiler toolchain.
        # Linux system avoids CMake's independent NDK detection; ANDROID activates
        # libc++ Android configuration. Targets and sysroot remain explicit Android.
        cflags='-ffunction-sections -fdata-sections -D__BIONIC_NO_PAGE_SIZE_MACRO -flto=thin -ffat-lto-objects'
        ldflags=f'-nostdlib++ -rtlib=compiler-rt -unwindlib=libunwind -flto=thin -Wl,-z,defs -Wl,--gc-sections -Wl,--build-id=sha1 {FLAGS}'
        build=self.work/'runtime-build'
        opts={
            'CMAKE_SYSTEM_NAME':'Linux','ANDROID':'1','ANDROID_NATIVE_API_LEVEL':'21',
            'CMAKE_SYSTEM_PROCESSOR':processor,'CMAKE_BUILD_TYPE':'RelWithDebInfo',
            'CMAKE_C_COMPILER':tools/'clang','CMAKE_CXX_COMPILER':tools/'clang++',
            'CMAKE_C_COMPILER_TARGET':triple+'21','CMAKE_CXX_COMPILER_TARGET':triple+'21',
            'CMAKE_SYSROOT':sysroot,'CMAKE_AR':tools/'llvm-ar','CMAKE_RANLIB':tools/'llvm-ranlib',
            'CMAKE_C_FLAGS':cflags,'CMAKE_CXX_FLAGS':cflags+' -DHAS_THREAD_LOCAL',
            'CMAKE_SHARED_LINKER_FLAGS':ldflags,'CMAKE_EXE_LINKER_FLAGS':ldflags,
            'LLVM_ENABLE_RUNTIMES':'libcxx;libcxxabi','LLVM_INCLUDE_TESTS':'OFF',
            'LIBCXX_INCLUDE_TESTS':'OFF','LIBCXXABI_INCLUDE_TESTS':'OFF',
            'LIBCXXABI_ENABLE_SHARED':'OFF','LIBCXXABI_USE_LLVM_UNWINDER':'OFF',
            'LIBCXX_ENABLE_SHARED':'ON','LIBCXX_ENABLE_STATIC':'ON',
            'LIBCXX_ENABLE_EXCEPTIONS':'ON','LIBCXXABI_ENABLE_EXCEPTIONS':'ON',
            'LIBCXX_ENABLE_ABI_LINKER_SCRIPT':'OFF','LIBCXX_ENABLE_STATIC_ABI_LIBRARY':'ON',
            'LIBCXX_STATICALLY_LINK_ABI_IN_SHARED_LIBRARY':'ON',
            'LIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY':'OFF',
            'LIBCXX_SHARED_OUTPUT_NAME':'c++_shared','LIBCXX_STATIC_OUTPUT_NAME':'c++_static',
            'LIBCXX_ABI_VERSION':'1','LIBCXX_ABI_NAMESPACE':'__ndk1',
        }
        (self.out/'runtime-cmake-options.json').write_text(json.dumps({k:str(v) for k,v in opts.items()},indent=2))
        self.run(['cmake','-G','Ninja','-S',llvm/'runtimes','-B',build,*[f'-D{k}={v}' for k,v in opts.items()]])
        self.run(['cmake','--build',build,'--target','cxx_shared','--parallel',self.a.jobs,'--verbose'])
        candidates=list(build.rglob('libc++_shared.so'))
        assert len(candidates)==1, f'Ambiguous runtime outputs: {candidates}'
        runtime=candidates[0]; baseline=sysroot/'usr/lib'/triple/'libc++_shared.so'
        def symbols(p):
            text=subprocess.check_output([tools/'llvm-readelf','--dyn-syms','--wide',p],text=True)
            return {line.split()[7].split('@')[0] for line in text.splitlines()
                    if len(line.split())>=8 and line.split()[4] in ('GLOBAL','WEAK') and line.split()[6]!='UND'}
        missing=sorted(symbols(baseline)-symbols(runtime))
        (self.out/'runtime-export-comparison.json').write_text(json.dumps({'missing_original_exports':missing},indent=2))
        assert not missing, 'Rebuilt libc++ removed original exports; candidate rejected'
        shutil.copy2(baseline,self.out/'original-libc++_shared.so')
        shutil.copy2(runtime,baseline) # only this job's disposable NDK
        runtime_sha=digest(baseline)
        for name in ['CMakeCache.txt','build.ninja']:
            shutil.copy2(build/name,self.out/('runtime-'+name))
        # Keep complete flags/logs and source pins, then free this disposable
        # runtime checkout before the larger engine build on a standard runner.
        for disposable in [llvm,build]:
            assert disposable.resolve().is_relative_to(self.work) and disposable.resolve()!=self.work
            shutil.rmtree(disposable)
        # The static unwinder is from the exact NDK29, as in Android's official
        # DeviceLibcxxBuilder. It is linked into the newly linked shared runtime;
        # no additional shared unwind library is shipped.
        godot=self.source('godot','https://github.com/godotengine/godot.git',GODOT)
        self.notices(godot,'godot',include_thirdparty=True)
        swappy_archive=self.out/'godot-swappy.zip'
        urllib.request.urlretrieve('https://github.com/godotengine/godot-swappy/releases/download/from-source-2025-01-31/godot-swappy.zip',swappy_archive)
        assert digest(swappy_archive)==SWAPPY_SHA, 'Official Swappy archive digest changed'
        with zipfile.ZipFile(swappy_archive) as z:
            for swappy_abi in ['arm64-v8a','armeabi-v7a','x86','x86_64']:
                dest=godot/'thirdparty/swappy-frame-pacing'/swappy_abi/'libswappy_static.a'
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(z.read(swappy_abi+'/libswappy_static.a'))
        swappy=godot/'thirdparty/swappy-frame-pacing'/abi/'libswappy_static.a'
        os.environ['ANDROID_HOME']=str(sdk)
        options=['platform=android','target=template_release',f'arch={self.a.arch}',
                 'ndk_platform=android-24','production=yes','dev_build=no','optimize=speed',
                 'debug_symbols=no','lto=none','swappy=yes','opengl3=yes','vulkan=yes',
                 'module_jolt_physics_enabled=yes',f'linkflags={FLAGS}']
        self.run(['scons',f'-j{self.a.jobs}','verbose=yes',*options],godot)
        libs=godot/'platform/android/java/lib/libs/release'/abi
        target=self.out/'native'/abi; target.mkdir(parents=True)
        results={}
        for name in ['libgodot_android.so','libc++_shared.so']:
            shutil.copy2(libs/name,target/name)
            results[name]=self.inspect(target/name,tools)
        assert digest(target/'libc++_shared.so')==runtime_sha
        receipt={'candidate_only':True,'godot_source':GODOT,'llvm_source':LLVM,
                 'android_build_reference':ANDROID_BUILD,'ndk':NDK,'abi':abi,
                 'runtime_api':21,'engine_api':24,'page_link_flags':FLAGS,
                 'engine_options':options,'swappy_archive_sha256':SWAPPY_SHA,'swappy_sha256':digest(swappy),'native':results,
                 'commands':self.commands,'runtime_16kb_verified':False,'game_exported':False}
        (self.out/'native-build-receipt.json').write_text(json.dumps(receipt,indent=2))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arch',choices=ARCHES,required=True)
    p.add_argument('--sdk',type=Path,required=True)
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--jobs',type=int,default=2)
    a=p.parse_args()
    if sys.platform!='linux': p.error('Use a disposable Linux x86_64 build host')
    if a.work.exists(): p.error('Work directory must not exist; use a fresh isolated path')
    if not 1<=a.jobs<=8:p.error('Jobs must be1–8')
    if not os.access(a.sdk,os.W_OK):p.error('SDK must be disposable and writable')
    a.work.mkdir(parents=True)
    build=Build(a)
    try: build.native()
    finally: (build.out/'commands.json').write_text(json.dumps(build.commands,indent=2))

if __name__=='__main__':main()
