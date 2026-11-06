using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text.Json;
using ReleaseDoctor;

internal static class Program
{
    private static int Passed,Failed,Skipped,Index;
    private static string Root="",FixtureRoot="",AnyCpuAssembly="",FixtureRid="win-x64";
    private static readonly List<object> Observations=[];
    [DllImport("libc",SetLastError=true)] private static extern int mkfifo(string path,uint mode);
    private static void Require(bool value,string message="Expectation failed") {if(!value) throw new InvalidOperationException(message);}
    private static string Next(string label)=>Path.Combine(Root,(++Index).ToString("D3")+" "+label);
    private static async Task Case(string name,Func<Task> body)
    {
        try {await body();Passed++;Console.WriteLine("PASS "+name);Observations.Add(new{name,result="pass"});}
        catch(Exception e){Failed++;Console.WriteLine("FAIL "+name+" "+e.GetType().Name+" "+e.Message);Observations.Add(new{name,result="fail",error=e.GetType().Name,message=e.Message});}
    }
    private static string Target()
    {
        string p=Next("target");Demo.Fixture(p,AnyCpuAssembly);return p;
    }
    private static Task<Report> Inspect(string target,string rid="win-x64",string? manifest=null,string? expected=null,TestHooks? hooks=null,string entry="Sample.dll")=>Inspection.Run(target,Next("report"),entry,rid,manifest,expected,hooks);
    private static async Task Expect(string target,int code,string reason,string? manifest=null,TestHooks? hooks=null)
    {var r=await Inspect(target,manifest:manifest,hooks:hooks);Require(r.ExitCode==code && r.Reason==reason,$"Expected {code}/{reason}, got {r.ExitCode}/{r.Reason}");Require(code!=1||!r.Complete);}
    private static void Runtime(string target,string json)=>File.WriteAllText(Path.Combine(target,"Sample.runtimeconfig.json"),json);
    private static byte[] NativePe(bool x64=true)
    {
        byte[] b=new byte[512];b[0]=(byte)'M';b[1]=(byte)'Z';BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(60),128);"PE\0\0"u8.CopyTo(b.AsSpan(128));
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(132),(ushort)(x64?0x8664:0x14c));BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(148),(ushort)(x64?240:224));
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(152),(ushort)(x64?0x20b:0x10b));BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(152+(x64?108:92)),16);return b;
    }
    private static byte[] Elf(int machine=62,int @class=2,int endian=1)
    {
        byte[] b=new byte[64];b[0]=0x7f;b[1]=(byte)'E';b[2]=(byte)'L';b[3]=(byte)'F';b[4]=(byte)@class;b[5]=(byte)endian;b[6]=1;
        void U16(int offset,ushort value){if(endian==1)BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(offset),value);else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(offset),value);}
        U16(16,3);U16(18,(ushort)machine);U16(@class==2?52:40,(ushort)(@class==2?64:52));
        if(endian==1)BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(20),1);else BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(20),1);return b;
    }
    private static void Flags(string target,int add)
    {
        string p=Path.Combine(target,"Sample.dll");byte[] b=File.ReadAllBytes(p);int offset;
        using(var pe=new PEReader(new MemoryStream(b)))offset=pe.PEHeaders.CorHeaderStartOffset+16;
        int flags=BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(offset));BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(offset),flags|add);File.WriteAllBytes(p,b);
    }
    private static ProcessStartInfo Self(string mode)
    {
        string host=Environment.ProcessPath!;var start=new ProcessStartInfo(host);
        if(Path.GetFileNameWithoutExtension(host).Equals("dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add(mode);return start;
    }
    public static async Task<int> Main(string[] args)
    {
        // In-process API tests run under the test apphost. Its owned child dispatches
        // the exact production worker entry; this test-only host is never packaged.
        if(args.Length>0 && args[0]=="--metadata-worker") return await ReleaseDoctor.Program.Main(args);
        if(args.Length==1 && args[0].StartsWith("--probe-",StringComparison.Ordinal))
        {
            switch(args[0])
            {
                case "--probe-hang":await Task.Delay(30_000);return 0;
                case "--probe-stdout":Console.Write(new string('x',100_000));return 0;
                case "--probe-stderr":Console.Error.Write(new string('x',100_000));return 0;
                case "--probe-exit":return 17;
            }
        }
        for(int i=0;i<args.Length;i+=2)
        {
            if(i+1>=args.Length) return 2;
            if(args[i]=="--work")Root=Path.GetFullPath(args[i+1]);
            else if(args[i]=="--fixture")FixtureRoot=Path.GetFullPath(args[i+1]);
            else if(args[i]=="--anycpu")AnyCpuAssembly=Path.GetFullPath(args[i+1]);
            else if(args[i]=="--fixture-rid")FixtureRid=args[i+1];else return 2;
        }
        if(Root.Length==0 || FixtureRoot.Length==0 || Directory.Exists(Root) || !File.Exists(AnyCpuAssembly) || !File.Exists(Path.Combine(FixtureRoot,"Tripwire.dll")) || FixtureRid is not ("win-x64" or "linux-x64")) return 2;
        Directory.CreateDirectory(Root);
        await Case("valid-anycpu-optional-checks-visible",async()=>
        {
            var r=await Inspect(Target());Require(r.ExitCode==0 && r.Complete && r.ManagedArchitecture=="anycpu");
            Require(r.Frameworks.Single().DeclaredVersion=="10.0.14" && r.Checks.Count(c=>c.Code=="NOT_SELECTED")==2 && r.InputProvenance=="UNVERIFIED" && r.Startup=="NOT_EXECUTED");
        });
        await Case("real-x64-fdd-tripwire-entry-apphost-not-executed",async()=>
        {
            string p=Next("tripwire");Directory.CreateDirectory(p);
            foreach(string f in Directory.EnumerateFiles(FixtureRoot))File.Copy(f,Path.Combine(p,Path.GetFileName(f)),false);
            var before=Snapshot.Capture(p);var r=await Inspect(p,rid:FixtureRid,entry:"Tripwire.dll");Require(r.ExitCode==0 && r.ManagedArchitecture=="x64",r.Reason);before.Recheck();
            Require(!Directory.EnumerateFiles(Root,"TRIPWIRE_ENTRY_EXECUTED",SearchOption.AllDirectories).Any() && !File.Exists(Path.Combine(Environment.CurrentDirectory,"TRIPWIRE_ENTRY_EXECUTED")));
        });
        await Case("expected-version-release-part-with-build-metadata",async()=>{var r=await Inspect(Target(),expected:"0.1.0-preview.1+ignored-external-build");Require(r.ExitCode==0);});
        await Case("expected-version-mismatch",async()=>{var r=await Inspect(Target(),expected:"9.0.0");Require(r.ExitCode==2&&r.Reason=="EXPECTED_VERSION_MISMATCH");});
        foreach(string suffix in new[]{"dll","runtimeconfig.json","deps.json"})await Case("missing-"+suffix,async()=>{string p=Target();File.Delete(Path.Combine(p,"Sample."+suffix));var r=await Inspect(p);Require(r.ExitCode==1&&!r.Complete);});
        foreach(var item in new[]{
            ("malformed-json","{",2,"JSON_INVALID"),
            ("duplicate-json","{\"runtimeOptions\":{},\"runtimeOptions\":{}}",2,"JSON_DUPLICATE_PROPERTY"),
            ("duplicate-nested","{\"runtimeOptions\":{\"framework\":{\"name\":\"a\",\"name\":\"b\"}}}",2,"JSON_DUPLICATE_PROPERTY"),
            ("self-contained","{\"runtimeOptions\":{\"includedFrameworks\":[]}}",1,"SELF_CONTAINED_UNSUPPORTED"),
            ("ambiguous-framework","{\"runtimeOptions\":{\"framework\":{},\"frameworks\":[]}}",1,"FRAMEWORK_DECLARATION_UNSUPPORTED"),
            ("custom-framework","{\"runtimeOptions\":{\"framework\":{\"name\":\"Private.Framework\",\"version\":\"10.0.14\"}}}",1,"CUSTOM_FRAMEWORK_UNSUPPORTED"),
            ("custom-policy","{\"runtimeOptions\":{\"rollForward\":\"execute-this\",\"framework\":{}}}",1,"ROLL_FORWARD_UNSUPPORTED")})
            await Case(item.Item1,async()=>{string p=Target();Runtime(p,item.Item2);await Expect(p,item.Item3,item.Item4);});
        await Case("roll-forward-disable-is-declaration-not-host-compatibility",async()=>
        {
            string p=Target();string path=Path.Combine(p,"Sample.runtimeconfig.json");File.WriteAllText(path,File.ReadAllText(path).Replace("\"tfm\"","\"rollForward\":\"Disable\",\"tfm\""));
            var r=await Inspect(p);Require(r.ExitCode==0&&r.Frameworks[0].RollForward=="Disable"&&r.InstalledRuntime=="NOT_CHECKED");
        });
        await Case("two-framework-declarations",async()=>
        {
            string p=Target();Runtime(p,"{\"runtimeOptions\":{\"frameworks\":[{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.14\"},{\"name\":\"Microsoft.AspNetCore.App\",\"version\":\"10.0.14\"}]}}");var r=await Inspect(p);Require(r.ExitCode==0&&r.Frameworks.Count==2);
        });
        await Case("declared-apply-patches-not-silently-ignored",async()=>{string p=Target(),f=Path.Combine(p,"Sample.runtimeconfig.json");File.WriteAllText(f,File.ReadAllText(f).Replace("\"tfm\"","\"applyPatches\":false,\"tfm\""));var r=await Inspect(p);Require(r.ExitCode==0&&r.Frameworks[0].RollForward.Contains("applyPatches=false")&&r.InstalledRuntime=="NOT_CHECKED");});
        await Case("legacy-roll-forward-unsupported",async()=>{string p=Target(),f=Path.Combine(p,"Sample.runtimeconfig.json");File.WriteAllText(f,File.ReadAllText(f).Replace("\"tfm\"","\"rollForwardOnNoCandidateFx\":2,\"tfm\""));await Expect(p,1,"LEGACY_ROLL_FORWARD_UNSUPPORTED");});
        await Case("duplicate-framework",async()=>
        {
            string p=Target();Runtime(p,"{\"runtimeOptions\":{\"frameworks\":[{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.14\"},{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.14\"}]}}");await Expect(p,2,"DUPLICATE_FRAMEWORK");
        });
        await Case("deps-wrong-rid",async()=>{string p=Target(),f=Path.Combine(p,"Sample.deps.json");File.WriteAllText(f,File.ReadAllText(f).Replace("win-x64","linux-x64"));await Expect(p,2,"DEPS_RID_MISMATCH");});
        await Case("deps-missing-entry-runtime-asset",async()=>{string p=Target(),f=Path.Combine(p,"Sample.deps.json");File.WriteAllText(f,File.ReadAllText(f).Replace("Sample.dll","Other.dll"));await Expect(p,2,"ENTRY_RUNTIME_ASSET_MISSING");});
        await Case("deps-duplicate-property",async()=>{string p=Target();File.WriteAllText(Path.Combine(p,"Sample.deps.json"),"{\"runtimeTarget\":{},\"runtimeTarget\":{}}");await Expect(p,2,"JSON_DUPLICATE_PROPERTY");});
        foreach(var item in new[]{("requires32",2,2,"ENTRY_32BIT_REQUIRED"),("prefers32",131072,1,"ENTRY_32BIT_PREFERRED")})
            await Case(item.Item1,async()=>{string p=Target();Flags(p,item.Item2);await Expect(p,item.Item3,item.Item4);});
        await Case("non-managed-entry-unsupported-not-corrupt",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"Sample.dll"),NativePe());await Expect(p,1,"ENTRY_NOT_MANAGED_UNSUPPORTED");});
        await Case("benign-truncated-entry",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"Sample.dll"),[77,90,0,0]);await Expect(p,2,"ENTRY_METADATA_INVALID");});
        await Case("native-pe64-header-golden",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"native.bin"),NativePe());var r=await Inspect(p);Require(r.ExitCode==0&&r.ObservedNativeHeaders==1);});
        await Case("native-pe32-rid-mismatch",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"native.bin"),NativePe(false));await Expect(p,2,"NATIVE_RID_MISMATCH");});
        await Case("native-elf-wrong-os",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"native.bin"),Elf());await Expect(p,2,"NATIVE_RID_MISMATCH");});
        foreach(var item in new[]{("elf64-golden",62,2,1,0),("elf32-golden",3,1,1,2),("elf-arm64-golden",183,2,1,2),("elf-big-endian-golden",62,2,2,2)})
            await Case(item.Item1,async()=>
            {
                string p=Target(),d=Path.Combine(p,"Sample.deps.json");File.WriteAllText(d,File.ReadAllText(d).Replace("win-x64","linux-x64"));File.WriteAllBytes(Path.Combine(p,"native.bin"),Elf(item.Item2,item.Item3,item.Item4));
                var r=await Inspect(p,"linux-x64");Require(r.ExitCode==item.Item5 && (item.Item5==0?r.ObservedNativeHeaders==1:r.Reason=="NATIVE_RID_MISMATCH"));
            });
        await Case("native-truncated-header",async()=>{string p=Target();File.WriteAllBytes(Path.Combine(p,"native.bin"),[0x7f,69,76,70,2,1,1]);await Expect(p,2,"ELF_HEADER_INVALID");});
        foreach(int offset in new[]{20,52})await Case("native-elf-bad-header-field-"+offset,async()=>{string p=Target();byte[] bytes=Elf();bytes[offset]=0;File.WriteAllBytes(Path.Combine(p,"native.bin"),bytes);await Expect(p,2,"ELF_HEADER_INVALID");});
        await Case("inventory-valid-exact-self-exemption",async()=>{string p=Target();Demo.Manifest(p);var r=await Inspect(p,manifest:"BUILD-MANIFEST.json");Require(r.ExitCode==0&&r.Checks.Last().Code=="INVENTORY_AGREES_NOT_AUTHENTICATED");});
        await Case("inventory-extra-file",async()=>{string p=Target();Demo.Manifest(p);File.WriteAllText(Path.Combine(p,"extra.txt"),"extra");await Expect(p,2,"INVENTORY_MISMATCH","BUILD-MANIFEST.json");});
        await Case("inventory-changed-hash",async()=>{string p=Target();Demo.Manifest(p);File.AppendAllText(Path.Combine(p,"Sample.runtimeconfig.json")," ");await Expect(p,2,"INVENTORY_MISMATCH","BUILD-MANIFEST.json");});
        foreach(var item in new[]{("duplicate-path",0),("unsafe-path",1),("self-reference",2),("case-colliding-path",3),("wrong-type-size",4)})
            await Case("inventory-"+item.Item1,async()=>
            {
                string p=Target();Demo.Manifest(p);string f=Path.Combine(p,"BUILD-MANIFEST.json");var doc=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(f))!;var files=doc["files"]!.AsArray();
                if(item.Item2==0)files.Add(files[0]!.DeepClone());
                if(item.Item2==1)files[0]!["path"]="../outside";
                if(item.Item2==2)files[0]!["path"]="BUILD-MANIFEST.json";
                if(item.Item2==3){var clone=files[0]!.DeepClone();clone["path"]=clone["path"]!.GetValue<string>().ToUpperInvariant();files.Add(clone);}
                if(item.Item2==4)files[0]!["bytes"]="wrong";
                File.WriteAllText(f,doc.ToJsonString());var r=await Inspect(p,manifest:"BUILD-MANIFEST.json");Require(r.ExitCode!=0&&!r.Checks.Last().Status.Equals("pass"));
            });
        await Case("inventory-unknown-path-no-wildcard-exemption",async()=>{string p=Target();Demo.Manifest(p);File.WriteAllText(Path.Combine(p,"OTHER-MANIFEST.json"),"{}");await Expect(p,2,"INVENTORY_MISMATCH","BUILD-MANIFEST.json");});
        foreach(var item in new[]{("version","9.0.0","MANIFEST_VERSION_MISMATCH"),("rid","linux-x64","MANIFEST_RID_MISMATCH")})
            await Case("manifest-declared-"+item.Item1+"-mismatch",async()=>{string p=Target();Demo.Manifest(p);string f=Path.Combine(p,"BUILD-MANIFEST.json");var doc=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(f))!;doc[item.Item1]=item.Item2;File.WriteAllText(f,doc.ToJsonString());await Expect(p,2,item.Item3,"BUILD-MANIFEST.json");});
        await Case("late-file-change",async()=>{string p=Target();await Expect(p,1,"INPUT_CHANGED",hooks:new(){BeforeRecheck=()=>File.AppendAllText(Path.Combine(p,"Sample.runtimeconfig.json")," ")});});
        await Case("late-added-file",async()=>{string p=Target();await Expect(p,1,"INPUT_CHANGED",hooks:new(){BeforeRecheck=()=>File.WriteAllText(Path.Combine(p,"late.txt"),"late")});});
        await Case("late-change-before-config-read",async()=>{string p=Target();await Expect(p,1,"INPUT_CHANGED",hooks:new(){AfterSnapshot=_=>File.AppendAllText(Path.Combine(p,"Sample.runtimeconfig.json")," ")});});
        await Case("byte-limit",async()=>{string p=Target();using(var f=File.Create(Path.Combine(p,"large.bin")))f.SetLength(Snapshot.FileLimit+1);await Expect(p,1,"BYTE_LIMIT");});
        await Case("actual-walk-entry-limit",async()=>{string p=Target();for(int i=0;i<513;i++)File.WriteAllText(Path.Combine(p,"e"+i+".txt"),"");await Expect(p,1,"ENTRY_LIMIT");});
        await Case("aggregate-byte-limit",async()=>{string p=Target();for(int i=0;i<4;i++){using var f=File.Create(Path.Combine(p,"bulk"+i+".bin"));f.SetLength(Snapshot.FileLimit);}await Expect(p,1,"BYTE_LIMIT");});
        await Case("walk-depth-limit",async()=>{string p=Target(),deep=p;for(int i=0;i<17;i++)deep=Directory.CreateDirectory(Path.Combine(deep,"d")).FullName;File.WriteAllText(Path.Combine(deep,"deep.txt"),"");var r=await Inspect(p);Require(r.ExitCode==1&&!r.Complete);});
        await Case("json-byte-limit",async()=>{string p=Target();Runtime(p,new string(' ',4*1024*1024+1));await Expect(p,1,"JSON_LIMIT");});
        await Case("json-array-limit",async()=>{string p=Target();Runtime(p,"{\"unknown\":["+string.Join(',',Enumerable.Repeat("0",1025))+"]}");await Expect(p,1,"JSON_LIMIT");});
        await Case("path-no-controls-no-traversal",()=>
        {
            foreach(string path in new[]{"../escape","a\\b","bad\nfile","/absolute","a:stream",new string('a',97),string.Join('/',Enumerable.Repeat("x",17))})
            {try{Contract.Relative(path);throw new InvalidOperationException("Unsafe path accepted");}catch(Problem){}}
            return Task.CompletedTask;
        });
        await Case("report-collision-keeps-sentinel",async()=>
        {
            string p=Target(),output=Next("existing");Directory.CreateDirectory(output);File.WriteAllText(Path.Combine(output,"sentinel"),"untouched");var r=await Inspection.Run(p,output,"Sample.dll","win-x64");Require(r.ExitCode==1&&r.Reason=="OUTPUT_EXISTS"&&File.ReadAllText(Path.Combine(output,"sentinel"))=="untouched");
        });
        await Case("nested-report-refused",async()=>{string p=Target();var r=await Inspection.Run(p,Path.Combine(p,"report"),"Sample.dll","win-x64");Require(r.ExitCode==1&&r.Reason=="INPUT_REPORT_COLLISION"&&!Directory.Exists(Path.Combine(p,"report")));});
        await Case("report-write-failure-never-pass",async()=>{string p=Target();var r=await Inspect(p,hooks:new(){BeforeReport=output=>File.WriteAllText(Path.Combine(output,"summary.json"),"blocked")});Require(r.ExitCode==1&&!r.Complete&&r.Reason=="REPORT_WRITE_FAILED");});
        string valid=JsonSerializer.Serialize(Metadata.Read(Path.Combine(Target(),"Sample.dll")),Contract.Json);
        foreach(string invalid in new[]{"", "{}",valid+"{}",valid[..^1],valid.Replace("\"schema\": 1","\"schema\": 2"),valid.Replace("\"complete\": true","\"complete\": false"),valid.Replace("\"architecture\": \"anycpu\"","\"architecture\": \"private-string\""),valid.Replace("\"schema\": 1","\"schema\": 1,\"schema\": 1"),valid.Replace("\"schema\": 1","\"extra\": 1,\"schema\": 1"),new string('x',16*1024+1)})
            await Case("invalid-worker-protocol-"+(++Index),async()=>{Require(invalid!=valid,"Protocol mutation did not modify the golden");string p=Target();await Expect(p,1,"WORKER_PROTOCOL",hooks:new(){Worker=()=>Task.FromResult(new TransportResult(0,Contract.Utf8(invalid),""))});});
        foreach(var item in new[]{("--probe-hang","WORKER_TIMEOUT"),("--probe-stdout","WORKER_OUTPUT_LIMIT"),("--probe-stderr","WORKER_OUTPUT_LIMIT"),("--probe-exit","WORKER_FAILED")})
            await Case("real-owned-child-"+item.Item1,async()=>{var watch=Stopwatch.StartNew();var r=await Transport.RunAsync(Self(item.Item1),500);Require(r.Problem==item.Item2&&watch.Elapsed<TimeSpan.FromSeconds(7),r.Problem);});
        await Case("reports-no-private-path-or-raw-config",async()=>
        {
            string p=Target(),output=Next("private report");string config=Path.Combine(p,"Sample.runtimeconfig.json");File.WriteAllText(config,File.ReadAllText(config).Replace("\"tfm\"","\"neverReportThis\":\"PRIVATE_VALUE\",\"tfm\""));
            var r=await Inspection.Run(p,output,"Sample.dll","win-x64");string json=File.ReadAllText(Path.Combine(output,"summary.json")),text=File.ReadAllText(Path.Combine(output,"report.txt"));Require(r.ExitCode==0&&!json.Contains(Root)&&!json.Contains("PRIVATE_VALUE")&&!text.Contains(Root)&&!text.Contains("PRIVATE_VALUE")&&!text.Contains(">="));
        });
        await Case("invalid-rid-does-not-echo-untrusted-argument",async()=>{var r=await Inspect(Target(),rid:"PRIVATE_PATH_OR_COMMAND");Require(r.ExitCode==1&&r.Reason=="RID_UNSUPPORTED"&&!JsonSerializer.Serialize(r,Contract.Json).Contains("PRIVATE_PATH_OR_COMMAND"));});
        foreach(bool directory in new[]{false,true})
        {
            string name=directory?"symlink-directory-refused":"symlink-file-refused";
            try
            {
                string p=Target(),link=Path.Combine(p,"link");if(directory)Directory.CreateSymbolicLink(link,FixtureRoot);else File.CreateSymbolicLink(link,Path.Combine(FixtureRoot,"Tripwire.dll"));
                await Case(name,()=>Expect(p,1,"LINK_UNSUPPORTED"));
            }
            catch(Exception e) when(OperatingSystem.IsWindows()&&(e is UnauthorizedAccessException || e is IOException&&e.HResult==unchecked((int)0x80070522)))
            {Skipped++;Console.WriteLine("SKIP "+name+" local symbolic-link privilege unavailable");Observations.Add(new{name,result="skip",reason="Local Windows symlink privilege unavailable"});}
        }
        if(OperatingSystem.IsLinux())await Case("linux-fifo-refused-before-open",async()=>{string p=Target();Require(mkfifo(Path.Combine(p,"fifo"),0x180)==0,"mkfifo failed");await Expect(p,1,"NON_REGULAR_FILE");});
        else {Skipped++;Observations.Add(new{name="linux-fifo-refused-before-open",result="skip",reason="Linux-only statx/FIFO regression; Ubuntu CI required"});}
        await Case("actual-cli-demo",async()=>
        {
            string host=Environment.GetEnvironmentVariable("DOCTOR_TEST_APP")??Path.Combine(Path.GetDirectoryName(typeof(Inspection).Assembly.Location)!,OperatingSystem.IsWindows()?"doctor.exe":"doctor");
            var start=new ProcessStartInfo(host);start.ArgumentList.Add("demo");start.ArgumentList.Add(Next("actual demo"));var r=await Transport.RunAsync(start,30_000);Require(r.Problem==""&&System.Text.Encoding.UTF8.GetString(r.Stdout).Contains("DEMO PASS"),r.Problem+System.Text.Encoding.UTF8.GetString(r.Stdout));
        });
        var receipt=new{passed=Passed,failed=Failed,skipped=Skipped,observations=Observations,scope="Synthetic trusted fixtures; no target execution/Assembly.Load, installed-host or malicious-PE-sandbox claim"};
        File.WriteAllText(Path.Combine(Root,"receipt.json"),JsonSerializer.Serialize(receipt,Contract.Json));Console.WriteLine($"SUMMARY passed={Passed} failed={Failed} skipped={Skipped}");return Failed==0?0:1;
    }
}
