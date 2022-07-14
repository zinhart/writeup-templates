```dataviewjs
var pageName='PLATFORM'
var dataSource='"reports/boxes/finished"'
let data = dv.pages(dataSource)
			.sort(b => b.ip_address)
		    .filter(function(b) {
			    if (b.file.name != `writeup-dataview-template`){
				    return false;
			    }
				return true;    
		    });
data.forEach(function(b) {
b.dns_server = ( b.dns_server.path != undefined ? dv.fileLink(`${b.dns_server.path}`,false,`${b.dns_server.display}`) : "N/A");
b.dependencies = ( b.dependencies.path != undefined ? dv.fileLink(`${b.dependencies.path}`,false,`${b.dependencies.display}`) : "N/A");
});
var generalInfoHeader=`${pageName} General Info`;
var boxInfoHeader=`${pageName} Machine Information`;
var passwordExtractHeader=`${pageName} Password Extract`;
var difficultyExtractHeader=`${pageName} Difficulty Index`;
var notesExtractHeader=`${pageName} Notes`;
var tilExtractHeader=`${pageName} Things I learned`;
let pg = dv.current();
dv.header(1,pageName);


dv.header(2, generalInfoHeader)
dv.table(["BOX", "OS", "INITIAL FOOTHOLD", "PRIVESC", "DIFFICULTY"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.hostname}`),
			   b.os_version,
			   b.initial_foothold_description,
			   b.privilege_escalation_description,
			   b.difficulty
			   ]));


dv.header(2, boxInfoHeader)
dv.table(["IP(HOST)", "DNS SERVER", "FQDN", "OS", "ARCHITECTURE", "DEPENDENCIES"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.ip_address}(${b.hostname})`),
			   b.dns_server,
			   b.fqdn,
			   b.os_version,
			   b.architecture,
			   b.dependencies
			   ]))


dv.header(2, passwordExtractHeader);
dv.table(["BOX", "SERVICE", "USER", "HASH TYPE", "HASH"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.ip_address}(${b.hostname})`),
			   b.pws.svc,
			   b.pws.usr,
			   b.pws.ht,
			   b.pws.hash
			   ]));

dv.header(2, difficultyExtractHeader);
dv.table(["BOX", "IF DIFFICULTY", "PRIVESC DIFFICULTY"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.ip_address}(${b.hostname})`),
			   b.if_difficulty,
			   b.pe_difficulty
			   ]));
dv.header(2, notesExtractHeader);
dv.table(["BOX", "INITIAL FOOTHOLD", "PRIVESC"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.ip_address}(${b.hostname})`),
			   b.rif,
			   b.rpe,
			   ]));
dv.header(2, tilExtractHeader);
dv.table(["BOX", "TIL"], data
    .map(b => [
			   dv.fileLink(`${b.file.path}`,false,`${b.ip_address}(${b.hostname})`),
			   b.til
			   ]));
```