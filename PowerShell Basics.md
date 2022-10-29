# PowerShell Basics


## cmdlets and help
powershell commands called cmdlets and each cmdlet is constructed with form `verb-nown`

**verp:**
Think of it much like http verbs *GET, POST..*
- Get
- Start
- Stop 
- Read
- Write
- New
- Out
- where
	- 
	- 

**nown:**
Also think of it like url you will apply the verp on it
- Member
- Object
- ChildItem
	- 
	- 

Now we know that cmdlet is `verb-nown`, the outbut from cmdlet is object so when we pipe the out form cmdlet to another with `|` we pass an object not a string. 

To gets all the _cmdlets_ installed on the current Computer we can use `Get-Command` and to get a help for a specific cmdlet we can use `Get-Help`

**Examples:**

list cmdlets with wildcard
```powershell
PS C:\> Get-Command New-*
PS C:\> Get-Command *-Member
```
get help for a cmdlet
```PowerShell
PS C:\> Get-Help Select-Object -Examples
```

## Object manipulation and filtering

As we said the outbut from PowerShell cmdlet is an object, we can perform opertaions on this object methods and properties.

**Examples:**
view members for cmdlets with a membertype of Method/property
```powershell
PS C:\> Get-Command | Get-Member -MemberType Method
PS C:\> Get-Command | Get-Member -MemberType Property
```
pulling out the properties from the output of a cmdlet and creating a new object, listing the directories (first 5 and last 2) and just selecting the mode and the name.
```powershell
PS C:\> Get-ChildItem | Select-Object -property Name, Mode -first 5 -last 2 
```

We can filter cmdlet objects  with `Where-Object` or sort with `Sort-Object`

**Examples:**
Get system processes and filter for objects that have property **status == stopped**
```powershell
PS C:\> Get-Service | Where-Object -Property Status -eq Stopped

PS C:\> Get-Service | Where-Object {$_.Status -eq Stopped}
```

Sort directories
```powershell
PS C:\> Get-ChildItem | Sort-Object
```

Search for file (tryhackme):
```powershell
PS C:\> Get-ChildItem -Recurse -Path "C:\" -ErrorAction SilentlyContinue -Include *.txt|Where-Object -Property Name -Match "interesting*"

PS C:\> Get-ChildItem -Recurse -Path 'C:\' -Include "interesting*.txt" 
```
Print file content (tryhackme):
```Powershell
PS C:\> get-content -path "C:\Program Files\interesting-file.txt.txt"
```
Count cmdlets except `alias` and `function` (tryhackme):
```powershell
PS C:\>  Get-Command|Where-Object -Property CommandType -ne "Alias"|Where-Object -Property CommandType -ne "Function"|Measure-Object
```

Calc MD5 hash (tryhackme):
```powershell
PS C:\> Get-FileHash "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5
```

print current location (tryhackme): `get-location`
request web server (tryhackme): `invoke-webrequest`
base64 decode (tryhackme): 
```powershell
PS C:\> Get-ChildItem -Recurse -Path 'C:\' -Include "b64.txt" 
PS C:\> [System.Text.Encoding]::utf8.GetString([System.Convert]::FromBase64String($(get-content -Path "C:\Users\Administrator\Desktop\b64.txt")))
```

list machine users (tryhackme): `get-localuser`

Find user with sid (tryhackme):
```powershell
PS C:\> Get-LocalUser | Where-Object -Property sid -eq "S-1-5-21-2877391638-273970274-1386674568-1001"
```

Find users with password required (tryhackme):
```powershell
PS C:\> Get-LocalUser|Select-Object -Property name,sid,passwordrequired
```

count local groups (tryhackme):
```powershell
PS C:\> Get-LocalGroup |Measure-Object
```

get IP inforamtion (tryhackme): `Get-NetIPAddress`

```powershell
PS C:\> Get-NetTCPConnection|Where-Object -Property State -eq "Listen"|Measure-Object
```

```powershell
PS C:\> get-hotfix|measure-object
```

```powershell
PS C:\> Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue -Include *.bak*
PS C:\> Get-Content 'C:\Program Files (x86)\Internet Explorer\passwords.bak.txt'
```

```powershell
PS C:\> Get-ChildItem -Recurse -Path C:\|Select-String "API_KEY" -List|select path
PS C:\> Get-Content 'C:\Users\Public\Music\config.xml'
```

```powershell
PS C:\> Get-ScheduledTask -TaskName new-sched-task
```

```powershell
PS C:\> Get-ACL 'C:\'
```

```powershell
$email_files = Get-ChildItem -path 'C:\Users\Administrator\Desktop\emails' -Recurse -Include "*.txt"

foreach($content in $email_files){
	$pass=Get-Content $content|Select-String "password"
	$http_url= Get-Content $content|Select-String "http"

	if($pass){
		echo "passfile: $content.Name"
		echo "password: $pass"
	}
	
	if($http_link){
		echo "file contains http url: $content.Name"
		echo "url: $http_url"
	}

}
```

```powershell
$ports = 129..140
$counter=0

foreach($port in $ports){
$testport=Test-NetConnection localhost -Port $port
    if($testport.PingSucceeded){
        $counter+=1
        echo $port
    }
}

echo "there're $counter open ports"
```

---
## PowerShell for pentesters room
url: https://tryhackme.com/room/powershellforpentesters

1- What useful PowerShell script did you find on Walter's desktop?
```powershell
PS C:\Users\Walter>   powershell
PS C:\Users\Walter> cd .\Desktop\
PS C:\Users\Walter\Desktop> get-childitem
```

2- What is the MD5 hash value of the file on Walter's  desktop?
```powershell
PS C:\Users\Walter\Desktop> Get-Filehash -Algorithm MD5 .\powerview.ps1
```

3- Download files from a remote server
```powershell
PS C:\> (New-Object System.Net.WebClient).DownloadFile("http:192.168.1.11:8080/file.txt","myfile.txt")
PS C:\> Invoke-WebRequest "http:192.168.1.11:8080/file.txt" -OutFile "myfile.txt"
```

4- What Windows Security Update was installed on 5/15/2019?
```powershell
PS C:\> Get-HotFix
```

#### Enumerating domain with powerview
5- One of the accounts has a special description; what is it?
```powershell
PS C:\> (Get-NetUser).description
```

6- How many accounts are disabled?
```powershell
PS C:\> Get-NetUser -UACfilter accountdisable|measure-object
```

7- How many users are in the "domain admins" group?
```powershell
PS C:\> Get-NetGroupMember "Domain Admins"
```

8- Which users are in the "domain admins" group? (Listed alphabetically, small, comma-separated, using space)
```powershell
PS C:\> (Get-NetGroupMember "Domain Admins").membername|Sort-Object
```

9- List shares; what is the name of the "interesting" share?
```powershell
PS C:\> Find-DomainShare -CheckShareAccess
```

10- What is the name of the user-created Group Policy?
```powershell
PS C:\> Get-NetGPO 
```

11- What are the first names of users' whose accounts were disabled? (Sorted alphabetically, small, comma-separated, using space)
```powershell
PS C:\> (Get-NetUser -UACFilter accountdisable).cn|Sort-Object # not "Guest" or "krbtgt"
```


## Resourses
- https://learnxinyminutes.com/docs/powershell/
- https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview
- https://learn.microsoft.com/en-us/powershell/