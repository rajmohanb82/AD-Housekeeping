# Deploy with Apache Tomcat

Directory Keep is a Python service. Apache Tomcat 10.1 is the front door on a server that is already joined to Active Directory.

```text
Operator browser
    → Tomcat 10.1  :8080  /ad-housekeeping     private networks only
        → Python / Waitress  127.0.0.1:8765    the console
            → directory adapter                lab today, LDAP or ADWS later
```

The Tomcat process and the Python process run as a group managed service account, `svc-adhk$`. That account is allowed to reset passwords and clear lockouts on `OU=People`. It is not a member of Domain Admins, and the server is not a domain controller.

## What is in the installer

| File | Purpose |
| --- | --- |
| `installer/install.sh` | Create the virtualenv, stage the webapp, optionally download Tomcat |
| `installer/Install-DirectoryKeep.ps1` | Stage, or install onto a domain-joined Windows server |
| `installer/webapp/` | The Tomcat context: welcome page, `web.xml`, private-network valve |
| `installer/ad-housekeeping.service` | systemd unit for a Linux host |

Stage mode only writes files. Install mode on Windows refuses to run unless the computer is domain-joined and the shell is elevated. Neither mode edits directory ACLs. The PowerShell script prints the `dsacls` delegation at the end so an operator can review it.

## This laptop

```bash
chmod +x installer/install.sh
./installer/install.sh --run
```

`--run` installs dependencies, copies the webapp to `dist/tomcat/webapps/ad-housekeeping`, and starts the console on port 8765.

`--with-tomcat` also downloads Apache Tomcat **10.1.60** from `downloads.apache.org` and checks the published SHA-512 before expanding it. Java has to be installed before `catalina.sh start` will do anything. The interview path does not need that download. The **Tomcat deployment** page in the console shows the same files.

## Member server

Run this from an elevated PowerShell on a server that is already in the domain:

```powershell
# Files only
.\installer\Install-DirectoryKeep.ps1 -Mode Stage

# Tomcat 10.1.60, a local Python virtualenv, firewall rule for 8080
.\installer\Install-DirectoryKeep.ps1 -Mode Install
```

Install mode downloads `apache-tomcat-10.1.60-windows-x64.zip` and checks it against the Apache SHA-512 file. It copies the console to `C:\Program Files\DirectoryKeep` and asks you to register the Python process with NSSM, because `New-Service` cannot set a working directory. Tomcat’s own `service.bat install` registers the front door.

Then, separately, from a domain controller:

```powershell
New-ADServiceAccount -Name svc-adhk -DNSHostName fab-mgmt01.fabrikam.corp -PrincipalsAllowedToRetrieveManagedPassword FAB-MGMT01$
Install-ADServiceAccount -Identity svc-adhk

$ou = "OU=People,OU=Fabrikam,DC=fabrikam,DC=corp"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:CA;Reset Password;user"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:WP;lockoutTime;user"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:RPWP;pwdLastSet;user"
```

Change the host name and the OU to yours. Do not widen this to the domain root. Tier-0 changes stay on a privileged access workstation, which is the same split the role switcher demonstrates.

## Tomcat context

`META-INF/context.xml` allows only loopback and RFC 1918 addresses through `RemoteAddrValve`. Put TLS in front of Tomcat if operators are not on the same host. Do not expose port 8080 to the internet.

The welcome page tells operators the console is on port 8765. Keeping Python off the public listener means the only published port is the one Tomcat is already responsible for.

## What the installer will not do

- Join a computer to a domain.
- Grant Domain Admin, Enterprise Admin, or Schema Admin.
- Reset krbtgt.
- Disable the built-in Administrator on a forest you have not inventoried.

Those are change-window tasks. The console will show you why they matter. It will not perform them against a directory it is not connected to.
