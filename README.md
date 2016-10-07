

## DESCRIPTION

The value in performing a penetration test for a client is directly related to the information provided
to them at the end of the engagement. With many engagements encompassing many target hosts, tracking
information throughout can be cumbersome and time consuming. This tool creates an initial file repository
directory tree structure for penetration test reporting/file storage based on single host, list of hosts,
or nmap ping sweep of given network range to keep things organized throughout the engagement and save
time assembling the final report.

Questions, comments, or concerns can be directed to keith.thome@outlook.com.

Subdirectories created can be customized by modifying the SUB_DIR_FRAMEWORK array.

Currently, the directory tree created for file storage is:

/(ip address)/
      --/recon
      --/tools
      --/exfil
      --/misc
      --/proofs

Additionally, when utilizing network scanners to identify live hosts, a hosts.txt file will be created
listing live hosts found to be used with other tools.

## USAGE

Create penetration test file repository for a single IP address
```
$./ptfileprep.py ip 192.168.20.1
[*] Single IP only mode.
[*] Now creating directories...
[*] Pentest file repository framework successfully created... 
```
Create penetration test file repository from file containing IP addresses
```
$./ptfileprep.py file hosts.txt
[*] File in mode.
[*] Now reading hosts.txt file...
[*] Now creating directories...
[*] Pentest file repository framework successfully created...
```
Create penetration test file repository from results of an nmap ping scan
```
$./ptfileprep.py nmap 192.168.20.0/24
[*] Using nmap scan mode.

[+] Sweeping range 192.168.20.0/24 for live hosts
[*] 192.168.20.1
[*] 192.168.20.2
[*] 192.168.20.254
[*] 192.168.20.130

[*] Found 4 live hosts
[*] Now creating directories...
[*] Now writing hosts.txt file with list of live IP/hosts...
[*] Pentest file repository framework successfully created...
```
## LICENSE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

#### CHANGE LOG

v10 2016-10-07
- initial release
