#!/usr/bin/env python
#
# Pentest File Prep 
# ptfileprep.py (c) 2016 Keith Thome
# revision 1.3, 2016-10-24
#
# author: Keith Thome
# contact: keith.thome@outlook.com
#
# DESCRIPTION
# 
# The value in performing a penetration test for a client is directly related to the information provided
# to them at the end of the engagement. With many engagements encompassing many target hosts, tracking
# information throughout can be cumbersome and time consuming. This tool creates an initial file repository
# directory tree structure for penetration test reporting/file storage based on single host, list of hosts,
# or nmap ping sweep of given network range to keep things organized throughout the engagement and save
# time assembling the final report.
#
# Subdirectories created can be customized by modifying the SUB_DIR_FRAMEWORK array.
#
# Currently, the directory tree created for file storage is:
# 
# /(ip address)/
#       --/recon
#		--/exploitation
#       --/enumeration
#       --/misc
#       --/proofs
#
# Additionally, when utilizing network scanners to identify live hosts, a hosts.txt file will be created
# listing live hosts found to be used with other tools.
# 
# USAGE
# 
# Create penetration test file repository for a single IP address
# 
# $./ptfileprep.py ip 192.168.20.1
# [*] Single IP only mode.
# [*] Now creating directories...
# [*] Pentest file repository framework successfully created... 
#
# Create penetration test file repository from file containing IP addresses
#
# $./ptfileprep.py file hosts.txt
# [*] File in mode.
# [*] Now reading hosts.txt file...
# [*] Now creating directories...
# [*] Pentest file repository framework successfully created...
#
# Create penetration test file repository from results of an nmap ping scan
#
# $./ptfileprep.py nmap 192.168.20.0/24
# [*] Using nmap scan mode.
# 
# [*] Sweeping range 192.168.20.0/24 for live hosts
# [*] 192.168.20.1
# [*] 192.168.20.2
# [*] 192.168.20.254
# [*] 192.168.20.130
# 
# [*] Found 4 live hosts
# [*] Now creating directories...
# [*] Now writing hosts.txt file with list of live IP/hosts...
# [*] Pentest file repository framework successfully created...
#
# Create penetration test file repository from results of an nmap ping scan
# excluding a network range
#
# $./ptfileprep.py eR 192.168.20.1-192.168.20.5 nmap 192.168.20.0/24
# [*] Excluding 192.168.20.1-192.168.20.5 IP range from processing
# [*] Using nmap scan mode.
# 
# [*] Sweeping range 192.168.20.0/24 for live hosts
# [*] 192.168.20.254
# [*] 192.168.20.130
# 
# [*] Found 2 live hosts
# [*] Now creating directories...
# [*] Now writing hosts.txt file with list of live IP/hosts...
# [*] Pentest file repository framework successfully created...
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# TODOLIST
#
# TODO add support for recording hostnames if revealed during scan
#
# CHANGE LOG
# 
# v12 2016-10-11
# - added support for netdiscover scans
# - added support for -e exclusion switch to exclude single IP, range of IPs, or IPs from a file
# v10 2016-10-07
# - initial release

import subprocess
import sys
import os
import argparse

# subdirectories to create for each IP/host
SUB_DIR_FRAMEWORK = ["recon", "exploitation", "enumeration", "proofs", "misc"]

# IPs to create repository from
ip_addresses = []

# IPs that should be excluded
exclusions = []

progOptions = {'fileIn':None}

def exclude_iprange(ip_range):
    start_ip = ip_range.split("-")[0]
    end_ip = ip_range.split("-")[1]
    start = list(map(int,start_ip.split('.')))
    end = list(map(int,end_ip.split('.')))
    iprange=[]
    while start!= end:
        for i in range(len(start)-1,-1,-1):
            if start[i]<255:
                start[i]+=1
                break
            else:
                start[i]=0
        exclusions.append('.'.join(map(str,start)))

def performNmapScan(ip_range):
    ip_address = ""
    print " "
    print "[*] Sweeping range %s" % ip_range + " for live hosts using nmap"
    scan_results = "nmap -n -sP %s" % ip_range
    results = subprocess.check_output(scan_results, shell=True)
    lines = results.split("\n")
    for line in lines:
        line = line.strip()
        line = line.rstrip()
        if ("Nmap scan report for" in line):
            ip_address = line.split(" ")[4]
            if ip_address not in exclusions:
                print "[*] %s" % (ip_address)
                ip_addresses.append(ip_address)

    print " "
    print "[*] Found %s live hosts" % (len(ip_addresses))

def performNetdiscoverScan(ip_range):
    ip_address = ""
    print " "
    print "[*] Sweeping range %s" % ip_range + " for live hosts using netdiscover"
    scan_results = "netdiscover -P -N -r %s" % ip_range
    results = subprocess.check_output(scan_results, shell=True)
    lines = results.split("\n")
    for line in lines:
        line = line.strip()
        line = line.rstrip()
        ip_address = line.split(" ")[0]
        if len(ip_address) > 7 and ip_address not in exclusions:
            print "[*] %s" % (ip_address)
            ip_addresses.append(ip_address)

    print " "
    print "[*] Found %s live hosts" % (len(ip_addresses))

def createDirTree():
    print "[*] Now creating directories..."
    for ip_address in ip_addresses:
        # create initial directory for each ip_address
        try:
            os.stat(ip_address)
        except:
            os.mkdir(ip_address)

        # create sub-directories for each ip_address
        for sub_dir in SUB_DIR_FRAMEWORK:
            try:
                os.stat(ip_address + "/" + sub_dir)
            except:
                os.mkdir(ip_address + "/" + sub_dir)

def writeHostsTxt():
    # write single hosts.txt file containing list of IP addresses found
    print "[*] Now writing hosts.txt file with list of live IP/hosts..."
    hostsFile = "hosts.txt"
    f = open(hostsFile, 'w')
    for ip_address in ip_addresses:
        f.write("%s\n" % (ip_address))
    f.close()


def readHosts():
    print "[*] Now reading %s file..." % progOptions['fileIn']
    f = open(progOptions['fileIn'], 'r')
    for ip_address in f.readlines():
        if ip_address not in exclusions:
            ip_addresses.append(ip_address.rstrip('\n'))
    f.close()


def main():

    usage = "ptfileprep.py <command> [<args>]"

    parser = argparse.ArgumentParser(usage, version='Pentest File Prep 1.3 (c) Keith Thome',
                                     description='Creates initial file repository directory tree structure for penetration test reporting/file storage based on single host, list of hosts, or nmap ping sweep of given network range.')

    parser.add_argument('-eI', '--excludeIP', dest='excludeIP', help='Exclude single IP from processing.')
    parser.add_argument('-eR', '--excludeRange', dest='excludeRange', help='Exclude range of IPs from processing in the form of starting ip-ending ip. Ie. 192.168.20.5-192.168.20.10')
    parser.add_argument('-eF', '--excludeFile', dest='excludeFile', help='Exclude IPs contained in file from processing.')

    subparsers = parser.add_subparsers(help='sub-command help')

    parser_ip = subparsers.add_parser(
        'ip', help='Create file repository for a single IP address.')
    parser_ip.add_argument(
        'ip_address', help='IP address to create file respository for.')
    parser_ip.set_defaults(action='ip')

    parser_file = subparsers.add_parser(
        'file', help='Create file repository from list of IP addresses contained in a file.')
    parser_file.add_argument(
        'file_in', help='File containing list of IP addresses to create file repository from.')
    parser_file.set_defaults(action='file')

    parser_nmap = subparsers.add_parser(
        'nmap', help='Create file repository from live hosts found via a nmap network range ping scan.')
    parser_nmap.add_argument(
        'ip_range', help='IP block to pass to nmap for scanning.')
    parser_nmap.set_defaults(action='nmap')

    parser_netdiscover = subparsers.add_parser(
        'netdiscover', help='Create file repository from live hosts found via a netdiscover network range ping scan.')
    parser_netdiscover.add_argument(
        'ip_range', help='IP block to pass to netdiscover for scanning.')
    parser_netdiscover.set_defaults(action='netdiscover')

    args = parser.parse_args()

    if len(sys.argv) > 1:

        if args.excludeIP is not None:
            exclusions.append(args.excludeIP)
            print "[*] Excluding %s from processing" % args.excludeIP

        if args.excludeFile is not None:
            print "[*] Now reading %s exclusions file..." % args.excludeFile
            f = open(args.excludeFile, 'r')
            for ip_address in f.readlines():
                exclusions.append(ip_address.rstrip('\n'))
            f.close()

        if args.excludeRange is not None:
            print "[*] Excluding %s IP range from processing" % args.excludeRange
            exclude_iprange(args.excludeRange)

        if args.action == "ip":
            print "[*] Single IP only mode."
            if args.ip_address not in exclusions:
                ip_addresses.append(args.ip_address)
            createDirTree()

        elif args.action == "file":
            print "[*] File in mode."
            progOptions['fileIn'] = args.file_in
            readHosts()
            createDirTree()

        elif args.action == "nmap":
            print "[*] Using nmap scan mode."
            performNmapScan(args.ip_range)
            createDirTree()
            writeHostsTxt()

        elif args.action == "netdiscover":
            print "[*] Using netdiscover scan mode."
            performNetdiscoverScan(args.ip_range)
            createDirTree()
            writeHostsTxt()

        print "[*] Pentest file repository framework successfully created..."
        print " "
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
