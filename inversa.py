# Importing the necessary libraries
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit
from tools_fix import tools_fix
from tool_resp import tool_resp
from tool_status import tool_status
from tool_cmd import tool_cmd

CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )

def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)


# Inversa Help Context
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./inversa.py example.com: Scans the domain example.com.")
        print("\t./inversa.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./inversa.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./inversa.py --update   : Updates the scanner to the latest version.")
        print("\t./inversa.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits Inversa.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# Inversa Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """\
                     
       ██╗███╗░░██╗██╗░░░██╗███████╗██████╗░░██████╗░█████╗░
       ██║████╗░██║██║░░░██║██╔════╝██╔══██╗██╔════╝██╔══██╗
       ██║██╔██╗██║╚██╗░██╔╝█████╗░░██████╔╝╚█████╗░███████║
       ██║██║╚████║░╚████╔╝░██╔══╝░░██╔══██╗░╚═══██╗██╔══██║
       ██║██║░╚███║░░╚██╔╝░░███████╗██║░░██║██████╔╝██║░░██║
       ╚═╝╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝
       """+bcolors.ENDC+"""AUTOMATED WEB APPLICATION VULNERABILITY SCANNER 
       
       Author: THREE TRACKERS
                            """
    print(logo_ascii)
    print(bcolors.ENDC)


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            #for cursor in '|/-\\/': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
            #for cursor in '....scanning...please..wait....': yield cursor
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"Inversa received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"Inversa received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Checks for existence of IPV6 address.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],

                #3
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],

                #4
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],

                #5
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],

                #6
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #9
                ["theHarvester","The Harvester - Scans for emails using Google's passive search.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],

                #11
                # ["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

                #12
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],

                #13
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],

                #19
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],

                #26
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],

                #32
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],

                #33
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],

                #36
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],

                #40
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],

                #45
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],

                #46
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],

                #57
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],

                #65
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],

                #74upload
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],

                #75
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],

                #76
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],

                #77
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],

                #78
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],

                #79
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],

                #80
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],

                #81
                ["amass","AMass - Brutes Domain for Subdomains","amass",1],

                #82
                ["sqli_dec", "SQLi_Dec - Checks for SQL injection vulnerablities", "xsser", 1]
            ]


# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update Inversa.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    parser.add_argument('-v', '--vulnerability', 
                        help='Which Vulnerability to choose?',choices=['Injection','Port-Enumeration','Misconfiguration'])
    return parser


# Shuffling Scan Order (starts)
# scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
# random.shuffle(scan_shuffle)
# tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0

if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()


if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()
elif args_namespace.update:
    logo()
    print("Inversa is updating....Please wait.\n")
    spinner.start()
    # Checking internet connectivity first...
    rs_internet_availability = check_internet()
    if rs_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
    cmd = 'sha1sum inversa.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/skavngr/inversa/master/inversa.py -O inversa.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
    if oldversion_hash == newversion_hash :
        clear()
        print("\t"+ bcolors.OKBLUE +"You already have the latest version of inversa." + bcolors.ENDC)
    else:
        clear()
        print("\t"+ bcolors.OKGREEN +"inversa successfully updated to the latest version." +bcolors.ENDC)
    spinner.stop()
    sys.exit(1)

elif args_namespace.target:
    # print(args_namespace.target)
    target = url_maker(args_namespace.target)
    #target = args_namespace.target
    os.system('rm /tmp/inversa* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"inversa was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"not found" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        clear()
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by inversa."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. inversa will still perform the rest of the tests. Install these tools to fully utilize the functionality of inversa."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    
    cmds=[]
    if args_namespace.vulnerability == 'Injection':
        cmds=[29, 31, 50, 80]
    if args_namespace.vulnerability == 'Port-Enumeration':
        cmds=[7, 12, 13, 15, 16, 17, 18, 19, 40, 41, 42, 65, 66, 67, 68, 69, 70, 71, 72, 74, 75, 77]
    if args_namespace.vulnerability == 'Misconfiguration':
        cmds=[0,1,2,3,4,5,6,8,9,10,11,14,20,21,22,23,24,25,26,27,28,29,30,32,33,34,35,36,37,38,39,43,44,45,46,47,48,49,52,54,56,57,58,59,60,61,62,63,64,73,76,78,79]

    while(tool < len(tool_names)):
        if tool not in cmds:
            tool = tool + 1
            continue
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/inversa_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #print(bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n")
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                #clear()
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #sys.stdout.write(CURSOR_UP_ONE) 
                sys.stdout.write(ERASE_LINE)
                #print("-" * terminal_size(), end='\r', flush=True)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit inversa.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    date = subprocess.Popen(["date", "+%Y-%m-%d"],stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = "rs.dbg.%s.txt" % (target) 
    vulreport = "rs.vul.%s.txt" % (target)
    # print(args_namespace.target)
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open(vulreport, "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/inversa_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory inversa resides.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open(debuglog, "a") as report:
            try:
                with open("/tmp/inversa_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/inversa_te* > /dev/null 2>&1') # Clearing previous scan files


