# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                #1
                ["Does not have an IPv6 Address. It is good to have one.","i",1],

                #2
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],

                #3
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],

                #4
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],

                #5
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],

                #6
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],

                #7
                ["No Web Application Firewall Detected","m",7],

                #8
                ["Some ports are open. Perform a full-scan manually.","l",8],

                #9
                ["Email Addresses Found.","l",9],

                #10
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],

                #11
                # ["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],

                #12
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],

                #13
                ["Whois Information Publicly Available.","i",11],

                #14
                ["XSS Protection Filter is Disabled.","m",12],

                #15
                ["Vulnerable to Slowloris Denial of Service.","c",13],

                #16
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],

                #17
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],

                #18
                ["POODLE Vulnerability Detected.","h",15],

                #19
                ["OpenSSL CCS Injection Detected.","h",16],

                #20
                ["FREAK Vulnerability Detected.","h",17],

                #21
                ["LOGJAM Vulnerability Detected.","h",18],

                #22
                ["Unsuccessful OCSP Response.","m",19],

                #23
                ["Server supports Deflate Compression.","m",20],

                #24
                ["Secure Client Initiated Renegotiation is supported.","m",21],

                #25
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],

                #26
                ["No DNS/HTTP based Load Balancers Found.","l",23],

                #27
                ["Domain is spoofed/hijacked.","h",24],

                #28
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],

                #29
                ["Open Files Found with Golismero BruteForce.","m",25],

                #30
                ["Open Directories Found with Golismero BruteForce.","m",26],

                #31
                ["DB Banner retrieved with SQLMap.","l",27],

                #32
                ["Open Directories Found with DirB.","m",26],

                #33
                ["XSSer found XSS vulnerabilities.","c",28],

                #34
                ["Found SSL related vulnerabilities with Golismero.","m",29],

                #35
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],

                #36
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],

                #37
                ["Found Subdomains with Golismero.","m",31],

                #38
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],

                #39
                ["Found Subdomains with Fierce.","m",31],

                #40
                ["Email Addresses discovered with DMitry.","l",9],

                #41
                ["Subdomains discovered with DMitry.","m",31],

                #42
                ["Telnet Service Detected.","h",32],

                #43
                ["FTP Service Detected.","c",33],

                #44
                ["Vulnerable to STUXNET.","c",34],

                #45
                ["WebDAV Enabled.","m",35],

                #46
                ["Found some information through Fingerprinting.","l",36],

                #47
                ["Open Files Found with Uniscan.","m",25],

                #48
                ["Open Directories Found with Uniscan.","m",26],

                #49
                ["Vulnerable to Stress Tests.","h",37],

                #50
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],

                #51
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],

                #52
                ["Apache Expect XSS Header not present.","m",12],

                #53
                ["Found Subdomains with Nikto.","m",31],

                #54
                ["Webserver vulnerable to Shellshock Bug.","c",40],

                #55
                ["Webserver leaks Internal IP.","l",41],

                #56
                ["HTTP PUT DEL Methods Enabled.","m",42],

                #57
                ["Some vulnerable headers exposed.","m",43],

                #58
                ["Webserver vulnerable to MS10-070.","h",44],

                #59
                ["Some issues found on the Webserver.","m",30],

                #60
                ["Webserver is Outdated.","h",45],

                #61
                ["Some issues found with HTTP Options.","l",42],

                #62
                ["CGI Directories Enumerated.","l",26],

                #63
                ["Vulnerabilities reported in SSL Scans.","m",29],

                #64
                ["Interesting Files Detected.","m",25],

                #65
                ["Injectable Paths Detected.","l",46],

                #66
                ["Found Subdomains with DNSMap.","m",31],

                #67
                ["MS-SQL DB Service Detected.","l",47],

                #68
                ["MySQL DB Service Detected.","l",47],

                #69
                ["ORACLE DB Service Detected.","l",47],

                #70
                ["RDP Server Detected over UDP.","h",48],

                #71
                ["RDP Server Detected over TCP.","h",48],

                #72
                ["TCP Ports are Open","l",8],

                #73
                ["UDP Ports are Open","l",8],

                #74
                ["SNMP Service Detected.","m",49],

                #75
                ["Elmah is Configured.","m",50],

                #76
                ["SMB Ports are Open over TCP","m",51],

                #77
                ["SMB Ports are Open over UDP","m",51],

                #78
                ["Wapiti discovered a range of vulnerabilities","h",30],

                #79
                ["IIS WebDAV is Enabled","m",35],

                #80
                ["X-XSS Protection is not Present","m",12],

                #81
                ["Found Subdomains with AMass","m",31]



            ]

# Tool Responses (Ends)