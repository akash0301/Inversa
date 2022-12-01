# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O /tmp/inversa_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

                #3
                ["wget -O /tmp/inversa_temp_wp_check --tries=1 ","/wp-admin"],

                #4
                ["wget -O /tmp/inversa_temp_drp_check --tries=1 ","/user"],

                #5
                ["wget -O /tmp/inversa_temp_joom_check --tries=1 ","/administrator"],

                #6
                ["uniscan -e -u ",""],

                #7
                ["wafw00f ",""],

                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b google -d ",""],

                #10
                ["dnsrecon -d ",""],

                #11
                #["fierce -wordlist xxx -dns ",""],

                #12
                ["dnswalk -d ","."],

                #13
                ["whois ",""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ",""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                #16
                ["sslyze --heartbleed ",""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                #22
                ["sslyze --certinfo=basic ",""],

                #23
                ["sslyze --compression ",""],

                #24
                ["sslyze --reneg ",""],

                #25
                ["sslyze --resum ",""],

                #26
                ["lbd ",""],

                #27
                ["golismero -e dns_malware scan ",""],

                #28
                ["golismero -e heartbleed scan ",""],

                #29
                ["golismero -e brute_url_predictables scan ",""],

                #30
                ["golismero -e brute_directories scan ",""],

                #31
                ["golismero -e sqlmap scan ",""],

                #32
                ["dirb http://"," -fi"],

                #33
                ["xsser --all=http://",""],

                #34
                ["golismero -e sslscan scan ",""],

                #35
                ["golismero -e zone_transfer scan ",""],

                #36
                ["golismero -e nikto scan ",""],

                #37
                ["golismero -e brute_dns scan ",""],

                #38
                ["dnsenum ",""],

                #39
                ["fierce --domain ",""],

                #40
                ["dmitry -e ",""],

                #41
                ["dmitry -s ",""],

                #42
                ["nmap -p23 --open -Pn ",""],

                #43
                ["nmap -p21 --open -Pn ",""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                #45
                ["davtest -url http://",""],

                #46
                ["golismero -e fingerprint_web scan ",""],

                #47
                ["uniscan -w -u ",""],

                #48
                ["uniscan -q -u ",""],

                #49
                ["uniscan -r -u ",""],

                #50
                ["uniscan -s -u ",""],

                #51
                ["uniscan -d -u ",""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                #53
                ["nikto -Plugins 'subdomain' -host ",""],

                #54
                ["nikto -Plugins 'shellshock' -host ",""],

                #55
                ["nikto -Plugins 'cookies' -host ",""],

                #56
                ["nikto -Plugins 'put_del_test' -host ",""],

                #57
                ["nikto -Plugins 'headers' -host ",""],

                #58
                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

                #60
                ["nikto -Plugins 'outdated' -host ",""],

                #61
                ["nikto -Plugins 'httpoptions' -host ",""],

                #62
                ["nikto -Plugins 'cgi' -host ",""],

                #63
                ["nikto -Plugins 'ssl' -host ",""],

                #64
                ["nikto -Plugins 'sitefiles' -host ",""],

                #65
                ["nikto -Plugins 'paths' -host ",""],

                #66
                ["dnsmap ",""],

                #67
                ["nmap -p1433 --open -Pn ",""],

                #68
                ["nmap -p3306 --open -Pn ",""],

                #69
                ["nmap -p1521 --open -Pn ",""],

                #70
                ["nmap -p3389 --open -sU -Pn ",""],

                #71
                ["nmap -p3389 --open -sT -Pn ",""],

                #72
                ["nmap -p1-65535 --open -Pn ",""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ",""],

                #74
                ["nmap -p161 -sU --open -Pn ",""],

                #75
                ["wget -O /tmp/inversa_temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ",""],

                #77
                ["nmap -p137,138 --open -Pn ",""],

                #78
                ["wapiti "," -f txt -o inversa_temp_wapiti"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                
                #80
                ["whatweb "," -a 1"],

                #81
                ["amass enum -d ",""]
            ]
