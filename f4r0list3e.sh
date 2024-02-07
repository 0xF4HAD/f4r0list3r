#!/bin/bash

echo -e "\e[1;31m"
cat << "EOF"

  █████▒▄▄▄       ██▀███   ▒█████   ██▓     ██▓  ██████ ▄▄▄█████▓▓█████  ██▀███  
▓██   ▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓██▒    ▓██▒▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒████ ░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒██░    ▒██▒░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
░▓█▒  ░░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░▒██░    ░██░  ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
░▒█░    ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░░██████▒░██░▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
 ▒ ░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▓  ░░▓  ▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
 ░       ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░ ▒ ░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░
 ░ ░     ░   ▒     ░░   ░ ░ ░ ░ ▒    ░ ░    ▒ ░░  ░  ░    ░         ░     ░░   ░ 
             ░  ░   ░         ░ ░      ░  ░ ░        ░              ░  ░   ░        
EOF
echo -e "\e[0m"
echo -e "\e[1;32m Welcome to f4r0list3r - Make Your Recon Faster & Easy!\e[0m"
#    https://github.com/zan8in/afrog/
#    https://github.com/tomnomnom/assetfinder
#    https://github.com/owasp-amass/amass
#    assetfinder & Sublist3r & subfinder & Crt.sh & amass
#    waybackurls
#    whatweb
#    https://github.com/haccer/subjack
#    https://github.com/PentestPad/subzy
#    https://github.com/devanshbatham/ParamSpider
#    https://github.com/Emoe/kxss
#    https://github.com/projectdiscovery/httpx?tab=readme-ov-file


  

    url=$1 
    RESET="\e[0m"
    YELLOW="\e[1;33m"
    
     

    if [ ! -x "$(command -v assetfinder)" ]; then
        echo -e "\e[1;31m [-] assetfinder required to run script... \e[0m"
        exit 1
    fi
    
    if [ ! -x "$(command -v amass)" ]; then
        echo -e "\e[1;31m [-] amass required to run script.. \e[0m"
        exit 1
    fi
    
    if [ ! -x "$(command -v sublist3r)" ]; then
        echo -e "\e[1;31m [-] sublist3r required to run script.. \e[0m"
        exit 1
    fi

    # if [ ! -x "$(find / -type f -name 'EyeWitness')" ];then
    #     echo -e "\e[1;31m [-] Eyewitness required to run script.. \e[0m"
    #     exit 1
    # fi
 
    if [ ! -x "$(command -v httprobe)" ]; then
        echo -e "\e[1;31m [-] httprobe required to run script.. \e[0m"
        exit 1
    fi
    
    if [ ! -x "$(command -v waybackurls)" ]; then
        echo -e  "\e[1;31m [-] waybackurls required to run script.. \e[0m"
        exit 1
    fi
    
    if [ ! -x "$(command -v whatweb)" ]; then
        echo -e "\e[1;31m [-] whatweb required to run script.. \e[0m"
        exit 1
    fi

# Making Dir

    if [ ! -d "$url" ];then
        mkdir $url
    fi
    if [ ! -d "$url/recon" ];then 
        mkdir $url/recon
    fi
    if [ ! -d "$url/recon/Subdomains/" ];then 
        mkdir $url/recon/Subdomains/
    fi
    if [ ! -d "$url/recon/3rd-lvls" ];then
        mkdir $url/recon/3rd-lvls
    fi
    if [ ! -d "$url/recon/scans" ];then
        mkdir $url/recon/scans
    fi
    if [ ! -d "$url/recon/httprobe" ];then
        mkdir $url/recon/httprobe
    fi
    if [ ! -d "$url/recon/potential_takeovers" ];then
         mkdir $url/recon/potential_takeovers
    fi
    if [ ! -d "$url/recon/wayback" ];then
        mkdir $url/recon/wayback
    fi
    if [ ! -d "$url/recon/wayback/params" ];then
        mkdir $url/recon/wayback/params
    fi
    if [ ! -d "$url/recon/wayback/extensions" ];then
        mkdir $url/recon/wayback/extensions
    fi
    if [ ! -d "$url/recon/whatweb" ];then
        mkdir $url/recon/whatweb
    fi
    if [ ! -d "$url/recon/VulnScan" ];then
        mkdir $url/recon/VulnScan
    fi
    if [ ! -f "$url/recon/httprobe/alive.txt" ];then
        touch $url/recon/httprobe/alive.txt
    fi
    if [ ! -f "$url/recon/final.txt" ];then
        touch $url/recon/final.txt
    fi
    if [ ! -f "$url/recon/3rd-lvl" ];then
        touch $url/recon/3rd-lvl-domains.txt
    fi
    
    
 # Harvesting subdomains (assetfinder & Sublist3r & subfinder & Crt.sh & amass)

    echo -e "$YELLOW[+] Harvesting subdomains with assetfinder...$RESET"
    assetfinder --subs-only $url >> $url/recon/Subdomains/assetfinder.txt

    echo -e "$YELLOW[+] Harvesting subdomains with Sublist3r...$RESET"
    sublist3r  -d $url  >> $url/recon/Subdomains/sublist3r.txt

    echo -e "$YELLOW[+] Harvesting subdomains with subfinder...$RESET"
    subfinder -d $url  >> $url/recon/Subdomains/subfinder.txt
    
    echo -e "$YELLOW[+] Double checking for subdomains with amass and Crt.sh ...$RESET"
    #amass enum -passive -d $url | tee -a $url/Subdomains/amass.txt
    curl -s https://crt.sh/\?q\=%25.$url\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> $url/recon/Subdomains/crt.txt
    # sort -u $url/recon/final1.txt >> $url/recon/final.txt
    cat $url/recon/Subdomains/assetfinder.txt $url/recon/Subdomains/sublist3r.txt $url/recon/Subdomains/subfinder.txt $url/recon/Subdomains/crt.txt | anew $url/recon/Subdomains/final.txt
    
# Searching for CNAME Records with nslookup 
    echo -e "$YELLOW[+] Searching for CNAME Records With nslookup ...$RESET"
    input_file="$url/recon/Subdomains/final.txt"

# Check if the input file exists
    if [ ! -f "$input_file" ]; then
        echo "Error: Input file '$input_file' not found."
        exit 1
    fi
# Output file to store nslookup results
    output_file="nslookup_results.txt"

# Clear the output file
    > "$output_file"

# Loop through each domain in the input file
    while IFS= read -r domain; do
        echo -e "\e[1;32m Performing nslookup for:\e[0m  $domain "
        
        # Perform nslookup for the domain and append the result to the output file
        echo -e "\e[1;33m Domain: $domain \e[0m" >> "$output_file"
        nslookup -type=cname "$domain" >> "$output_file"
        echo "" >> "$output_file"  # Add an empty line for readability
    done < "$input_file"

    echo "nslookup for all domains completed. Results are saved in: $output_file"



 # Compiling 3rd lvl domains

    #echo "[+] Compiling 3rd lvl domains..."
    #cat $url/recon/final.txt | grep -Po '(\w+\.\w+\.\w+)$' | sort -u >> $url/recon/3rd-lvl-domains.txt
    #write in line to recursively run thru final.txt
    #for line in $(cat $url/recon/3rd-lvl-domains.txt);do echo $line | sort -u | tee -a $url/recon/final.txt;done
    
    #echo "[+] Harvesting full 3rd lvl domains with sublist3r..."
    #for domain in $(cat $url/recon/3rd-lvl-domains.txt);do sublist3r -d $domain -o $url/recon/3rd-lvls/$domain.txt;done
 
# Probing for alive domains

    echo -e "\e[1;33m[++] Probing for alive domains...\e[0m"
    cat $url/recon/Subdomains/final.txt | sort -u | httprobe -s -p https:443 | sed 's~https\?://~~; s~:443~~'  >> $url/recon/httprobe/alive.txt
    cat $url/recon/Subdomains/final.txt | httpx -mc 200 | sort -u  >> $url/recon/httprobe/alive.txt

# Probing for alive domains

    echo -e "\e[1;33m[++] Paramspider Mining URLs from dark corners of Web Archives...\e[0m"
    # for URL in $url/recon/httprobe/alive.txt; do (paramspider -d "${URL}");done
    paramspider -l $url/recon/httprobe/alive.txt
    

#  Checking for possible subdomain takeover (subjack & subzy)

    echo -e "\e[1;33m[++] Checking for possible subdomain takeover...\e[0m"
    if [ ! -f "$url/recon/potential_takeovers/domains.txt" ];then
        touch $url/recon/potential_takeovers/domains.txt
    fi
    if [ ! -f "$url/recon/potential_takeovers/potential_takeovers1.txt" ];then
        touch $url/recon/potential_takeovers/potential_takeovers1.txt
    fi
    for line in $(cat $url/recon/Subdomains/final.txt);do echo $line |sort -u >> $url/recon/potential_takeovers/domains.txt;done
    subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c /usr/share/subjack/fingerprints.json -v 3  >> $url/recon/potential_takeovers/potential_takeovers1.txt
    subzy run --targets $url/recon/httprobe/alive.txt  >> $url/recon/potential_takeovers/potential_takeovers1.txt
    sort -u $url/recon/potential_takeovers/potential_takeovers1.txt >> $url/recon/potential_takeovers/potential_takeovers.txt
    rm $url/recon/potential_takeovers/potential_takeovers1.txt

# Running whatweb on compiled domains 

    echo -e "\e[1;33m[++] Running whatweb on compiled domains...\e[0m"
    for domain in $(cat $url/recon/httprobe/alive.txt);do
        if [ ! -d  "$url/recon/whatweb/$domain" ];then
            mkdir $url/recon/whatweb/$domain
        fi
        if [ ! -d "$url/recon/whatweb/$domain/output.txt" ];then
            touch $url/recon/whatweb/$domain/output.txt
        fi
        if [ ! -d "$url/recon/whaweb/$domain/plugins.txt" ];then
            touch $url/recon/whatweb/$domain/plugins.txt
        fi
        echo -e "\e[1;33m[**] Pulling plugins data on $domain $(date +'%Y-%m-%d %T') \e[0m"
        whatweb --info-plugins -t 50 -v $domain >> $url/recon/whatweb/$domain/plugins.txt; sleep 3
        echo -e "\e[1;33m[**] Running whatweb on $domain $(date +'%Y-%m-%d %T')\e[0m"
        whatweb -t 50 -v $domain >> $url/recon/whatweb/$domain/output.txt; sleep 1
    done

 # Scraping wayback data

    echo -e "\e[1;33m[++] Scraping wayback data...\e[0m"
    cat $url/recon/final.txt | waybackurls | tee -a  $url/recon/wayback/wayback_output1.txt
    sort -u $url/recon/wayback/wayback_output1.txt >> $url/recon/wayback/wayback_output.txt
    rm $url/recon/wayback/wayback_output1.txt
    
    echo -e "\e[1;33m[++] Pulling and compiling all possible params found in wayback data...\e[0m"
    cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
    for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done
    
    echo -e "\e[1;33m[++] Pulling and compiling js/php/aspx/jsp/json files from wayback output...\e[0m"
    for line in $(cat $url/recon/wayback/wayback_output.txt);do
        ext="${line##*.}"
        if [[ "$ext" == "js" ]]; then
            echo $line | sort -u | tee -a  $url/recon/wayback/extensions/js.txt
        fi
        if [[ "$ext" == "html" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/jsp.txt
        fi
        if [[ "$ext" == "json" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/json.txt
        fi
        if [[ "$ext" == "php" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/php.txt
        fi
        if [[ "$ext" == "aspx" ]];then
            echo $line | sort -u | tee -a $url/recon/wayback/extensions/aspx.txt
        fi
    done
    

# Scanning for Open Ports using nmap

    echo -e "\e[1;33m[++] Scanning for open ports...\e[0m"
    nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt

# Harvesting Subdomains,IP & Servers with Knockpy

    echo -e "\e[1;33m[++] Harvesting Subdomains,IP & Servers with Knockpy...\e[0m"
    knockpy  $url 
    

# Harvesting subdomains with Gau

    echo -e "\e[1;33m[++] Harvesting subdomains with Gau...\e[0m"
    gau $url --subs --fc 404 --providers wayback   >> $url/recon/gau_urls.txt
    cat $url/recon/gau_urls.txt | grep $1 >> $url/recon/gau_urlsfinal.txt
    rm $url/recon/gau_urls.txt

# Eyewitness 

    # echo -e "\e[1;33m[++] Running eyewitness against all compiled domains...\e[0m"
    # eyewitness=$(find / -type f -name 'EyeWitness.py')
    # eyewitness --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve --no-prompt


# Checking for vulnerabilitys on alive subdomains (afrog)

    echo -e "\e[1;33m[++] Checking for vulnerabilitys on alive subdomains ...\e[0m"
    if [ ! -f "$url/recon/VulnScan" ];then
        touch $url/recon/VulnScan/vulnscan_domains.txt
    fi
    afrog -T $url/recon/httprobe/alive.txt -S high,critical   >> $url/recon/VulnScan/vulnscan_domains.txt
