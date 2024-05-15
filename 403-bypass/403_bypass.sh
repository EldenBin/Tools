#!/bin/bash

#colors
cyan='\e[96m'
red='\e[31m'
green='\e[32m'
yellow='\e[33m'
end='\e[0m'

#
information="$cyan[#]$end"
success="$green[+]$end"
warning="$yellow[!]$end"
error="$red[X]$end"

# Wordlists
default_methods_wordlist="wordlists/default_methods.txt"
default_userAgents_wordlist="wordlists/default_UserAgents.fuzz.txt"
default_headers_wordlist="wordlists/default_headers.txt"
default_endpaths_wordlist="wordlists/default_endpaths.txt"
default_midpaths_wordlist="wordlists/default_midpaths.txt"
default_ip_wordlist="wordlists/default_ip_list.txt"

# Settings
declare -A enable_methods_fuzz=( ["enabled"]=false ["wordlist"]=$default_methods_wordlist )
declare -A enable_userAgents_fuzz=( ["enabled"]=false ["wordlist"]=$default_userAgents_wordlist )
declare -A enable_headers_fuzz=( ["enabled"]=false ["wordlist"]=$default_headers_wordlist )
declare -A enable_path_fuzz=( ["enabled"]=true ["endpaths_wordlist"]=$default_endpaths_wordlist ["midpaths_wordlist"]=$default_midpaths_wordlist )
enable_other_payloads=false

#
total_finds=()  # working payloads
interesting_finds=() # to check payloads
file_buffer=()
legit_http_req_size=   # size of the legit HTTP request
total_requests=0


_ascii_art() {

    echo "

# ###################################################################################
# #  _  _    ___ _____   ____                                                       #
# # | || |  / _ \___ /  | __ ) _   _ _ __   __ _ ___ ___                            #
# # | || |_| | | ||_ \  |  _ \| | | | '_ \ / _' / __/ __|                           #
# # |__   _| |_| |__) | | |_) | |_| | |_) | (_| \__ \__ \                           #
# #    |_|  \___/____/  |____/ \__, | .__/_\__,_|___/___/               _       _   #
# #   __ _ _   _| |_ ___  _ __ |___/|_| _| |_ ___  __| |  ___  ___ _ __(_)_ __ | |_ #
# #  / _' | | | | __/ _ \| '_ ' _ \ / _' | __/ _ \/ _' | / __|/ __| '__| | '_ \| __|#
# # | (_| | |_| | || (_) | | | | | | (_| | ||  __/ (_| | \__ \ (__| |  | | |_) | |_ #
# #  \__,_|\__,_|\__\___/|_| |_| |_|\__,_|\__\___|\__,_| |___/\___|_|  |_| .__/ \__|#
# #                                                                      |_|        #
# ###################################################################################

"

}

_help() {
    
    echo -e "\n${yellow}Help${end}"
    echo "This script automates some of the most common methods to bypass 403 and 401 HTTP errors."
    echo "If no options are specified, the script will only run directory fuzzing."
    echo "If no wordlists are specified, the script will use default wordlists."

    echo -e "\nIf you dont have the default wordlists, download them at: ${cyan}https://github.com/JohnNeve/Tools/tree/main/403-bypass${end}"
    echo -e "Or run the command: ${cyan}./403_bypass.sh --download-wordlists${end}"

    echo -e "\n${yellow}Usage:${end}"
    echo -e 'Example: ./403-bypass.sh "http://www.example.com" "/path_to_bypass" -m'

    echo -e "\n$warning To follow the script logic, don't put '$cyan/$end' at the end of the URL"

    echo -e "\n${yellow}Options:${end}"

    echo -e "${cyan}-dir [endpaths_wordlist.txt] [midpaths_wordlist.txt]${end}:\n\t\t Use different wordlist(s) to perform directory fuzzing"
    echo -e "\t\t This tool manipulate the URL as follows: http:/target.com:1337/${yellow}midpaths${end}/endpoint/${yellow}endpaths${end}"
    echo -e "\t\t Endpaths are collected from [custom_wordlist.txt] or [$default_endpaths_wordlist]"
    echo -e "\t\t Midpaths are collected from [custom_wordlist.txt] or [$default_midpaths_wordlist]"
    echo -e "\t\t Not specifying a midpaths wordlist, the default one will be loaded"
    echo -e "\t\t [+] examples: ./403_bypass.sh http://www.example.com /path -dir /path/to/wordlist.txt"
    echo -e "\t\t               ./403_bypass.sh http://www.example.com /path -dir /path/to/endpaths.txt /path/to/midpaths.txt"

    echo -e "${cyan}-u [wordlist]${end} | ${cyan}--usragents [wordlist]${end}:\n\t\t Enable user agent fuzzing"
    echo -e "\t\t If no wordlist specified, the default will be loaded ($default_userAgents_wordlist)"
    echo -e "\t\t [+] example: ./403_bypass.sh http://www.example.com /path -u\n"

    echo -e "${cyan}-m [wordlist] ${end}| ${cyan}--methods [wordlist]${end}:\n\t\t Enable HTTP methods fuzzing"
    echo -e "\t\t If no wordlist specified, the default will be loaded ($default_methods_wordlist)"
    echo -e "\t\t [+] example: ./403_bypass.sh http://www.example.com /path --methods /path/to/wordlist.txt\n"

    echo -e "${cyan}-hd [wordlist] ${end}| ${cyan}--headers [wordlist]${end}:\n\t\t Enable HTTP headers fuzzing"
    echo -e "\t\t If no wordlist specified, the default will be loaded ($default_headers_wordlist)"
    echo -e "\t\t [+] example: ./403_bypass.sh http://www.example.com /path --headers\n"

    echo -e "${cyan}-o ${end}| ${cyan}--others ${end}:\n\t\t Try other payloads:"
    echo -e "\t\t     -- URL characters alter case"
    echo -e "\t\t     -- HTTP version up(down)grade"
    echo -e "\t\t\t[+] example: ./403_bypass.sh http://www.example.com /path --others\n"

    echo -e "${cyan}-s ${end}| ${cyan}--skip${end}:\n\t\t Skip path fuzzing"
    echo -e "\t\t [+] example: ./403_bypass.sh http://www.example.com /path -u -h -s\n"

    echo -e "${cyan}-h${end} | ${cyan}--help${end} | ${cyan}--h${end}:\n\t\t Show this message and exit"
    echo -e "\t\t [+] example: ./403_bypass.sh --help\n"
}

_parse_args() {

    local position=1

    while [[ $# -gt 0 ]]
    do
        case "$1" in

            -h|--help|--h)
                _help
                exit 0
                ;;

            -m|--methods)
                
                if [ $m_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}--methods${end} flag already setted!"
                    exit 1
                fi

                if [[ $# -gt 1 && "$2" != -* ]]
                then

                    if [ ! -f $2 ]; then
                        echo -e "$error Argument $cyan$2$end: file not found!"
                        exit 1
                    fi

                    enable_methods_fuzz["enabled"]=true
                    enable_methods_fuzz["wordlist"]=$2
                    shift
                else
                    enable_methods_fuzz["enabled"]=true
                fi

                local m_set=true
                ;;

            -u|--usragents)

                if [ $u_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}--useragents${end} flag already setted!"
                    exit 1
                fi

                if [[ $# -gt 1 && "$2" != -* ]]
                then

                    if [ ! -f $2 ]; then
                        echo -e "$error Argument $cyan$1$end: file not found!"
                        exit 1
                    fi

                    enable_userAgents_fuzz["enabled"]=true
                    enable_userAgents_fuzz["wordlist"]=$2
                    shift
                else
                    enable_userAgents_fuzz["enabled"]=true
                fi

                local u_set=true
                ;;

            -hd|--headers)

                if [ $hd_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}$1${end} flag already setted!"
                    exit 1
                fi

                if [[ $# -gt 1 && "$2" != -* ]]
                then

                    if [ ! -f $2 ]; then
                        echo -e "$error Argument $cyan$1$end: file not found!"
                        exit 1
                    fi

                    enable_headers_fuzz["enabled"]=true
                    enable_headers_fuzz["wordlist"]=$2
                    shift
                else
                    enable_headers_fuzz["enabled"]=true
                fi

                local hd_set=true
                ;;

            -s|--skip)

                if [ $s_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}--skip${end} flag already setted!"
                    exit 1
                fi

                enable_path_fuzz["enabled"]=false

                local s_set=true
                ;;

            -dir|--dir)

                if [ $dir_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}--dir${end} flag already setted!"
                    exit 1
                fi

                if [[ $# -gt 1 && "$2" != -* ]]
                then

                    if [ ! -f $2 ]; then
                        echo -e "$error Argument $cyan$1$end: file not found!"
                        exit 1
                    fi

                    enable_path_fuzz["endpaths_wordlist"]=$2
                    shift

                    if [[ $# -gt 1 && "$2" != -* ]]
                    then

                        if [ ! -f $2 ]; then
                        echo -e "$error Argument $cyan$1$end: file not found!"
                        exit 1
                        fi

                        enable_path_fuzz["midpaths_wordlist"]=$2
                        shift

                    fi

                else
                    echo -e "$error ${cyan}$i${end} flag need at least one argument!"
                    exit 1
                fi

                local dir_set=true
                ;;

            -o|--others)

                if [ $others_set ]
                then
                    echo -e "$error Parsing argument error: ${cyan}$1${end} flag already setted!"
                    exit 1
                fi

                enable_other_payloads=true

                local others_set=true
                ;;

            --download-files)

                mkdir -p wordlists

                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/default_midpaths.txt" "wordlists/default_midpaths"
                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/default_endpaths.txt" "wordlists/default_endpaths"
                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/default_ip_list.txt" "wordlists/default_ip_list"
                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/default_headers.txt" "wordlists/default_headers"
                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/default_methods.txt" "wordlists/default_methods"
                _download_files "https://raw.githubusercontent.com/JohnNeve/Tools/main/403-bypass/wordlists/deafult_UserAgents.fuzz.txt" "wordlists/default_UserAgents.fuzz"

                exit 0
                ;;

            -*)

                echo -e "$error Invalid flag: $1"
                exit 1
                ;;

            *)

                if [ $position -eq 1 ]
                then
                    url="$1"
                elif [ $position -eq 2 ]
                then
                    path="$1"
                fi
                (( position++ ))
                ;;

        esac
        
        shift

    done

    if [ -z "$url" ]
    then
        echo -e "\n${error} URL is required."
        exit 1
    fi

    if [ -z "$path" ]
    then
        echo -e "\n${error} Path to bypass is required."
        exit 1
    fi

}

_print_results() {

    echo -e "\n$success ${yellow}End of script$end"

    if [ "${#interesting_finds[@]}" != 0 ]; then
        echo -e "\n$warning Other results to check:"

        for element in "${interesting_finds[@]}"; do
	        echo -e "$warning $element"
        done
    fi

    echo -e "${cyan}[↑]${end} Other results to check"
    echo -e "\n[+] Results:"

    if [ "${#total_finds[@]}" == 0 ]; then
        echo -e "$error No relevant results..."
    else
        for element in "${total_finds[@]}"; do
	        echo -e "$success $element"
        done
    fi

    echo -e "\n$warning Total requests: $yellow$total_requests$end"
    exit 0
}

_print_choices() {

    echo -e "$information Settings"

    echo -e "-- URL >> $yellow$url$end"
    echo -e "-- PATH >> $yellow$path$end"

    if ${enable_path_fuzz[enabled]}; then
        echo -e "-- Directory Fuzzing: ${green}Enabled${end}"
        echo -e "-- Directory Fuzzing Endpaths Wordlist: $yellow${enable_path_fuzz[endpaths_wordlist]}$end"
        echo -e "-- Directory Fuzzing Midpaths Wordlist: $yellow${enable_path_fuzz[midpaths_wordlist]}$end"
    else
        echo -e "-- Directory Fuzzing: ${red}Disabled${end}"
    fi

    if ${enable_methods_fuzz[enabled]}; then
        echo -e "-- HTTP Methods Fuzzing: ${green}Enabled${end}"
        echo -e "-- HTTP Methods Fuzzing Wordlist: ${yellow}${enable_methods_fuzz[wordlist]}${end}"
    else
        echo -e "-- HTTP Methods Fuzzing: ${red}Disabled${end}"
    fi

    if ${enable_userAgents_fuzz[enabled]}; then
        echo -e "-- User Agents Fuzzing: ${green}Enabled${end}"
        echo -e "-- User Agents Fuzzing Wordlist: ${yellow}${enable_userAgents_fuzz[wordlist]}${end}"
    else
        echo -e "-- User Agents Fuzzing: ${red}Disabled${end}"
    fi

    if ${enable_headers_fuzz[enabled]}; then
        echo -e "-- HTTP Headers Fuzzing: ${green}Enabled${end}"
        echo -e "-- HTTP Headers Fuzzing Wordlist: ${yellow}${enable_headers_fuzz[wordlist]}${end}"
    else
        echo -e "-- HTTP Headers Fuzzing: ${red}Disabled${end}"
    fi

    if ${enable_other_payloads}; then
        echo -e "-- Other Bypass Methods: ${green}Enabled${end}"
    else
        echo -e "-- Other Bypass Methods: ${red}Disabled${end}"
    fi

}

_read_file() {

    file=$1
    file_buffer=()

    while IFS= read -r string
    do
        file_buffer+=("$string")
    done < $file

}

_test_connection() {

    echo -e "\n$information Checking connection..."

    read -r http_code size_download <<< $(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$path")

    if [ "$http_code" -ne 200 ] && [ "$http_code" -ne 401 ] && [ "$http_code" -ne 403 ]
    then
        echo -e "$error HTTP code: $http_code"
        echo -e "$error Error reaching the server"
        exit 1
    fi

    echo -e "$success Connection ${yellow}OK$end"

    legit_http_req_size=$size_download
    echo -e "$success Size download: $yellow$legit_http_req_size$end\n"

}

_download_files() {

    local url=$1
    local filename=$2

    echo -e "\n$information Downloading $yellow$filename$end..."
    curl --output $filename.txt "$url"

}

_check_wordlist() {

    if [ ! -f $1 ]
    then

        echo -e "\n$error Can't find the wordlist $cyan$1$end"
        echo -e "$error Please check the wordlist path or, if you are using the default wordlist, make sure it is located in the same directory as the script${end}"
        exit 1

    fi

}

_check_http_codes() {

    local message=$1

    case $http_code in

        200 | 201 | 202)
            echo -e "$success $message ${end}-- HTTP code: $green$http_code$end -- Size download: $green$size_download$end"
            total_finds+=("HTTP code: $green$http_code$end -- Size download: $size_download -- $message ${end}")
            
            ;;
        
        404 | 000)

            echo -e "$warning $message ${end}-- HTTP code: $red$http_code$end -- Size download: $red$size_download$end"
            interesting_finds+=("HTTP code: $red$http_code$end -- Size download: $size_download -- $message ${end}")
            ;;

        *)

            if [[ "$http_code" != 403 && "$http_code" != 401 && "$http_code" != 200 && "$http_code" != 000  && "$http_code" != 404 && "$http_code" != 201 && "$http_code" != 202 ]]
            then
            
                echo -e "$warning $message ${end}-- HTTP code: $yellow$http_code$end -- Size download: $yellow$size_download$end"

            else

                echo -e "[:] $message ${end}-- HTTP code: $http_code -- Size download: $size_download"

            fi
            ;;

    esac

}

_dir_fuzzing() {

    echo -e "$information Path fuzzing bypass"

    _check_wordlist "${enable_path_fuzz[endpaths_wordlist]}"
    _check_wordlist "${enable_path_fuzz[midpaths_wordlist]}"

    _read_file "${enable_path_fuzz[endpaths_wordlist]}"
    local endpaths=("${file_buffer[@]}")

    _read_file "${enable_path_fuzz[midpaths_wordlist]}"
    local midpaths=("${file_buffer[@]}")

    file_buffer=()

    echo -e "$information Collected $cyan$(( ${#endpaths[@]} + ${#midpaths[@]} ))$end words."

    for endpath in ${endpaths[@]}
    do
        
        read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url$path${endpath}")"

        (( total_requests++ ))

        _check_http_codes "Payload: $yellow$url$path$endpath$end"

    done

    for midpath in ${midpaths[@]}
    do
        
        read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$url${midpath}$path")"

        (( total_requests++ ))

        _check_http_codes "Payload: $yellow$url$midpath$path"

    done

}

_methods_fuzzing() {

    echo -e "\n$information ${yellow}HTTP methods fuzzing${end}"

    _check_wordlist "${enable_methods_fuzz[wordlist]}"

    _read_file "${enable_methods_fuzz[wordlist]}"
    local http_methods=("${file_buffer[@]}")

    file_buffer=()

    echo -e "$information Collected $cyan${#http_methods[@]}$end words."

    for payload in ${http_methods[@]}
    do
        
        read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -X $payload "$url$path")"

        (( total_requests++ ))

        _check_http_codes "HTTP method: $yellow$payload$end"

    done

    read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" --head "$url$path")"

    (( total_requests++ ))

    _check_http_codes "HTTP method: HEAD"

}

_headers_fuzzing() {

    echo -e "\n$information ${yellow}Headers fuzzing${end}"

    _check_wordlist "${enable_headers_fuzz[wordlist]}"
    _check_wordlist "${default_ip_wordlist}"

    _read_file "${enable_headers_fuzz[wordlist]}"
    local headers=("${file_buffer[@]}")

    _read_file "$default_ip_wordlist"
    local ips=("${file_buffer[@]}")

    file_buffer=()
    
    echo -e "$information Collected $yellow$(( ${#headers[@]} + ${#ips[@]} ))$end words"

	for method in "${headers[@]}"
    do

			echo -e "\n$information $yellow$method$end"

			for ip in "${ips[@]}"
            do
			
				read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -H "$method$ip" "$url$path")"
				
				(( total_requests++ ))

                _check_http_codes "Header: $yellow$method$ip$end"
			
			done

	done

}

_userAgents_fuzz() {

    echo -e "\n$information ${yellow}User Agents fuzzing${end}"

    _check_wordlist "${enable_userAgents_fuzz[wordlist]}"

    _read_file "${enable_userAgents_fuzz[wordlist]}"
    local user_agents=("${file_buffer[@]}")

    file_buffer=()

    echo -e "$information Collected $cyan${#user_agents[@]}$end words."

    for user_agent in "${user_agents[@]}"
    do
        
        read -r http_code size_download <<< "$(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" -A "$user_agent" "$url$path")"

        (( total_requests++ ))

        _check_http_codes "User Agent: $yellow$user_agent$end"

    done

}

_alter_case_URL() {

    __generate_upper_string() {

        substr="${temp:$i:$j}"

        up_substr="${substr^^}"

        uppercase_path="${temp/"$substr"/"$up_substr"}"

        altered_url=$url$uppercase_path

    }

    echo -e "\n$information URL case switching"

    temp=

    ignore_char=

    for ((i=0; i<${#path}; i++))
    do

        temp="$path"

        char="${temp:$i:1}"

        if [[ $char == '\' ]] || [[ $char == "/" ]] || [[ $char == *['!'@#\$%^\&*()_+]* ]]; then
            continue
        fi

        for ((j=i+1; j<${#path}; j++))
        do

            __generate_upper_string

            read -r http_code size_download <<< $(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" "$altered_url")

            _check_http_codes "Payload: $yellow$altered_url$end"

        done

    done

}

_change_HTTP_version() {

    echo -e "\n$information Changing HTTP version"

    http_versions=("--http1.0" "--http1.1" "--http2" "--http2-prior-knowledge")

    for command in "${http_versions[@]}"
    do

        read -r http_code size_download <<< $(curl -s -o /dev/null -iL -w "%{http_code} %{size_download}" $command "$url$path")

        _check_http_codes "HTTP version: $yellow$command$end"

    done

}

_parse_args "$@"

_ascii_art

_print_choices

_test_connection

if ${enable_path_fuzz[enabled]}; then
    _dir_fuzzing
fi

if ${enable_methods_fuzz[enabled]}; then
    _methods_fuzzing
fi

if ${enable_headers_fuzz[enabled]}; then
    _headers_fuzzing
fi

if ${enable_userAgents_fuzz[enabled]}; then
    _userAgents_fuzz
fi

if ${enable_other_payloads}; then
    _alter_case_URL
    _change_HTTP_version
fi

_print_results
