403-Bypass 
====

This is a simple script to automate attacks to bypass 403 and 401 HTTP forbidden errors.
<br><br>

<img src="images/preview.png" alt="preview">

Usage
----------
This script works with wordlists. You can use default wordlists by retrieving them with <code> ./403-bypass.sh --download-files </code> or specify others.
If no wordlists are specified, the script will use the default ones.

For example:

    ./403-bypass.sh "http://example.com" "/endpoint"

    ./403-bypass.sh "http://example.com" "/endpoint" "custom_wordlist1.txt" "custom_wordlist2.txt"

Options
----------

- <code>-dir [endpaths_wordlist.txt] [midpaths_wordlist.txt]</code>: Use different wordlist(s) to perform directory fuzzing, considering that this tool manipulates the URL as follows: <b>http:/target.com:1337/midpaths/endpoint/endpaths</b>.


    ./403-bypass.sh "http://example.com" "/endpoint" --dir /custom_endpaths_wordlist.txt

    ./403-bypass.sh "http://example.com" "/endpoint" --dir /custom_endpaths_wordlist.txt /custom_midpaths_wordlist.txt


<code>-dir [endpaths_wordlist.txt] [midpaths_wordlist.txt]</code>: Use different wordlist(s) to perform directory fuzzing, considering that this tool manipulates the URL as follows: <b>http:/target.com:1337/midpaths/endpoint/endpaths</b>.
