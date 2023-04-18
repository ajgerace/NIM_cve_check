# NGINX_nim_cve_check
Python script to download the latest NGINX security advisory file and checking the NGINX Instance Manager installbase to check for vulnerable devices.

This script will prompt user for NIM user and password along with name and/or address of the NGINX Instance Manager.  It will retrieve a list of managed NGINX instances and then download the latest security advisory file from NGINX.org.  It compares the version of each of the managed instances and provides a output list of the devices and its vulnerabilities.

```
$ python3 nginx_nim_cve_check.py 
Enter NGINX NIM User name: admin
Enter NGINX NIM password: 
Enter the hostname or IP address for your NIM instance: 192.168.0.228

******** nginx02.f5demo.org - NginxPlus - 1.21.3 ********
	**** Vulnerability ****
	Name: Memory corruption in the ngx_http_mp4_module
	Severity: medium
	CVE: 2022-41741
	URL:http://mailman.nginx.org/pipermail/nginx-announce/2022/RBRRON6PYBJJM2XIAPQBFBVLR4Q6IHRA.html
	Vulnerable versions: 1.1.3-1.23.1, 1.0.7-1.0.15

	**** Vulnerability ****
	Name: Memory disclosure in the ngx_http_mp4_module
	Severity: medium
	CVE: 2022-41742
	URL:http://mailman.nginx.org/pipermail/nginx-announce/2022/RBRRON6PYBJJM2XIAPQBFBVLR4Q6IHRA.html
	Vulnerable versions: 1.1.3-1.23.1, 1.0.7-1.0.15


******** nginx01.f5demo.org - NginxPlus - 1.21.3 ********
	**** Vulnerability ****
	Name: Memory corruption in the ngx_http_mp4_module
	Severity: medium
	CVE: 2022-41741
	URL:http://mailman.nginx.org/pipermail/nginx-announce/2022/RBRRON6PYBJJM2XIAPQBFBVLR4Q6IHRA.html
	Vulnerable versions: 1.1.3-1.23.1, 1.0.7-1.0.15

	**** Vulnerability ****
	Name: Memory disclosure in the ngx_http_mp4_module
	Severity: medium
	CVE: 2022-41742
	URL:http://mailman.nginx.org/pipermail/nginx-announce/2022/RBRRON6PYBJJM2XIAPQBFBVLR4Q6IHRA.html
	Vulnerable versions: 1.1.3-1.23.1, 1.0.7-1.0.15

```
