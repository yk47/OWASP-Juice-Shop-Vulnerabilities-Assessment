# OWASP-Juice-Shop-Vulnerabilities-Assessment
Identify and fix vulnerabilities such as SQL Injection, XSS, and in secure login flows in OWASP Juice Shop.

To break down the Juice Shop website and hack into it to discover vulnerabilities, all the while understanding the limits and preserving the integrity of a target. After discovering vulnerabilities documenting the vulnerability in a general report would help people from other technology backgrounds would understand the severity of a vulnerability.
The objective is to break down the Juice Shop website and identify vulnerabilities while respecting the target’s limits and preserving its integrity. After discovering issues, I document each vulnerability in a clear report so professionals from other technical backgrounds can understand the severity and impact.

Title: E-Commerce Juice Shop Website  vulnerability assessment  report

Target Machine IP: 192.168.0.160
Description:
This machine hosts the OWASP Juice Shop web application, which was assessed for common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Broken Authentication, and Insecure Access Controls.

<img width="939" height="505" alt="image" src="https://github.com/user-attachments/assets/158a2196-db11-4ab2-8651-b3bf6f7a72ab" />


Lets ping and check the response from the machine 
<img width="939" height="480" alt="image" src="https://github.com/user-attachments/assets/2834b2fb-3fb5-405e-9f15-cefae659a992" />

scanning and reconnaissance

nmap scan on 192.168.0.160
nmap -sC -A -oN CapstonScan.txt 192.168.0.160



Output:-
# Nmap 7.94SVN scan initiated Sat Sep 13 16:30:02 2025 as: nmap -sC -A -oN CapstonScan.txt 192.168.0.160
Nmap scan report for 192.168.0.160
Host is up (0.0010s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
20/tcp   closed ftp-data
21/tcp   closed ftp
80/tcp   open   http       Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open   ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     Feature-Policy: payment 'self'
|     X-Recruiting: /#/jobs
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Wed, 22 Jan 2025 10:17:49 GMT
|     ETag: W/"7c3-1948d84a8cc"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 1987
|     Vary: Accept-Encoding
|     Date: Sat, 13 Sep 2025 11:00:19 GMT
|     Connection: close
|     <!--
|     Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
|     SPDX-License-Identifier: MIT
|     --><!DOCTYPE html><html lang="en"><head>
|     <meta charset="utf-8">
|     <title>OWASP Juice Shop</title>
|     <meta name="description" content="Probably the most modern and sophisticated insecure web application">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link id="favicon" rel="icon" type="image/x-icon" href="asset
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 204 No Content
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
|     Vary: Access-Control-Request-Headers
|     Content-Length: 0
|     Date: Sat, 13 Sep 2025 11:00:20 GMT
|     Connection: close
|   Help, NCP: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
8080/tcp closed http-proxy
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=1/22%Time=6790CFC4%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,979,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:
SF:\x20\*\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20SAM
SF:EORIGIN\r\nFeature-Policy:\x20payment\x20'self'\r\nX-Recruiting:\x20/#/
SF:jobs\r\nAccept-Ranges:\x20bytes\r\nCache-Control:\x20public,\x20max-age
SF:=0\r\nLast-Modified:\x20Wed,\x2022\x20Jan\x202025\x2010:17:49\x20GMT\r\
SF:nETag:\x20W/\"7c3-1948d84a8cc\"\r\nContent-Type:\x20text/html;\x20chars
SF:et=UTF-8\r\nContent-Length:\x201987\r\nVary:\x20Accept-Encoding\r\nDate
SF::\x20Wed,\x2022\x20Jan\x202025\x2011:00:19\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n<!--\n\x20\x20~\x20Copyright\x20\(c\)\x202014-2022\x20Bjoern\
SF:x20Kimminich\x20&\x20the\x20OWASP\x20Juice\x20Shop\x20contributors\.\n\
SF:x20\x20~\x20SPDX-License-Identifier:\x20MIT\n\x20\x20--><!DOCTYPE\x20ht
SF:ml><html\x20lang=\"en\"><head>\n\x20\x20<meta\x20charset=\"utf-8\">\n\x
SF:20\x20<title>OWASP\x20Juice\x20Shop</title>\n\x20\x20<meta\x20name=\"de
SF:scription\"\x20content=\"Probably\x20the\x20most\x20modern\x20and\x20so
SF:phisticated\x20insecure\x20web\x20application\">\n\x20\x20<meta\x20name
SF:=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\
SF:x20\x20<link\x20id=\"favicon\"\x20rel=\"icon\"\x20type=\"image/x-icon\"
SF:\x20href=\"asset")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:nection:\x20close\r\n\r\n")%r(NCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,EA,"HTTP/1\.1\x20204\
SF:x20No\x20Content\r\nAccess-Control-Allow-Origin:\x20\*\r\nAccess-Contro
SF:l-Allow-Methods:\x20GET,HEAD,PUT,PATCH,POST,DELETE\r\nVary:\x20Access-C
SF:ontrol-Request-Headers\r\nContent-Length:\x200\r\nDate:\x20Wed,\x2022\x
SF:20Jan\x202025\x2011:00:20\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RT
SF:SPRequest,EA,"HTTP/1\.1\x20204\x20No\x20Content\r\nAccess-Control-Allow
SF:-Origin:\x20\*\r\nAccess-Control-Allow-Methods:\x20GET,HEAD,PUT,PATCH,P
SF:OST,DELETE\r\nVary:\x20Access-Control-Request-Headers\r\nContent-Length
SF::\x200\r\nDate:\x20Wed,\x2022\x20Jan\x202025\x2011:00:20\x20GMT\r\nConn
SF:ection:\x20close\r\n\r\n");
MAC Address: 08:00:27:AE:72:38 (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 5.0 - 5.4 (98%), Linux 4.15 - 5.8 (94%), Linux 5.0 - 5.5 (93%), Linux 2.6.32 - 3.13 (93%), Linux 2.6.39 (93%), Linux 2.6.22 - 2.6.36 (91%), Linux 3.10 - 4.11 (91%), Linux 5.1 (91%), Linux 5.0 (91%), Linux 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.04 ms 192.168.0.160

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
 Nmap done at Sat Sep 13 16:30:29 2025 -- 1 IP address (1 host up) scanned in 26.90 seconds


Lets check the website

192.168.0.160
<img width="939" height="513" alt="1" src="https://github.com/user-attachments/assets/dd648a40-92dc-46c3-aba7-377fe78ec66b" />


As we can see there only default page

port number 80,3000 is open lets check it out with port 80 first

192.168.0.160:80 or 8080

<img width="939" height="513" alt="2" src="https://github.com/user-attachments/assets/4395e027-ccba-43d4-9b07-472ecd435adb" />

No response from port 80 or 8080

192.168.0.160:3000
<img width="939" height="511" alt="3" src="https://github.com/user-attachments/assets/a1a1a654-ec4a-4d7f-8387-c99e0b955160" />

We got the website called OWASP Juice shop

Let's try to crack it and find some vulnerabilities into it
# Vulnerability 1:- Title: Zero Stars (Improper Input Validation)

Description:
Improper input validation is a security flaw where an application or system does not adequately check or sanitize user-provided input. This weakness can enable attackers to inject harmful code or data, potentially leading to unauthorized access, data theft, or other malicious activities.

Steps to Reproduce:
Navigated through the customer Feedback and turned on Burpsuite to capture the request
<img width="819" height="445" alt="4" src="https://github.com/user-attachments/assets/53ead79d-2185-4987-9041-775e6252122f" />
<img width="872" height="475" alt="5" src="https://github.com/user-attachments/assets/beececeb-2840-47e2-be01-ba9fb30b290d" />

User should Changed the rating to 0 which is impossible to give as the least rating

1. Then forwarded the request. Then got the pop-up solved the challenged Zero-stars
<img width="939" height="512" alt="6" src="https://github.com/user-attachments/assets/20a0be90-6bed-4532-8af2-2ae4754d0f9c" />

Here we can change the rating value to 0 and forward it
<img width="939" height="513" alt="7" src="https://github.com/user-attachments/assets/bbe4ea54-eaeb-4b15-9408-52406521bd18" />

2. After forwarding the request with 0 ratings we see this
<img width="939" height="513" alt="8" src="https://github.com/user-attachments/assets/4e18718c-a384-4db8-97b3-68c925da7bd5" />

Impact:
Improper input validation can lead to serious consequences, such as:
-	Unauthorized access to sensitive data.
-	The ability for attackers to act on behalf of other users.
-	Performing restricted actions.
-	Enabling more severe attacks like SQL injection or code execution.
-	Using the flaw to initiate denial-of-service (DoS) attacks.
- To prevent these risks, it's essential to:
-	Validate and sanitize user input thoroughly.
-	Implement server-side input validation.
-	Use a whitelist approach to define acceptable input.
-	Properly encode user input to avoid unintended behavior.
-	Leverage security libraries specifically designed for input validation.
- These measures help protect systems from such vulnerabilities.



# Vulnerability 2:- Title: Confidential Document (Sensitive Data Exposure)

Description:
Sensitive data exposure occurs when attackers exploit system vulnerabilities to access confidential information, such as financial details, PINs, or health records. Common causes include inadequate encryption, weak access controls, or poor data management practices.


Steps to Reproduce:
Using BurpSuit, I discovered the /ftp directory and found various documents, including backups, error reports, and confidential company files. I downloaded the acquisitions.md file.

1.Go to About Us page and Open that link you will rederect to /ftp/legal.md
<img width="939" height="512" alt="9" src="https://github.com/user-attachments/assets/766986c3-4948-43e2-9639-33340f4d653c" />

2. Open Burpsuit and intercept the traffic -> send it to repeater -> send the request with only /ftp
we found acquisition.md file
<img width="939" height="513" alt="10" src="https://github.com/user-attachments/assets/e4a85b5c-4a64-4211-aedc-cf6437dbf46f" />

3.Send the request with /ftp/ acquisitions.md
<img width="939" height="512" alt="11" src="https://github.com/user-attachments/assets/334f019a-4c7c-4e18-a5e7-b20e6a30dc4e" />

We found the Confidential Document
<img width="939" height="515" alt="12" src="https://github.com/user-attachments/assets/485d6eb6-dfca-4b26-a0ce-28a70c9403fe" />

Impact:
Sensitive data exposure can lead to:
-	Financial losses for individuals or organizations due to stolen information.
-	Loss of customer trust and confidence.
-	Legal penalties or fines for non-compliance with regulations like HIPAA, PCI-DSS, and GDPR.
-	Damage to the organization’s reputation and negative media coverage.
To prevent such attacks, organizations must prioritize secure data storage and transmission, conduct regular system audits, and train employees in proper data handling practices.



# Vulnerability 3:- Title: DOM XSS (Cross-Site Scripting)

Description:
Cross-Site Scripting (XSS) is a web vulnerability where attackers inject malicious scripts into web pages that are then executed by other users' browsers. This happens when an application fails to validate and sanitize user input before reflecting it back to the web page. For instance, JavaScript-based XSS was executed via the search bar, allowing the injected code to run in the victim's browser.


Stepsto Reproduce:
By injecting the payload <iframe src="javascript:alert('juice shop')"> into the search bar, a pop-up alert displaying "juice shop" appeared, along with a blank iframe. This confirms that the payload was successfully executed.
<img width="939" height="515" alt="13" src="https://github.com/user-attachments/assets/fbbf3c47-3129-4ee5-9b41-e657ee36d513" />


Impact:

Cross-Site Scripting (XSS) attacks can have significant consequences, including:
-	Theft of Sensitive Information: Attackers can steal cookies, session tokens, and personal data. 
-	Unauthorized Actions: Malicious scripts can perform actions on behalf of the user, such as unauthorized transactions or posting harmful content. 
-	Redirection to Malicious Sites: Users can be redirected to harmful websites. 
-	Malware Distribution: Attackers can spread malware to users' devices. 
-	Propagation of Attacks: Malicious scripts can spread to other users if they are able to propagate themselves. 
To prevent XSS attacks, it's essential to:
-	Validate and Sanitize User Input: Ensure that all user inputs are properly validated and sanitized to prevent malicious code injection. 
-	Encode User Input: Properly encode user inputs to prevent them from being interpreted as executable code. 
-	Use Security Libraries: Implement security libraries specifically designed for XSS protection. 
-	Implement Content Security Policy (CSP): Utilize CSP headers to restrict the sources from which content can be loaded, reducing the risk of XSS attacks. 
By adopting these measures, organizations can significantly reduce the risk of XSS attacks and protect their users.



# Vulnerability 4:- Title: Error Handling (Security Misconfiguration)

Description:
Security misconfiguration occurs when an application or system is not set up correctly, leaving it exposed to attacks. This can result from issues like using default settings, weak passwords, or not applying security updates. These vulnerabilities make it easier for attackers to access sensitive data or perform unauthorized actions.
Stepsto Reproduce:
I intercepted a valid request from the web app using Burp Suite and modified the GET request to an invalid file path (/rest/Mahesh). This triggered an internal server error (500 response), revealing sensitive server information. Exposing such error messages is a security risk because it gives attackers insight into the server's state, allowing them to adjust their attack strategy accordingly.


1.Click on any product and in the BurpSuit history send it to repeter
<img width="939" height="512" alt="14" src="https://github.com/user-attachments/assets/5e36116a-2749-4e09-964c-8342ebc92769" />

2.In the repeater send the request with /rest/hacksplane
<img width="939" height="513" alt="15" src="https://github.com/user-attachments/assets/147c611f-10b3-4ca0-b965-33a8ddb7604a" />


And we Got it
<img width="939" height="513" alt="16" src="https://github.com/user-attachments/assets/cbf625e8-da3b-4cc0-913c-379dfd849fe8" />


Impact:
A successful security misconfiguration attack can lead to:
-	Unauthorized access to sensitive information.
-	The ability to act on behalf of another user.
-	Performing actions that should be restricted.
-	Launching additional attacks like data theft or privilege escalation.
-	Damage to system and data integrity.
To prevent such attacks, organizations should regularly review and monitor system and application configurations, follow security best practices, keep systems updated with the latest security patches, and use security frameworks designed for configuration management.



# Vulnerability 5:- Title: Missing Encoding ( improper input validation)

Description:
When software fails to properly validate input, an attacker can manipulate the input in unexpected ways, causing parts of the system to receive incorrect or malicious data. This can lead to unintended changes in how the system functions, such as altered behavior, unauthorized control over resources, or even the execution of arbitrary code.

Stepsto Reproduce:
I visited the Photowall page and noticed that a photo wasn't displayed. Using the Inspector tool, I examined the source code and discovered that the file path for the photo contained a #, indicating that the link wasn't properly connected and was being treated as a separate path.
<img width="939" height="513" alt="17" src="https://github.com/user-attachments/assets/946980d3-72e1-429a-ab30-17725244a2c4" />

 Using CyberChef with the URL encoding option, I replaced the # with its encoded form %23 in the source path within the source code. After making the change, I refreshed the page.
<img width="939" height="513" alt="18" src="https://github.com/user-attachments/assets/a36bb697-9ae3-4816-9116-77a0b5a3e707" />
<img width="939" height="513" alt="19" src="https://github.com/user-attachments/assets/ee0b8d3d-81a2-4c37-b75f-e897bd5a4868" />

Got the pop-up as the solved the challenge Missing Encoding

Impact:
A successful improper input validation attack can lead to:
-	Unauthorized access to sensitive data.
-	The ability to act on behalf of another user.
-	Performing actions that should be restricted.
-	Enabling further attacks like SQL injection or code execution.
-	Potentially launching a denial-of-service (DoS) attack.
To prevent such attacks, it is crucial to validate and sanitize user input, enforce server-side input validation, adopt a whitelist approach for input data, properly encode user input, and utilize security libraries designed for input validation.



# Vulnerability 6:- Title: Outdated Allowlist (Unvalidated redirects)
Description:
Unvalidated redirects happen when a website or web application redirects users to another page or site without properly checking the destination URL. If the site uses user input to create the URL and doesn't validate it, attackers can craft malicious URLs that, when clicked, redirect users to harmful websites.
Stepsto Reproduce:
In the main.js which is the source code, search for the redirect links and got the blockchain address.

<img width="939" height="513" alt="20" src="https://github.com/user-attachments/assets/150eaec8-ab2d-4641-b966-7c48d91ecd53" />

https://www.blockchain.com/explorer/addresses/btc/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm

Redirect to Blockchain 
<img width="940" height="512" alt="21" src="https://github.com/user-attachments/assets/030e5362-768b-4e86-ba5b-bad1771d4119" />

We Solve it
<img width="940" height="515" alt="22" src="https://github.com/user-attachments/assets/6033634d-56dd-44ad-a457-efdc7fe0890c" />

Impact:
The impact of an unvalidated redirects attack includes:
-	Theft of sensitive information like cookies, session tokens, or personal data.
-	Unauthorized actions performed on the user’s behalf, such as fraudulent transactions or posting malicious content.
-	Redirecting users to phishing sites where their sensitive information can be stolen.
-	Distributing malware to the user’s device.
-	Spreading the attack to others if the malicious site propagates itself.
To prevent these attacks, it is essential to validate and sanitize user input, encode inputs properly, and use security libraries designed for redirect protection. Implementing Content Security Policy (CSP) headers can also help mitigate these risks.



# Vulnerability 7:- Title: Privacy Policy
Description:-
A Privacy Policy attack occurs when an attacker exploits weaknesses or misrepresents a company's privacy policy to access sensitive information or carry out malicious actions. This can result from vulnerabilities like inadequate disclosure, insufficient consent processes, or poor data handling practices.

Stepsto Reproduce:
Just read the privacy policy of the company by http://192.168.1.10:3000/#/privacysecurity/privacy-policy
Got the pop-up solved the challenge Privacy Policy
<img width="940" height="515" alt="23" src="https://github.com/user-attachments/assets/dc69a99c-d175-42f9-bf39-243726c3eb13" />

Impact:
The impact of a Privacy Policy attack can include:
-	Unauthorized access to sensitive data.
-	Loss of trust from customers or users due to mishandling of their information.
-	Legal fines or penalties for failing to comply with regulations like HIPAA, PCI-DSS, or GDPR.
-	Reputational damage and negative publicity for the organization.
To prevent such attacks, organizations should regularly review and update privacy policies, follow best practices for creating them, and ensure compliance with relevant regulations. Making the policy clear, transparent, and easy to understand while providing detailed information about data collection, usage, and sharing also helps mitigate these risks.



# Vulnerability 8:- Title: Repetitive Registration
Description:
Repetitive registration involves creating multiple accounts using the same personal information or repeatedly registering with identical details. This poses a security risk because an attacker who gains access to a user's personal information can exploit it to create multiple fake accounts, potentially harming the user or the system.

Steps to Reproduce:
On the registration page, I attempted to create a new user account. In the "repeat password" field, I initially entered a 5-character password and matched it in the "repeat password" field. Then, I added 2 more characters to the original password, making it 7 characters long, but did not update the "repeat password" field. Despite this mismatch, the registration was successfully completed with the original password of 7 characters and a repeated password of only 5 characters.
<img width="939" height="512" alt="24" src="https://github.com/user-attachments/assets/02caf3e4-0dbe-477a-bb1f-f61a24ecf1f4" />

Impact:
The impact of a successful Repetitive Registration attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- damage to the integrity of the system and data
- consume resources, such as storage or processing power, causing a Denial of Service
(DoS) attack.
Preventing Repetitive Registration attacks requires implementing robust anti-automation
controls, regularly reviewing and monitoring anti-automation controls, and using a ratelimiting approach to anti-automation controls. Additionally, using a security framework that
is specifically designed for anti-automation can also help prevent these types of attacks.


# Vulnerability 9:- Title: Login Admin (Sql Injection)
Description:
SQL injection is a security flaw where attackers insert malicious SQL code into a web application's input fields. This can enable unauthorized access to the database, allowing attackers to retrieve sensitive information, alter data, or even delete it.

Steps to Reproduce:
In the login section, under username gave a sql payload admin’ or 1=1— and a random string
a password. As this is vulnerable to sql injection. Got the admin account login
<img width="940" height="512" alt="25" src="https://github.com/user-attachments/assets/2a2cb691-647e-4da4-9652-a3d51ab08fc0" />
<img width="940" height="513" alt="26" src="https://github.com/user-attachments/assets/ba8f1ab0-2268-4402-bf16-081171fc6274" />

Got the pop up for the login success 


Impact:-
The consequences of a successful login admin attack include:
-	Gaining unauthorized access to sensitive information.
-	Acting on behalf of another user.
-	Performing restricted actions.
-	Enabling further attacks, such as stealing data or escalating privileges.
-	Compromising the system's integrity and data.
-	Potentially launching a denial-of-service (DoS) attack.
To prevent such attacks, it's essential to implement strong access controls, regularly audit and monitor access permissions, and adopt a least privilege principle. Additionally, using security frameworks tailored for access control can help mitigate these risks.



# Vulnerability 10:- Title: Admin Section (Broken Access Control)
Description:
Broken Access Control occurs when an application or system does not correctly enforce access restrictions, enabling attackers to access sensitive data or perform restricted actions. This vulnerability often arises from issues like weak authentication or improperly implemented access controls.

Steps to Reproduce:
By the Dirbuster output, navigated through the 192.168.1.10:3000/administration. Thus getting into the admin panel. Then the pop-up came a solved the challenge
<img width="940" height="515" alt="27" src="https://github.com/user-attachments/assets/e09f608a-4d54-4ab9-ae22-a55516c96dc7" />

Impact:-
The effects of a broken access control attack can include:
-	Unauthorized access to sensitive information.
-	Acting on behalf of another user.
-	Performing actions that should be restricted.
-	Initiating further attacks like stealing data or escalating privileges.
-	Compromising the system's integrity and data.
To prevent such attacks, implement strong access control measures, regularly review and monitor them, and follow the principle of least privilege. Additionally, adopting a security framework tailored for access control can help mitigate these risks.



# Vulnerability 11:- Title: Five Star Feedback (Broken Access Control)

Description:
Broken Access Control happens when an application or system does not correctly enforce restrictions on user permissions. This allows attackers to access sensitive data or perform restricted actions. It typically results from flaws like weak authentication or insufficient access control mechanisms.

Steps to Reproduce:
With admin logged in, navigated through the http://192.168.1.4:3000/administration. Got all feedbacks and users ids Then deleted the 1 st 5 star feedback.
<img width="940" height="511" alt="28" src="https://github.com/user-attachments/assets/fa1c374c-ac79-48a6-9a72-92418579c725" />
<img width="940" height="515" alt="29" src="https://github.com/user-attachments/assets/ba549e91-be2c-498a-9840-15883e173b51" />

Got the pop-up as solved the Five star feedback challenge


Impact:-
Broken access control attacks can result in:
-	Gaining unauthorized access to sensitive information.
-	Acting on behalf of another user.
-	Carrying out restricted actions.
-	Launching additional attacks like stealing data or escalating privileges.
-	Compromising the system's integrity and data.
To prevent these attacks, it is crucial to establish strong access controls, continuously monitor and review permissions, and follow the principle of least privilege. Leveraging a security framework designed for access control can also help mitigate these vulnerabilities.



# Vulnerability 12:- Title: Password Strength (Broken Authentication)
Description:
Broken authentication refers to vulnerabilities in a system's authentication process, such as flaws in handling user credentials, session IDs, or tokens. Attackers can exploit these weaknesses to gain unauthorized access or steal sensitive information.

Steps to Reproduce:
In the login page, in username section given the admin username, admin@juice-sh.op which is obtained from previous challenge. Then a random password. This request is intercepted by the Burpsuite. Then, In the Intrudeter section, payload is set for the password using the sniper option. A password wordlist is given and waited for the 200 response. The password is turned out to be admin123
<img width="940" height="515" alt="30" src="https://github.com/user-attachments/assets/27aec6ec-cb7e-4c5a-adf5-389555ed8845" />

Using BurpSuit I found the password admin123
<img width="940" height="515" alt="31" src="https://github.com/user-attachments/assets/7db23a0d-3d27-450e-adfe-735a041aedcb" />
<img width="940" height="513" alt="32" src="https://github.com/user-attachments/assets/35a42cb4-992b-43c4-a50e-148798d83376" />

Impact:
The impact of a successful broken authentication attack can include:
- unauthorized access to sensitive data
- stealing of user credentials, such as usernames and passwords
- ability to perform actions on behalf of another user
- perform actions that would otherwise be restricted
- perform a large-scale attack by using compromised credentialsto attack multiple systems
or networks.




# Vulnerability 13:- Title: Security Policy
Description:
A Security Policy attack is a type of cyber attack where an attacker manipulates or misrepresents a company's security policies and procedures, in order to gain access to sensitive information or perform other malicious actions. This can happen due to vulnerabilities in the security policy, such as lack of proper disclosure, lack of proper implementation, or lack of proper oversight.


Steps to Reproduce:
As the Security policy is generally placed at the ./well-known, lets check there once, The security.txt file is at http://192.168.1.3:3000/.well-known/security.txt
<img width="940" height="513" alt="33" src="https://github.com/user-attachments/assets/2d821c9f-7af9-4626-a604-fb7154f5e250" />

Got the pop-up solved the challenge Security Policy
<img width="940" height="515" alt="34" src="https://github.com/user-attachments/assets/4629ae8b-d309-4671-a8d9-0346cf7f5fbe" />



Impact:
The impact of a successful Security Policy attack can include:
- unauthorized access to sensitive information
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- damage to the integrity of the system and data
- legal penalties or fines for organizations that are required to protect sensitive data
under regulations such as HIPAA, PCI-DSS, and GDPR
- damage to reputation and negative publicity for the organization.
Preventing Security Policy attacks requires regularly reviewing and monitoring security
policies, using best practices for security policy creation, and ensuring that the policy is
compliant with applicable regulations. Additionally, ensuring that the policy is easily
understandable, and providing transparent and clear information about the data collection,
use, and sharing can also help prevent these types of attacks.




# Vulnerability 14:- Title: View Basket (Broken Authentication)
Description:
Broken authentication is a type of cyber attack that targets the authentication mechanisms of a system, such as user credentials, session IDs, or tokens. The attacker can exploit vulnerabilities in the authentication process to gain unauthorized access to the system or steal sensitive information.

Steps to Reproduce:
Logged in as a user, and navigated to the Basket. Then with the inspector(f12), searched the
storage for any id’s or cookies. In the session storage got the bid as 6, which is a basket id.
Then changed it to 1. The whole basket items are changed.
<img width="940" height="515" alt="35" src="https://github.com/user-attachments/assets/ebac4c11-c884-4499-aa39-314f91888a1f" />

Impact:
The impact of a successful broken authentication attack can include:
- unauthorized access to sensitive data
- stealing of user credentials, such as usernames and passwords
- ability to perform actions on behalf of another user




# Vulnerability 15:- Title: Weird Crypto(cryptography)
Description:
Cryptographic Issues is a type of cyber attack that occurs when an application or system uses weak or broken cryptography, allowing an attacker to decrypt or tamper with sensitive data or perform other malicious actions. This can happen due to vulnerabilities in the cryptographic implementation, such as the use of weak encryption algorithms, the use of weak keys, or the use of poor random number generators.

Steps to Reproduce:
Navigated to the contact section, in that had customer Feedback,
As the weak algorithms are MD5,SHA1,DES,RC4,Blowfish. I have gone with MD5 and
commented it in the comment section and sent the request.
Pop-up came with the challenge weird crypto solved just put MD5 in the comment and submit
<img width="940" height="514" alt="36" src="https://github.com/user-attachments/assets/0c876711-d356-47df-85b5-424ea929cbf9" />

Impact:
The impact of a successful Cryptographic Issues attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- Damage to the integrity of the system and data
- Perform a Man-in-the-Middle (MitM) attack by intercepting the communication.
Preventing Cryptographic Issues attacks requires using secure cryptographic libraries and
algorithms, regularly reviewing and monitoring cryptographic controls, and keeping systems
and applications up to date with the latest security patches. Additionally, using a security
framework that is specifically designed for cryptography can also help prevent these types of
attacks.


# Vulnerability 16:- Title: Admin Registration (Improper input validation)
Description:
Improper input validation is a type of cyber attack that occurs when an application or system fails to properly validate or sanitize user input, allowing an attacker to insert malicious code or data into the system. This can allow the attacker to gain unauthorized access to the system, steal sensitive information, or perform other malicious actions.


Steps to Reproduce:
Tried to register a new user and intercepted the request with the Burpsuite and gone through
the response for leads.
In the response there is option role:”customer”, lets take this as a lead.
Let’s send the request to repeater and add the option role and set role:”admin” with another
username and send the request.
It’s taken as a valid request, and added a user with admin previlages.
Pop-up came as the challenge solved.
<img width="940" height="513" alt="37" src="https://github.com/user-attachments/assets/24752d91-d399-4f5c-8962-7030ef5c01c2" />
<img width="940" height="513" alt="38" src="https://github.com/user-attachments/assets/e7482789-2767-4740-9702-38e315dd9384" />
<img width="940" height="515" alt="39" src="https://github.com/user-attachments/assets/0b555289-8f6b-480c-a9b7-c73ea6cdb94f" />

Impact:
The impact of a successful improper input validation attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as SQL injection or code execution
- The attacker may use the vulnerability to launch a DoS attack.
Preventing improper input validation attacks requires properly validating and sanitizing user
input, implementing input validation on the server-side, and using a whitelist approach to
validate input data. Additionally, properly encoding user input and using a security library that
is specifically designed to validate input can also help prevent these types of attacks.





# Vulnerability 17:- Title: Björn's Favorite Pet(Open Source Intelligence)
Description:
Open Source Intelligence (OSINT) is a type of information gathering technique that is used to gather information from publicly available sources, such as the internet, social media, and other publicly available databases. OSINT can be used by attackers as a means of reconnaissance to gather information about a target organization or individual, which can then be used to launch targeted attacks.


Stepsto Reproduce:
With the forgot password option, got the change password page with the security question
as authentication.
Here we need the mail id and security question answer,
With the OSINT, I have Googled the Bjoern mail id, Favorite pet and got a youtube video. In
the video I got the registration of the Bjoern, in which I have got the both user name and
Favorite pet
User name:bjoern@owasp.org
Security question: Zaya
With these cred’s I have changed the password of the user Bjoern.
Pop-up came as the challenge completed
<img width="940" height="515" alt="40" src="https://github.com/user-attachments/assets/4cf39d21-88d7-47a1-8c78-6b873a59389c" />
<img width="940" height="515" alt="41" src="https://github.com/user-attachments/assets/d6c1eb49-c5f8-49ae-a982-08769de99289" />

Impact:
The impact of a successful OSINT attack can include:
- unauthorized access to sensitive information
- the ability to perform social engineering attacks, such as phishing, spear-phishing, or
whaling
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- damage to the integrity of the system and data
- damage to reputation and negative publicity for the organization.
Preventing OSINT attacks requires regularly monitoring and analyzing publicly available
information about an organization, implementing security best practices for social media and
other publicly available information, and implementing security awareness training for
employees on the dangers of sharing too much information online.



# Vulnerability 18:- Title: Captcha Bypass (Broken Anti Automation)
Description:
Broken Anti-Automation is a type of cyber attack that occurs when an application or system
fails to properly implement or enforce anti-automation controls, allowing an attacker to
automate actions that would otherwise be restricted. This can happen due to vulnerabilities
in the system, such as lack of rate-limiting, lack of proper anti-automation controls, or lack of
proper CAPTCHA.

Steps to Reproduce:
In the customer feedback section, gave a feedback and solved the captcha. Then sent this
request to the repeater in the Brupsuite.
In repeater, I have tried whether, same captcha Id is working for different requests, yes it’s
working as I have got success as response for many requests sent with the same captcha
request.
Now, I have sent this request to the Intruder, here I have set a null payload and repeated this
request for 15 times in small interval of time.
<img width="940" height="511" alt="42" src="https://github.com/user-attachments/assets/67d56b5c-8550-4576-88ae-fb7df2d59b89" />

Pop-up came as the challenge solved.
<img width="940" height="512" alt="43" src="https://github.com/user-attachments/assets/76f28da2-6984-4720-90d8-133e51837ff8" />
<img width="940" height="513" alt="44" src="https://github.com/user-attachments/assets/752d408c-dc44-4e32-b06a-c7dc40f34b44" />
<img width="854" height="439" alt="45" src="https://github.com/user-attachments/assets/231a2fcc-7e14-4059-ba92-31fa9d2dca59" />
<img width="940" height="516" alt="46" src="https://github.com/user-attachments/assets/4ac2d1e2-76c5-4b9b-a7de-3e4696fbdd7d" />

Impact:
The impact of a successful Broken Anti-Automation attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- Damage to the integrity of the system and data
- Perform a DDoS attack by using bots.
Preventing Broken Anti-Automation attacks requires implementing robust anti-automation
controls, regularly reviewing and monitoring anti-automation controls, and using a ratelimiting approach to anti-automation controls. Additionally, using a security framework that
is specifically designed for anti-automation can also help prevent these types of attacks



# Vulnerability 19:- Title: Forged Feedback (Broken Access Control)
Description:

Broken Access Control is a type of cyber attack that occurs when an application or system fails
to properly implement or enforce access controls, allowing an attacker to gain unauthorized
access to sensitive data or perform actions that would otherwise be restricted. This can
happen due to vulnerabilities in the system, such as weak authentication mechanisms or lack
of proper access controls.


Steps to Reproduce:
In the customer feedback section, created a feedback and sent the request the repeater of
the Burpsuite.
<img width="940" height="515" alt="47" src="https://github.com/user-attachments/assets/5ffd13ab-c741-4b6a-bbf7-7dd7df038911" />
<img width="940" height="511" alt="48" src="https://github.com/user-attachments/assets/5ff1776e-3ef5-4fef-a0c8-4101d58b5876" />
<img width="940" height="515" alt="49" src="https://github.com/user-attachments/assets/b130c008-f17c-4aa7-bdd0-e3d556df0226" />


Impact:
The impact of a successful broken access control attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- Damage to the integrity of the system and data.
Preventing broken access control attacks requires implementing robust access controls,
regularly reviewing and monitoring access controls, and using a least privilege approach to
access controls. Additionally, using a security framework that is specifically designed for
access control can also help prevent these types of attacks.



# Vulnerability 20:- Title: Login Bender (Injection)
Description:
SQL Injection is a type of cyber attack that occurs when an attacker inputs malicious SQL code
into a web form or URL in order to gain unauthorized access to a database or to perform other
malicious actions. This can happen when an application does not properly validate or sanitize
user input, allowing an attacker to inject malicious SQL code into the application.

Steps to Reproduce:
With the admin login, gone through the administration section. Here got the Bender login id
bender@juice-sh.op
<img width="940" height="513" alt="50" src="https://github.com/user-attachments/assets/049d42da-ffe2-43c8-99f3-4386b77fb6bd" />

Now, lets log in as bender in the login page with sql injectin attack as bender@juice-sh.op’-- as payload in username field and a random password.
<img width="940" height="515" alt="51" src="https://github.com/user-attachments/assets/b2a817c8-ed9b-436b-9ea1-f0e25a03bdc6" />

Pop-up came on challenge solved successfully


Impact:
The impact of a successful SQL injection attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- damage to the integrity of the system and data
- Perform a DDoS attack by using bots
Preventing SQL injection attacks requires using parameterized queries, using prepared
statements, using object-relational mapping (ORM) libraries, and regularly reviewing and
monitoring databases and applications for SQL injection vulnerabilities. Additionally, using a
security framework that is specifically designed for SQL injection protection can also help
prevent these types of attacks.




# Vulnerability 21:- Title: API-Only XSS (XSS)
Description:
Cross-Site Scripting (XSS) is a type of web application security vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users. XSS attacks occur when an application does not properly validate user input and reflects it back to the user without proper encoding or sanitization. This allows an attacker to inject malicious code, such as JavaScript, into the web page, which is then executed by the victim's browser.


Stepsto Reproduce:
Logged in as admin from creds of previous challenge. Intercepted a request with Brupsuite.
Sent it to repeater. Now, trying inject the xss script.
In the initial Get request, in the response got the details of the product, in this there is chance
of xss script injection.
Changed the Get flag to the PUT flag and to access the JSON token, added the option ContentType : applicatipon/json
Then add the end of the PUT request added the description with the XSS script embedded
{"description":"<iframe src=\"javascript:alert(`xss`)\">"}.
As, this PUT request has the admin json token its processed and gave the http 200 response.
Now the description of the product has been changed and the xss script executed, when the
product is opened, it’s shows a alert pop-up xss.
The challenge completed pop-up has shown
<img width="940" height="513" alt="52" src="https://github.com/user-attachments/assets/f24c1b1c-5efb-4cbf-b55f-6fd700008bd1" />
<img width="940" height="513" alt="53" src="https://github.com/user-attachments/assets/0cc28feb-7ae9-42ea-9302-f75afac16003" />
<img width="940" height="513" alt="54" src="https://github.com/user-attachments/assets/036ad748-c844-4c57-8982-2d83bb920451" />


Impact:
The impact of a successful XSS attack can include:
- stealing sensitive information such as cookies, session tokens, and personal
information
- perform actions on behalf of the user, such as making unauthorized transactions or
posting malicious content
- redirecting the user to a malicious website
- spreading malware to the user's device
- spreading the attack to other users, if the malicious script is able to propagate itself.
Preventing XSS attacks requires properly validating and sanitizing user input, properly
encoding user input, and using a security library specifically designed for XSS protection.
Additionally, using the Content Security Policy (CSP) header can also help to prevent XSS
attacks.




# Vulnerability 22:- Title: Client-side XSS Protection(XSS)
Description:
Cross-Site Scripting (XSS) is a type of web application security vulnerability that allows an
attacker to inject malicious scripts into web pages viewed by other users. XSS attacks occur
when an application does not properly validate user input and reflects it back to the user
without proper encoding or sanitization. This allows an attacker to inject malicious code, such
as JavaScript, into the web page, which is then executed by the victim's browser.

Steps to Reproduce:
Searched for the client-side protection for xss in various comment sections and the
descriptions. Found there is projection at the new user registration at the username.
Thus sent this request to the Burpsuite repeater tab for the xss script injection at the
username.
Used the xss script <iframe src=\”javascript:alert(“XSS”)\”>”
Then forwarded the request.
When visited the administration tab with admin logged in(where the user details are
displayed, we can see the pop-up of xss which confirms the xss attack is successful.
Pop-up of challenge completion is shown.
<img width="940" height="516" alt="55" src="https://github.com/user-attachments/assets/84a1cdad-f5b1-47bc-85c6-b32b9c23476e" />
<img width="940" height="513" alt="56" src="https://github.com/user-attachments/assets/4c2322ee-6fb2-4b46-95fb-c289ad95431f" />
<img width="940" height="515" alt="57" src="https://github.com/user-attachments/assets/54983298-f000-4390-b17e-bf80e00ee815" />

Impact:
The impact of a successful XSS attack can include:
- stealing sensitive information such as cookies, session tokens, and personal
information
- perform actions on behalf of the user, such as making unauthorized transactions or
posting malicious content
- redirecting the user to a malicious website
- spreading malware to the user's device
- spreading the attack to other users, if the malicious script is able to propagate itself.
Preventing XSS attacks requires properly validating and sanitizing user input, properly
encoding user input, and using a security library specifically designed for XSS protection.
Additionally, using the Content Security Policy (CSP) header can also help to prevent XSS
attacks.




# Vulnerability 23:- Title: Manipulate Basket (Broken Access Control)
Description:
Broken Access Control is a type of cyber attack that occurs when an application or system
fails to properly implement or enforce access controls, allowing an attacker to gain
unauthorized access to sensitive data or perform actions that would otherwise be restricted.
This can happen due to vulnerabilities in the system, such as weak authentication
mechanisms or lack of proper access controls

Steps to Reproduce:
Logged in as a user and intercepted the request of adding items to the basket with the
Burpsuite and then sent it to repeater for hit and trail attacks.
In intercepter, checked for whether the server accepts for change in itemids and no.of items.
Yes, its accepts as response is html 200.
Now, let’s change the basket id, changing this will add the items to the basket of the another
user, initially it doesn’t worked out and gave HTML 500 ,unauthoried.
Then, I have changed the request by adding another Basketid under the authorized user
Basketid:6. This exploitsthe HTML parameter pollution, thusthe attack is a success. The items
are added to another user with basket id:5
The pop-up came indicating a successful completion of the challenge
<img width="940" height="515" alt="58" src="https://github.com/user-attachments/assets/2c4e6d9e-bcb0-4c4b-a7da-5812e35ce030" />
<img width="940" height="512" alt="59" src="https://github.com/user-attachments/assets/a6dce1ae-2b79-47de-b56d-1c55d69523f5" />
<img width="940" height="516" alt="60" src="https://github.com/user-attachments/assets/ceedd71d-37f8-42a3-af84-b1bc70826e21" />
<img width="940" height="516" alt="61" src="https://github.com/user-attachments/assets/7c9d1649-51d2-4820-aab8-c66089346eaa" />


Impact:
The impact of a successful broken access control attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as data exfiltration or privilege escalation
- Damage to the integrity of the system and data.
Preventing broken access control attacks requires implementing robust access controls,
regularly reviewing and monitoring access controls, and using a least privilege approach to
access controls. Additionally, using a security framework that is specifically designed for
access control can also help prevent these types of attacks.




# Vulnerability 24:- Title: Payback Time (Improper Input Validation)
Description:
Improper input validation is a type of cyber attack that occurs when an application or system
fails to properly validate or sanitize user input, allowing an attacker to insert malicious code
or data into the system. This can allow the attackerto gain unauthorized accessto the system,
steal sensitive information, or perform other malicious actions.

Steps to Reproduce:
Logged in as a normal user, and intercepted the request of the adding the melon bike to the
basket by the burpsuite using the proxy.
Then changed the value of quantity 1 to -2000, then forwared the request.
Now, the quantity of bikes changed to -2000 i.e amount to be added to our account.
I have proceeded to the checkout by adding the personal details, and then make the checkout.
The pop-up shown as the challenge completed successfully.
<img width="940" height="512" alt="62" src="https://github.com/user-attachments/assets/0f526c12-b523-4170-881c-3e564a27aac0" />
<img width="940" height="515" alt="63" src="https://github.com/user-attachments/assets/375df95f-2a0f-4745-8f1c-6b8a5654cac0" />
<img width="940" height="513" alt="64" src="https://github.com/user-attachments/assets/805e03f8-d4d6-4222-80a7-d7943efaeaae" />
<img width="940" height="515" alt="65" src="https://github.com/user-attachments/assets/a8bb1ebc-99f1-460a-aa30-00785c434d18" />
<img width="940" height="515" alt="66" src="https://github.com/user-attachments/assets/50ccb6b9-dbb9-4b8f-a5de-ff79ca796275" />
<img width="940" height="513" alt="67" src="https://github.com/user-attachments/assets/7ba63abb-51d6-473a-90d1-67ca383eb1a7" />

Impact:
The impact of a successful improper input validation attack can include:
- unauthorized access to sensitive data
- the ability to perform actions on behalf of another user
- the ability to perform actions that would otherwise be restricted
- the ability to launch further attacks, such as SQL injection or code execution
- The attacker may use the vulnerability to launch a DoS attack.
Preventing improper input validation attacks requires properly validating and sanitizing user
input, implementing input validation on the server-side, and using a whitelist approach to
validate input data. Additionally, properly encoding user input and using a security library that
is specifically designed to validate input can also help prevent these types of attacks.




# Vulnerability 25:- Title: Privacy Policy Inspection
Description:
A Privacy Policy Inspection attack is a type of cyber attack where an attacker inspects and
analyzes an organization's privacy policy to find vulnerabilities and weaknesses that can be
exploited. The attacker may use automated tools to scan the privacy policy, or manually
inspect the policy to identify any gaps in protection or non-compliance with regulations.

Steps to Reproduce:
Logged in as the normal user and visited the privacy-policy page. While scrolling through the
page, noticed the glowing around some words. Opened the inspector for any clues there. Got
the class hot, searched for any other places with the class hot, got a few.
Noted these phrases in a notepad. Seems like it’s clue for the web directory as the first one is
a IP address. In this replaced all the spaces with / and finally got the address as
http://192.168.1.3/We/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsi
bility this. When navigated through this, there is no luck, no clues ahead jus a dummy page.
When rolled back, in the juice shop pop-up showed challenge solved, it seems the challenge
is to visit the web directory.
<img width="940" height="515" alt="68" src="https://github.com/user-attachments/assets/a350c4e7-700e-49a9-9806-dd9f3020b6f4" />
<img width="940" height="513" alt="69" src="https://github.com/user-attachments/assets/b6ab3275-ed4b-4f7a-a77c-830ba9d8df1e" />
<img width="940" height="516" alt="70" src="https://github.com/user-attachments/assets/2e088759-4ab0-4e6d-8c19-6aca0c16b91f" />
<img width="940" height="515" alt="71" src="https://github.com/user-attachments/assets/e165fb5f-6abc-4261-a3ec-1b966d87bee8" />

Impact:
The impact of a successful Privacy Policy Inspection attack can include:
- unauthorized access to sensitive information
- loss of trust from customers or users whose data was mishandled
- legal penalties or fines for organizations that are required to protect sensitive data
under regulations such as HIPAA, PCI-DSS, and GDPR
- damage to reputation and negative publicity for the organization
Preventing Privacy Policy Inspection attacks requires regularly reviewing and monitoring
privacy policies, using best practices for privacy policy creation, and ensuring that the policy
is compliant with applicable regulations. Additionally, implementing security best practices
for privacy policy management, and regularly testing the policy against known vulnerabilities
can also help prevent these types of attacks.











































