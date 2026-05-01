import subprocess
def log_file(write_data:str):
    with open("firewall_rules.log","a") as file:
        file.write(write_data)
        print(write_data)
def run_cmd(cmd:list):
    try:
        output=subprocess.run(cmd,text=True,capture_output=True,timeout=20)
        return output.returncode==0,output.stdout.strip(),output.stderr.strip()
        # 0 means true command runned successfully
    except subprocess.TimeoutExpired:
        return False,"","timeout_error"
    except Exception as error:
        return False,"",error
def admin_check():
    id_cmd=["id","-u"]
    success,stdout,stderr=run_cmd(id_cmd)
    if success:
        if stdout=="0":
            print("user can use the script ")
            return 1
        if stdout !="0":
            print("user can not use the script \nlogin as admin 1st  \nexiting")
            return 0
        if stderr:
            print(f"there are some issue {stderr}")
    else :
        print("failed to check")
def firewall_check():
    # now initially we making it 
    cmd = ["which","firewalld"]
    success,stdout,stderr=run_cmd(cmd)
    if success :
        if stdout:
            print("firewalld is installed ")
            return 1
        if stderr:
            print("firewalld is not installed ")
            return 0
    else :
        print("there are some issue in checking the firewall")
def firewall_deploy():
    if firewall_check() ==1:
        cmd=["systemctl","enable","firewalld"]
        cmd_start=["systemctl","start","firewalld"]
        cmd_check_status=["systemctl","is-active","firewalld"]
        rok,stdout1,error2=run_cmd(cmd_check_status)
        start,ok,error=run_cmd(cmd_start)
        print(ok)
        success,stdout,stderr=run_cmd(cmd)
        if success:
            if str(stdout1).strip()=="active":
                print("firewalld_status_active and now your firewalld is running")
                return 1
            else:
                print("status inactive \n checking status \nwait to reactive it ")   
                firewall_deploy()
                return 1
                      
        else :
            print("there are some issue.........")
            return 0 
        
def rules_setter(): 
    choice,ip_address,port_number=cli_interface()
    protocol="tcp"
    # 1st rule is to allow incoming traffic on port 80 and 443 for web servers
    if choice==1:
        cmd_allow_web=["firewall-cmd","--permanent","--add-service=http"]
        cmd_allow_https=["firewall-cmd","--permanent","--add-service=https"]
        sucess,stdout_web,stderr_web=run_cmd(cmd_allow_web)
        sucess1,stdout_https,stderr_https=run_cmd(cmd_allow_https)
        if sucess:
            log_file("rules for web server added successfully\n")
        else :
            log_file("there are some issue in adding rules for web server\n")
        if sucess1:
            log_file("rules for https added successfully\n")
        else :
            log_file("there are some issue in adding rules for https\n")
    # 2nd rule is to allow incoming traffic on port 22 for ssh access
    elif choice==2:
        cmd_allow_ssh=["firewall-cmd","--permanent","--add-service=ssh"]
        sucess,stdout_ssh,stderr_ssh=run_cmd(cmd_allow_ssh)
        if sucess:
            log_file("rules for ssh added successfully\n")
        else :
            log_file("there are some issue in adding rules for ssh\n")
    # 3rd rule is to allow incoming traffic on port 3306 for mysql database
    elif choice==3:
        cmd_allow_mysql=["firewall-cmd","--permanent","--add-service=mysql"]
        sucess,stdout_mysql,stderr_mysql=run_cmd(cmd_allow_mysql)   
        if sucess:
            log_file("rules for mysql added successfully\n")
        else :
            log_file("there are some issue in adding rules for mysql\n")
    # 4th rule is to allow incoming traffic on port 5432 for postgresql database
    elif choice==4:
        cmd_allow_postgresql=["firewall-cmd","--permanent","--add-service=postgresql"]
        sucess,stdout_postgresql,stderr_postgresql=run_cmd(cmd_allow_postgresql)
        if sucess:
            log_file("rules for postgresql added successfully\n")
        else :
            log_file("there are some issue in adding rules for postgresql\n")
    # 5th rule is used to allow traffic from specific ip address to access the server
    elif choice==5:
        cmd_allow_ip=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port protocol=\"tcp\"'"]
        sucess,stdout_ip,stderr_ip=run_cmd(cmd_allow_ip)
        if sucess:
            log_file("rules for specific IP added successfully\n")
        else :
            log_file("there are some issue in adding rules for specific IP\n")
    
    # 6th rule is used to block traffic from specific ip address to access the server
    elif choice==6:
        cmd_block_ip=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port protocol=\"tcp\"'"]
        sucess,stdout_block_ip,stderr_block_ip=run_cmd(cmd_block_ip)
        if sucess:          
            log_file("rules for blocking specific IP added successfully\n")
        else :
            log_file("there are some issue in adding rules for blocking specific IP\n")
    # 7th rule is used to allow traffic from specific ip address to access the server on specific port
    elif choice==7:
        cmd_allow_ip_port=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port={port_number} protocol=\"tcp\"'"]
        sucess,stdout_allow_ip_port,stderr_allow_ip_port=run_cmd(cmd_allow_ip_port)
        if sucess:
            log_file("rules for allowing specific IP and port added successfully\n")
        else :
            log_file("there are some issue in adding rules for allowing specific IP and port\n")
    # 8th rule is used to block traffic from specific ip address to access the server on specific port
    elif choice==8:
        cmd_block_ip_port=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port={port_number} protocol=\"tcp\"'"]
        sucess,stdout_block_ip_port,stderr_block_ip_port=run_cmd(cmd_block_ip_port)
        if sucess:
            log_file("rules for blocking specific IP and port added successfully\n")
        else :
            log_file("there are some issue in adding rules for blocking specific IP and port\n")
    # 9th rule is used to allow traffic from specific ip address to access the server on specific port for specific protocol
    elif choice==9:
        cmd_allow_ip_port_protocol=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port={port_number} protocol=\"{protocol}\"'"]
        sucess,stdout_allow_ip_port_protocol,stderr_allow_ip_port_protocol=run_cmd(cmd_allow_ip_port_protocol)
        if sucess:
            log_file("rules for allowing specific IP, port and protocol added successfully\n")
        else :
            log_file("there are some issue in adding rules for allowing specific IP, port and protocol\n")
    # 10th rule is for blocking traffic from specific ip address to access the server on specific port for specific protocol
    elif choice==10:
        cmd_block_ip_port_protocol=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" source address=\"{ip_address}\" port={port_number} protocol=\"{protocol}\"'"]
        sucess,stdout_block_ip_port_protocol,stderr_block_ip_port_protocol=run_cmd(cmd_block_ip_port_protocol)
        if sucess:
            log_file("rules for blocking specific IP, port and protocol added successfully\n")
        else :
            log_file("there are some issue in adding rules for blocking specific IP, port and protocol\n")

    elif choice==11:
        cmd_block_port=["firewall-cmd","--permanent",f"--add-rich-rule='rule family=\"ipv4\" port={port_number} protocol=\"{protocol}\"' drop"]
        sucess,stdout_block_port,stderr_block_port=run_cmd(cmd_block_port)
        if sucess:
            log_file("rules for blocking specific port added successfully\n")
        else :
            log_file("there are some issue in adding rules for blocking specific port\n")
    else :
        log_file("invalid choice \n please enter a valid choice\n")
    # in this i add different rule that are used to auto set so that it can be used by other projects
    # and also add a client interface to control the firewalld service
def firewall_service_manager():
    input,_,_=cli_interface()
    if input==1:
        cmd_start=["systemctl","start","firewalld"]
        start,ok,error=run_cmd(cmd_start)
        if start:
            log_file("firewall service started successfully\n")
        else :
            log_file("there are some issue in starting firewall service\n")
    elif input==2:
        cmd_stop=["systemctl","stop","firewalld"]
        stop,ok,error=run_cmd(cmd_stop)
        if stop:
            log_file("firewall service stopped successfully\n")
        else :
            log_file("there are some issue in stopping firewall service\n")
    elif input==3:
        cmd_restart=["systemctl","restart","firewalld"]
        restart,ok,error=run_cmd(cmd_restart)
        if restart:
            log_file("firewall service restarted successfully\n")
        else :
            log_file("there are some issue in restarting firewall service\n")
    elif input==4:
        cmd_check_status=["systemctl","is-active","firewalld"]
        check_status,stdout,error=run_cmd(cmd_check_status)
        if check_status:
            log_file(f"firewall service status is {stdout}\n")
        else :
            log_file("there are some issue in checking status of firewall service\n")
    
def cli_interface():
    print("welcome to firewall management system \n you can set rules and manage your firewall using this interface "
          "\n1. set rules \n2. manage firewall service \n3. exit")

    choice=input("enter your choice : ")
    if choice in ["1","2","3"]:
        if choice=="1":
            print("choose the rule you want to set \n1. allow incoming traffic on port 80 and 443 for web servers \n2. allow incoming traffic on port 22 for ssh access \n3. allow incoming traffic on port 3306 for mysql database \n4. allow incoming traffic on port 5432 for postgresql database \n5. allow traffic from specific ip address to access the server \n6. block traffic from specific ip address to access the server \n7. allow traffic from specific ip address to access the server on specific port \n8. block traffic from specific ip address to access the server on specific port \n9. allow traffic from specific ip address to access the server on specific port for specific protocol \n10. block traffic from specific ip address to access the server on specific port for specific protocol\n11. block the specific port for all incoming traffic")
            choice2=input("enter your choice : ")
            if choice2 in ["1","2","3","4","5","6","7","8","9","10"]:
                #  now we want to get an ip address and port number from user if they choose 5,6,7,8,9,10
                # user put ip_address or port number to perform the action on that ip address or port number
                if choice2 in ["5","6"]:
                    ip_address=input("enter the ip address : ")
                    log_file(f"ip address entered by user is {ip_address}\n")
                    return int(choice2),ip_address,None
                if choice2 in ["7","8","9","10"]:
                    ip_address=input("enter the ip address : ")
                    port_number=input("enter the port number : ")
                    log_file(f"ip address entered by user is {ip_address} and port number is {port_number}\n")
                    return int(choice2),ip_address,port_number

        elif choice=="2":
            print("choose the action you want to perform \n1. start firewall service \n2. stop firewall service \n3. restart firewall service \n4. check status of firewall service")
            choice3=input("enter your choice : ")
            if choice3 in ["1","2","3","4"]:
                return int(choice3),"firewall_service_manager",None
        elif choice=="3":
                log_file("exiting the firewall management system \n thank you for using the system")
                exit()
    # this is client interface used to get input from user and can make changes to firewalld service
print(firewall_deploy())
# todays track record :-
"""today i have added some more rules to the firewall management system and also added a client interface to control the firewalld service"""