import re
import os
import time 
import smtplib
from email.message import EmailMessage

class analyser:
    def ip_blocker(self,ip):
        # in this i add a ip blocked table and how many remaining 
        # i think i can add this function via shell scripting easily
        # i make a file like json or xml such that which contains trackrecord of every blocked ip , user , loggined user with his attempts 
        
        pass

    def file_writer(self,content):
        with open("threat_ip.txt", "a") as file:
            file.write(content+"\n")
    def mail_sender(self, search):
        if search:  # regex found an IP
            ip = search
            print(f"Suspicious IP detected: {ip}")
            self.mailsender("alert", f"IP threat detected by this IP {ip}")
        else:       # no IP found
            print("Suspicious activity detected (no IP found)")
            self.mailsender("unknown", "Alert: anonymous IP tried to login")


    def mailsender(self,ip,search): 
        print(f"ip :- {search}")
        with open("threat.txt",'a') as file:
       
                
            file.write(f"{search}")
            sender="forbgmiuseonly002@gmail.com"
            key = "feqcikcdywtgoxui"
            reciever="forbgmiuseonly001@gmail.com"
            body=f"threat detected {search} .... check your server "
            subject=f"ALERT MAIL FROM SERVER "
            msg = EmailMessage()
            msg['subject']=subject
            msg['from']=sender
            msg['to']=reciever
            msg.set_content(body)
                # with open('txt.txt', 'rb') as f:
                #     data = f.read()
                #     name=f.name 
                #     msg.add_attachment(data,maintype="application",subtype="zip", filename=name)
                #   now we establising a mail server using smtp 
            server = smtplib.SMTP("smtp.gmail.com",587)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender,key)
            server.send_message(msg)
            server.quit()
            print("mail sended successfully")
    def __init__(self,file_name):
        self.ippattern=r"\d+\.\d+\.\d+\.\d+"
        self.position = 0
        self.file_name=file_name
        self.count = 0
        self.wait=0
        self.count1=0
        if os.path.exists(file_name) :
            with open(file_name,'r') as f:
                f.seek(0,2)
                self.position=f.tell()
    def analyser(self):
        with open(self.file_name,"r") as f:
            while True:
                f.seek(self.position)
                line = f.readline()
                if not line.strip() or len(line) <=7 :
                    self.position=f.tell()
                    if not line:
                        time.sleep(2)
                        self.wait+=1
                        if(self.wait>3):
                            print("waitting for new logs ")
                            self.wait=0
                    continue
                # here we are using list and inside list there are two seperate elements of touple
                # list = {(e1,e2)} 
                patterns = [
        (re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'), "brute_force_attempt_standard"),#creates a regex object from a string pattern
        (re.compile(r'Failed password for (?:invalid user )?(\S+) from (::1)'), "brute_force_attempt_localhost"),
        (re.compile(r'Failed password for (?:invalid user )?(\S+)'), "brute_force_attempt_no_ip"),
        (re.compile(r'error: maximum authentication attempts exceeded for .*? from (\d+\.\d+\.\d+\.\d+)'), "brute_force_lockout_event"),
        (re.compile(r'authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)'), "pam_authentication_failure"),
        (re.compile(r'pam_unix\(sshd:auth\): authentication failure;.*rhost=(\S+)'), "pam_authentication_failure_rhost")
    ]
                risk_score = 0

                for regex,name in patterns:
                    match = regex.search(line)
                    if match:
                        atk = f"Detected: {name} :- {match.groups()}\n"
                        print(atk)
                        self.mail_sender(atk)
    
                        if name in ["brute_force_standard", "brute_force_localhost", "brute_force_no_ip"]:
                            self.file_writer(atk)
                            self.mail_sender(atk)
                            risk_score += 3
                        elif name in ["auth_attempts_exceeded", "pam_auth_failure_rhost"]:
                            self.file_writer(atk)
                            self.mail_sender(atk)
                            
                            risk_score += 2
                        elif name in ["pam_auth_failure"]:
                            risk_score += 1
                        elif "failed" in line.lower():
                            print("failed attempt it may be user own ")
                    if risk_score >= 20:  # threshold can be increased for high-volume attacks
                        print("⚠️ Server under heavy brute force attack!")
                        with open("alerts.log", "a") as log:
                            log.write("High risk detected\n")
                        self.mail_sender("⚠️ high alert saw your system what is happening someone try to hacking your device  check the server immediately")
                        risk_score = 0
                self.count=0
                self.position=f.tell()
if __name__=="__main__":
    file_name="auth.log"
    try :
        monitor=analyser(file_name)    
        monitor.analyser()
    except KeyboardInterrupt:
        print("exit successfully ")
# new type of pattern can be addable like type of patterns 
# I think i make the list of them and then set it as like it check the pattern in like and then i gave them a condition for each attempt and then send mail according to attack priority and also save in file i think i want to make a seperate file for in which ip is present and also add every failed attempt line with attempt type in threat_ip.txt
# and after some time i try to make a json file so that data can be clear and more formatted 
# this is my log monitoring project that used to monitor log of a system (logs are basicaly string generated by a demon of every activity by user ) and send alert  to user via mail by smtp protocol
# i also add a feature if user may want to send mail via file he can send too by just some edit and use by just uncomment the file 
# next time i try to fix the ips error by using function inside function in mailsender funcition so that it can send mail if a suspsious user attempt to unauthorized login and then add a ip block function
# patterns = [
#         (re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'), "brute_force_attempt_standard"),
#         (re.compile(r'Failed password for (?:invalid user )?(\S+) from (::1)'), "brute_force_attempt_localhost"),
#         (re.compile(r'Failed password for (?:invalid user )?(\S+)'), "brute_force_attempt_no_ip"),
#         (re.compile(r'error: maximum authentication attempts exceeded for .*? from (\d+\.\d+\.\d+\.\d+)'), "brute_force_lockout_event"),
#         (re.compile(r'authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)'), "pam_authentication_failure"),
#         (re.compile(r'pam_unix\(sshd:auth\): authentication failure;.*rhost=(\S+)'), "pam_authentication_failure_rhost")
#     ]
# these are the patterns that i searched on internet 

