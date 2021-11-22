#!/usr/bin/python3

from socket import *
import optparse
from threading import *


def connScan(host, port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((host, port))
        print("[+] %d/tcp Open" % port)
    except:
        print("[-] %d/tcp Closed" % port)
    finally:
        sock.close()
        

def portScan(host, ports):
    try:
        targetIp = gethostbyname(host)
    except:
        print("Can't Resolve Host %s" %host)
    try:
        targetName = gethostbyaddr(targetIp)
        print("[+] Scan results for: " + targetName[0])
    except:
         print("[+] Scan results for: " + targetIp)

    setdefaulttimeout(2)
    for port in ports:
        t = Thread(target=connScan, args=(host, int(port)))
        t.start()


def main():
    argsParser = optparse.OptionParser("Usage of program: -H <target host> -p <target port(s)>")
    argsParser.add_option("-H", dest= "host", type="string", help="Target host")
    argsParser.add_option("-p", dest= "port", type="string", help="Target ports separated by comma")
    (options, args) = argsParser.parse_args()
    host = options.host
    ports = str(options.port).strip().split(",")
    if host == None or ports[0] == None:
        print(argsParser.usage)
        exit(0)
    portScan(host,ports)


if __name__ == "__main__":
    main()
