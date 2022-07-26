import os
import socket
import subprocess

import subscripts

def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'):
        command = 'cls'
    os.system(command)


def printBanner():
    print("    _   __   _    __   _____")
    print("   / | / /  | |  / /  / ___/")
    print("  /  |/ /   | | / /   \__ \\")
    print(" / /|  /    | |/ /   ___/ /")
    print("/_/ |_/     |___/   /____/ - AcedTimo\n")
    return


def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def getSubnetMask(ipAddress):
    osName = os.name
    if osName == "nt":
        command = "powershell /c \"$mask = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where IPEnabled | Select IPSubnet); $mask.IPSubnet[0]\""
        ret = subprocess.check_output(command)
        netmask = ipAddress + str(sum([bin(int(x)).count("1") for x in ret.decode("utf-8").split(".")]))
    elif osName == "posix":
        command = "ip -o -f inet addr show | awk '/scope global/ {print $4}'" # Not sure if this works yet
        ret = subprocess.check_output(command)
        netmask = ret.decode("utf-8")
    else:
        return

    return netmask

def getIpRange():
    ipParts = subscripts.misc.getIP().split('.')
    ipRange = ""
    for i in range(0, len(ipParts) - 1):
        ipRange += ipParts[i] + "."
    ipRange += "0/"

    return getSubnetMask(ipRange)
