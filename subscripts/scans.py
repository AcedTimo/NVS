import time
import nmap3
import subscripts.misc
import subscripts.menus

def buildArguments():
    arguments = ""
    menus = subscripts.menus

    if not menus.allTCP and not menus.allUDP and not menus.detectOS and not menus.detectServices and not menus.detectVulns and not menus.excludeThisDevice:
        arguments = "none"
        return arguments

    if menus.allTCP and menus.allUDP:
        arguments += "-sU -sT -p- -T5 "
    else:
        if menus.allTCP:
            arguments += "-p- -T5 "
        if menus.allUDP:
            arguments += "-sU -p- -T5 "
    
    if menus.detectOS:
        arguments += "-O "
    if menus.detectServices:
        arguments += "-sV "
    if menus.detectVulns:
        arguments += "-sV --script=vuln "

    if menus.excludeThisDevice:
        ipAddress = subscripts.misc.getIP()
        arguments += f"--exclude {ipAddress}"
    
    return arguments.rstrip()

def startScan(target, arguments):
    print("\nStarting a scan on target: '" + target + "' with arguments:'" + arguments + "'")

    result = ""
    nmap = nmap3.Nmap()
    try:
        result = nmap.scan_top_ports(target=target, args=arguments)
        print("\nScan finished")
        time.sleep(2)
    except Exception as e:
        if str(e).__contains__("requires root privileges"):
            print("Insufficient Privileges. Try running the script as root")
            time.sleep(4)
            return result
        print("An Exception occurred: \n" + str(e))
        time.sleep(4)

    return result

def digestScanData(scanData):
    try:
        if scanData["runtime"]["exit"] != "success":
            print("The scan failed. Check the data below.")
            print(scanData)
            input("PAUSED")
            return
        if len(scanData) == 2:
            print("The host machine was unreachable")
            return
    except:
        x=0

    for resultDict in scanData:
        if resultDict == "stats" or resultDict == "runtime":
            continue

        ipAddress = resultDict

        try:
            hostname = scanData[resultDict]["hostname"][0]["name"]
        except:
            hostname = ""

        try:
            deviceState = scanData[resultDict]["state"]["state"]
        except:
            deviceState = ""

        try:
            osName = scanData[resultDict]["osmatch"][0]["name"]
        except:
            osName = ""

        try:
            accuracy = scanData[resultDict]["osmatch"][0]["accuracy"]
        except:
            accuracy = ""

        try:
            osType = scanData[resultDict]["osmatch"][0]["osclass"]["type"]
        except:
            osType = ""

        try:
            osVendor = scanData[resultDict]["osmatch"][0]["osclass"]["vendor"]
        except:
            osVendor = ""

        try:
            osFamily = scanData[resultDict]["osmatch"][0]["osclass"]["osfamily"]
        except:
            osFamily = ""

        try:
            osGen = scanData[resultDict]["osmatch"][0]["osclass"]["osgen"]
        except:
            osGen = ""

        try:
            macAddress = scanData[resultDict]["macaddress"]["addr"]
        except:
            macAddress = ""

        try:
            macVendor = scanData[resultDict]["macaddress"]["vendor"]
        except:
            macVendor = ""

        portList = []
        try:
            for portInfo in scanData[resultDict]["ports"]:
                serviceName = ""
                product = ""
                extraInfo = ""
                deviceType = ""

                try:
                    protocol = portInfo["protocol"]
                    portid = portInfo["portid"]
                    portState = portInfo["state"]
                except:
                    continue

                try:
                    serviceName = portInfo["service"]["name"]
                except:
                    x = 0

                try:
                    product = portInfo["service"]["product"]
                except:
                    x = 0

                try:
                    extraInfo = portInfo["service"]["extrainfo"]
                except:
                    x = 0

                try:
                    deviceType = portInfo["service"]["devicetype"]
                except:
                    x = 0

                vulnList = []
                try:
                    rawVulnString = portInfo["scripts"][0]["raw"]
                    rawVulnLines = rawVulnString.split("\n")
                    for vuln in rawVulnLines:
                        if not subscripts.menus.onlyShowExploits or str.__contains__(vuln, "\t*EXPLOIT*"):
                            vulnInfo = vuln.replace("\t", " ")
                            vulnInfo = vulnInfo.lstrip().rstrip()

                        if not subscripts.menus.onlyShowExploits:
                            vulnList.append(vulnInfo)
                            continue
                        if str.__contains__(vuln, "\t*EXPLOIT*"):
                            vulnInfo = vulnInfo.replace("*EXPLOIT*", "")
                            vulnList.append(vulnInfo)
                except:
                    x = 0

                portData = {
                    "protocol": protocol,
                    "portid": portid,
                    "portState": portState,
                    "serviceName": serviceName,
                    "product": product,
                    "extrainfo": extraInfo,
                    "deviceType": deviceType,
                    "vulnList": vulnList
                }

                portList.append(portData)
        except:
            x = 0

        hostDict = {
            "ipAddress": ipAddress,
            "hostname": hostname,
            "deviceState": deviceState,
            "osName": osName,
            "accuracy": accuracy,
            "osType": osType,
            "osVendor": osVendor,
            "osFamily": osFamily,
            "osGen": osGen,
            "macAddress": macAddress,
            "macVendor": macVendor,
            "portList": portList
        }

        for host in subscripts.menus.scannedHostsList:
            if host["ipAddress"] == ipAddress:
                subscripts.menus.scannedHostsList.remove(host)
                break

        subscripts.menus.scannedHostsList.append(hostDict)
    return
