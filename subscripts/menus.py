import time
import io
import ast
import termtables
import subscripts.misc
import subscripts.scans

# ---- Settings ----
allTCP = False
allUDP = False
detectOS = False
detectServices = False
detectVulns = False
onlyShowExploits = True
excludeThisDevice = True
# ------------------

scannedHostsList = []

def mainMenu():
    subscripts.misc.clearConsole()

    subscripts.misc.printBanner()

    print("[1] Scan a specific target IP or range")
    print("[2] Scan the entire local network")
    print("[3] View scanned Hosts")
    print("[4] Import Session")
    print("[5] Export Session")
    print("[6] Settings")
    print("[q] Quit\n")

    selection = input("Input: ")

    if selection == "q":
        subscripts.misc.clearConsole()
        print("Quitting.. Goodbye! ^-^")
        exit(0)

    if selection == "1":
        specificTarget()
        return

    if selection == "2":
        entireLocalNetwork()
        return

    if selection == "3":
        continueLoop = True
        while continueLoop:
            continueLoop = scannedHosts()
        return

    if selection == "4":
        importSession()
        return

    if selection == "5":
        exportSession()
        return

    if selection == "6":
        continueLoop = True
        while continueLoop:
            continueLoop = settings()
        return

    print("\nInvalid input")
    time.sleep(2000)
    return

def settings():
    subscripts.misc.clearConsole()
    global allTCP, allUDP, detectOS, detectServices, detectVulns, onlyShowExploits, excludeThisDevice

    print("Settings")
    print(f"[1] All TCP Ports             [{allTCP}]")
    print(f"[2] All UDP Ports             [{allUDP}]")
    print(f"[3] OS Detection              [{detectOS}]")
    print(f"[4] Service Version Detection [{detectServices}]")
    print(f"[5] Vulnerability Detection   [{detectVulns}]")
    print(f"[6] Only Show Exploits        [{onlyShowExploits}]")
    print(f"[7] Exclude This Device       [{excludeThisDevice}]")
    print("Press return to go back to the Main Menu")

    selection = input("Input: ")

    if selection == "1":
        if allTCP:
            allTCP = False
        else:
            allTCP = True
        return True
    if selection == "2":
        if allUDP:
            allUDP = False
        else:
            allUDP = True
        return True
    if selection == "3":
        if detectOS:
            detectOS = False
        else:
            detectOS = True
        return True
    if selection == "4":
        if detectServices:
            detectServices = False
        else:
            detectServices = True
        return True
    if selection == "5":
        if detectVulns:
            detectVulns = False
        else:
            detectVulns = True
        return True
    if selection == "6":
        if onlyShowExploits:
            onlyShowExploits = False
        else:
            onlyShowExploits = True
        return True
    if selection == "7":
        if excludeThisDevice:
            excludeThisDevice = False
        else:
            excludeThisDevice = True
        return True
    if selection == "":
        return False

    print("\nInvalid Input")
    time.sleep(2)
    return True

def specificTarget():
    subscripts.misc.clearConsole()
    global allTCP, allUDP, detectOS, detectServices, detectVulns

    print("Specify the target IP or Range to scan")
    print("Press return to go back to the Main Menu\n")
    target = input("Target: ")

    if target == "":
        return

    arguments = subscripts.scans.buildArguments()
    scanData = subscripts.scans.startScan(target, arguments)
    if scanData != "":
        subscripts.scans.digestScanData(scanData)
    return

def entireLocalNetwork():
    ipRange = subscripts.misc.getIpRange()
    arguments = subscripts.scans.buildArguments()
    scanData = subscripts.scans.startScan(ipRange, arguments)
    if scanData != "":
        subscripts.scans.digestScanData(scanData)
    return

def scannedHosts():
    global scannedHostsList
    if len(scannedHostsList) == 0:
        print("No hosts have been scanned yet")
        time.sleep(2)
        return

    header = ["Index", "IP Address", "Open Ports", "Vulnerabilities"]
    data = []
    index = 0

    for host in scannedHostsList:
        openPortCount = 0
        vulnCount = 0
        for port in host["portList"]:
            if port["portState"] == "open":
                openPortCount += 1
                vulnCount += len(port["vulnList"])

        data.append([str(index), host["ipAddress"], openPortCount, vulnCount])
        index += 1

    subscripts.misc.clearConsole()
    termtables.print(data, header)

    print("Specify a Host's Index to view it's gathered information")
    print("Type 'clear' to clear the entire list of hosts")
    print("Press return to go back to the Main Menu")

    selection = input("Input: ")

    if selection == "":
        return False

    if selection == "clear":
        scannedHostsList = []
        print("\nThe session was cleared")
        time.sleep(2)
        return False

    try:
        if int(selection) > index - 1:
            print("\nThe Index is invalid")
            time.sleep(2)
            return True
    except:
        print("\nThe Index is invalid")
        time.sleep(2)
        return True

    viewHostInfo(int(selection))
    return True

def viewHostInfo(index):  # Add option to delete a host when viewing it
    host = scannedHostsList[index]

    header = ["IP Address", "Hostname", "Device State", "Mac Address", "Mac Vendor"]
    data = [[host["ipAddress"], host["hostname"], host["deviceState"], host["macAddress"], host["macVendor"]]]
    subscripts.misc.clearConsole()
    print("Host Information")
    termtables.print(data, header)

    if host["accuracy"] != "":
        header = ["Name", "Type", "Vendor", "Family", "Gen", "Accuracy"]
        data = [[host["osName"], host["osType"], host["osVendor"], host["osFamily"], host["osGen"], host["accuracy"]]]
        print("\nOS Information")
        termtables.print(data, header)

    data = []
    data2 = []
    for port in host["portList"]:
        data.append([port["protocol"], port["portid"], port["portState"], port["serviceName"], port["product"], port["extrainfo"], port["deviceType"]])
        vulnString = ""
        for vuln in port["vulnList"]:
            data2.append([port["protocol"], port["portid"], vuln])

    if len(data) != 0:
        header = ["Protocol", "Port ID", "State", "Service", "Product", "Extra Info", "Device Type"]
        print("\nPort Information")
        termtables.print(data, header)

    if len(data2) != 0:
        header = ["Protocol", "Port ID", "Vulnerability"] # Make sure to add a newline after each vuln
        print("\nVulnerabilities")
        termtables.print(data2, header)

    print("\nType 'remove' to remove this Host from the Session")
    print("Press return to go back to the Main Menu")
    userInput = input("Input: ")

    if userInput == "remove":
        scannedHostsList.remove(host)
        print("The Host was removed from the Session")
        time.sleep(2)

    return

def importSession():
    subscripts.misc.clearConsole()
    print("Specify the path to the session file to import")
    print("Press return to go back to the Main Menu\n")
    sessionPath = input("Filepath: ")

    if sessionPath == "":
        return

    global scannedHostsList
    try:
        sessionFile = io.open(sessionPath, "r")
        sessionContent = sessionFile.read()
        sessionFile.close()

        scannedHostsList = ast.literal_eval(sessionContent)

        print("\nThe Session was successfully imported")
        time.sleep(2)
    except Exception as e:
        print("\nAn exception occurred when trying to import the Session:")
        print(e)
        print("\nPress return to go back to the Main Menu")
        input()
    return

def exportSession():
    subscripts.misc.clearConsole()
    suggestedFilename = time.strftime("%Y-%m-%d__%H-%M-%S", time.localtime()) + ".session"
    print("Specify the path to export the Session to")
    print("Suggested Filename: " + suggestedFilename)
    print("Simply press return to accept the suggestion")
    print("Type 'back' to go back to the Main Menu\n")
    sessionPath = input("Filepath: ")

    if sessionPath == "back":
        return

    if sessionPath == "":
        sessionPath = suggestedFilename

    try:
        sessionFile = io.open(sessionPath, "w")
        sessionFile.write(str(scannedHostsList))
        sessionFile.close()

        print("\nThe Session was successfully exported")
        time.sleep(2)
    except Exception as e:
        print("\nAn exception occurred when trying to export the Session:")
        print(e)
        print("\nPress return to go back to the Main Menu")
        input()
    return
