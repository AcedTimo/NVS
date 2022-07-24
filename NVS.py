import subscripts.menus
import subscripts.scans

# TODO
# Add another menu to view scanned hosts
# It should show the IP, number of open ports and found vulns
# User is prompted for input to select a scanned host
# if input matches host index in list display all the details found in the scan

if __name__ == '__main__':
    while True:
        subscripts.menus.mainMenu()
