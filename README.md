# port_scanner
Discover open port on any target host. 
USAGE:
python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t 192.168.1.1 -p 1-1000
  python port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,3389
  python port_scanner.py -t 192.168.1.1 --top-ports --threads 200
  python port_scanner.py -t 192.168.1.1 --output report.txt --json results.json
  python port_scanner.py -t myserver.local -p 1-65535 --timeout 2
