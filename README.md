# port_scanner
Discover open port on any target host. 
USAGE:

python portscope.py -t 192.168.1.1

  python portscope.py -t 192.168.1.1 -p 1-1000
  
  python portscope.py -t 192.168.1.1 -p 22,80,443,3306,3389
  
  python portscope.py -t 192.168.1.1 --top-ports --threads 200
  
  python portscope.py -t 192.168.1.1 --output report.txt --json results.json
  
  python portscope.py -t myserver.local -p 1-65535 --timeout 2



# DEMONSTRATION  


──────────────────────────────────────────────────────────────
  ⚠  LEGAL NOTICE
  This tool is for authorized security testing only.
  You must have explicit written permission to scan
  any target you do not personally own.
  Unauthorized scanning may violate computer crime laws.
──────────────────────────────────────────────────────────────
  
  I confirm I have permission to scan this target [y/N]: y


══════════════════════════════════════════════════════════════
  MULA PORT SCANNER v1.0.0
══════════════════════════════════════════════════════════════

  
  Target  : 192.168.1.1
  Ports   : 65 ports
  Threads : 100
  Timeout : 1.5s
  Time    : 2026-10-09 15:59:09


──────────────────────────────────────────────────────────────
  Scanning...
  Scan complete — 2.36s                    ] 65/65

──────────────────────────────────────────────────────────────

  PORT      STATE     SERVICE             VERSION
──────────────────────────────────────────────────────────────
  53        open      DNS                 unknown

══════════════════════════════════════════════════════════════

  SCAN SUMMARY
──────────────────────────────────────────────────────────────
  Open ports found  : 1
  Total CVEs found  : 0
  Scan duration     : 2.36s
══════════════════════════════════════════════════════════════
