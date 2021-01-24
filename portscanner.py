import sys
import socket

"""
	This programme is a port scanner wich scans all ports on a machine. If the Port is open on that machine,
	the programme would return the open port. Portscanner are used for Penetration Testing in order to exploit
	vulnerable services running on open ports. I personally used this to scan my vulnerable Metaslpoitable 2 VM
	to find vulnerable open ports.

	DISCLAIMER: Such programmes like these are to be used on machines you have explicit permission to test.
				I WILL NOT BE RESPONSIBLE FOR MISUSE OF THIS SOFTWARE!

	- Joseph Marc Antony
"""

def scan(ip_list, port_limit):
	print("Starting Scan...\n")

	for target in ip_list:
		ip = target.strip()
		open_ports = 0
		print(f"Showing results for {ip}")
		print("---------------------------------\n")
		for port in range(1, port_limit + 1):
			try:
				sock = socket.socket()
				sock.connect((ip, port))
				print(f"[+] Open Port: {port}")
				open_ports += 1
			except:
				pass
		if open_ports == 0:
			print("[-] No ports were found open!")
		print(f"\n{open_ports} were found open in port range 1 - {port_limit}\n")


if len(sys.argv) >= 2:
	try:
		if sys.argv[1] != "--help":
			targets = sys.argv[1].split(",")
			try:
				if sys.argv[2] != "--all":
					port_limit = int(sys.argv[2])
				else:
					port_limit = 65000
			except IndexError:
				port_limit = 100
			except ValueError:
				print("[-] Use integers to specify port limit.\n")
				print(f"USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]")
				print(f"For Help, Use: python {sys.argv[0]} --help")
			try:
				scan(targets, port_limit)
			except KeyboardInterrupt:
				print("\nQuitting Scan...")
				quit(-1)
		else:
			print(f"""
Base Usage: 
	NOTE: While scanning multiple IP's seperate with comma.
	python {sys.argv[0]} [TARGET IP's]

To specify Port limit to scan:
	Usage: python {sys.argv[0]} [TARGET IP's] [PORT LIMIT]

Optional Parameters:
	--all:
		Scans All ports from 1 - 65000
		Usage: python {sys.argv[0]} [TARGET IP's] --all
				""")
	except IndexError:
		print(f"[-] USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]")
else:
	print(f"[-] USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]")
