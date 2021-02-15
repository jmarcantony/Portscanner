"""
	This programme is a port scanner wich scans all ports on a machine. If the Port is open on that machine,
	the programme would return the open port. Portscanner are used for Penetration Testing in order to exploit
	vulnerable services running on open ports. I personally used this to scan my vulnerable Metaslpoitable 2 VM
	to find vulnerable open ports.

	DISCLAIMER: Programmes like these are to be used on machines you have explicit permission to test.
				I WILL NOT BE RESPONSIBLE FOR MISUSE OF THIS SOFTWARE!

	Written in Python 3.9.1

	- Joseph Marc Antony
"""

try:
	import sys
	import time
	import socket
	from colorama import Fore, init
except ModuleNotFoundError:
	print("[-] Requirements not satisfied.\nInstall requirements using command: pip install -r requirements.txt")
	quit(-1)
else:
	init()


def exec_time(function):
    def wrapper(*args):
        start = time.time()
        function(*args)
        end = time.time()
        exec_time = round(end - start, 2)
        print(Fore.YELLOW + f"[*] Scan completed in {exec_time} seconds\n")
    return wrapper


@exec_time
def scan(ip_list, port_limit):
	print(Fore.YELLOW + "\n[*] Starting Scan...")

	for target in ip_list:
		ip = target.strip()
		open_ports = 0
		print(Fore.CYAN + f"\nShowing results for {ip}")
		print("---------------------------------\n")
		for port in range(1, port_limit + 1):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				try:
					sock.connect((ip, port))
					open_ports += 1
				except ConnectionRefusedError:
					pass
				else:
					try:
						print(Fore.BLUE + f"[+] Open Port: " + Fore.GREEN + f"{port}{' ' * (6 - len(str(port)))}" + Fore.CYAN + "|" + Fore.BLUE + "    Service: " + Fore.GREEN + f"{socket.getservbyport(port, 'tcp')}")
					except OSError:
						print(Fore.BLUE + f"[+] Open Port: " + Fore.GREEN + f"{port}{' ' * (6 - len(str(port)))}" + Fore.CYAN + "|" + Fore.BLUE + "    Service: " + Fore.RED + "unknown")
		if open_ports == 0:
			print(Fore.RED + "[-] No ports were found open!")
						      
		print(Fore.YELLOW + f"\n[*] {open_ports} ports were found open in port range 1 - {port_limit}")


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
				port_limit = 1000
			except ValueError:
				print(Fore.RED + "[-] Use integers to specify port limit.\n")
				print(Fore.WHITE + f"USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]")
				print(f"For Help, Use: python {sys.argv[0]} --help")
			try:
				scan(targets, port_limit)
			except KeyboardInterrupt:
				print(Fore.RED + "\nQuitting Scan...")
				quit(-1)
		else:
			print(Fore.WHITE + f"""
Base Usage: 
	NOTE: While scanning multiple IP's seperate with comma.
	python {sys.argv[0]} [TARGET IP's]

	eg1. python {sys.argv[0]} 192.168.0.1
	eg2. python {sys.argv[0]} 192.168.0.1,127.0.0.1

To Specify Port limit to scan:
	Usage: python {sys.argv[0]} [TARGET IP's] [PORT LIMIT]

	eg. python {sys.argv[0]} 192.168.0.1 1000

Optional Parameters:
	--all:
		Scans All ports from 1 - 65000
		Usage: python {sys.argv[0]} [TARGET IP's] --all

		eg1. python {sys.argv[0]} 192.168.0.1 --all
		eg2. python {sys.argv[0]} 192.168.0.1,127.0.0.1 --all
		
				""")
	except IndexError:
		print(Fore.RED + f"[-] USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]\n" + Fore.WHITE + f"For Help, use:  python {sys.argv[0]} --help")
else:
	print(Fore.RED + f"[-] USAGE: python {sys.argv[0]} [TARGET IP's] [OPTIONAL PARAMETERS]\n" + Fore.WHITE + f"For Help, use:  python {sys.argv[0]} --help")
