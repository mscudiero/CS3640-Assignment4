import sys
import socket


SERVICES = ["IPV4_ADDR", "IPV6_ADDR", "TLS_CERT", "HOSTING_AS", "ORGANIZATION"]

def main():
	args = sys.argv
	if (len(args) < 2):
		print ("No command line arguments given.")
		return 1
	else:
		try:
			isa = args[args.index("-intel_server_addr") + 1]
			isp = args[args.index("-intel_server_port") + 1]
			dom = args[args.index("-domain") + 1]
			svc = args[args.index("-service") + 1]
		except ValueError:
			print ("Error: Some parameters incorrect or missing.")
			return 1
	if (str(svc) not in SERVICES): # Making sure the requested service is supported...
		print ("Unsupported service requested.")
		return 1

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((isa,int(isp)))
		data = str(dom) + "|" + str(svc)
		b = data.encode('utf-8')
		s.sendall((b))
		response = s.recv(1024)
		returned = response.decode('utf-8')
		print(returned)

if __name__ == "__main__":
	main()