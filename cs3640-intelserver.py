import socket
import sys
import dns.resolver
import ssl
from cymruwhois import Client


HOST = "127.0.0.1"
PORT = 5555
def ipv4(domain):
	try:
		result = dns.resolver.resolve(domain, "A")
	except:
		return "Error: DNS lookup failed. Possibly caused by incorrect domain."	
	return result[0].to_text()

def ipv6(domain):
	try:
		result = dns.resolver.resolve(domain, "AAAA")
	except:
		return "Error: DNS lookup failed. Possibly caused by incorrect domain."	
	return result[0].to_text()

def tlsCert(domain):
	context = ssl.create_default_context()
	s = socket.create_connection((domain, 443))
	ss = context.wrap_socket(s, server_hostname = domain)
	ss.do_handshake()
	cert = ss.getpeercert()
	print(cert)
	if cert == None:
		return "Error: No certificate found."
	else:
		return str(cert.get("subject"))

def hostingAS(domain):
	ip = ipv4(domain)
	c = Client()
	r = c.lookup(ip)
	return str(r.asn)

def organization(domain):
	context = ssl.create_default_context()
	s = socket.create_connection((domain, 443))
	ss = context.wrap_socket(s, server_hostname = domain)
	ss.do_handshake()
	cert = ss.getpeercert()
	if cert == None:
		return "Error: No certificate found."
	else:
		interesting = cert.get("subject")
		for x in interesting:
			if x[0][0] == "organizationName":
				return x[0][1]
		return "No organization found."


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST,PORT))
	s.listen()
	while True:
		conn, addr = s.accept()
		with conn:
			print (f"Connected by {addr}")
		
			data = conn.recv(1024)
			dataStr = data.decode('utf-8')
			print(dataStr)
			args = dataStr.split("|")
			match args[1]:
				case "IPV4_ADDR":
					print("Performing operation IPV4_ADDR on domain " + args[0])
					retData = ipv4(args[0])
				case "IPV6_ADDR":
					print("Performing operation IPV6_ADDR on domain " + args[0])
					retData = ipv6(args[0])
				case "TLS_CERT":
					print("Performing operation TLS_CERT on domain " + args[0])
					retData = tlsCert(args[0])
				case "HOSTING_AS":
					print("Performing operation HOSTING_AS on domain " + args[0])
					retData = hostingAS(args[0])
				case "ORGANIZATION":
					print("Performing operation ORGANIZATION on domain " + args[0])
					retData = organization(args[0])
			ret = retData.encode('utf-8')
			conn.sendall(ret)
