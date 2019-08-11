import sys
import os
import struct
import random
from request import *
from response import *
from easyzone import easyzone
from socket import *
import signal
import threading

BYTES_TO_READ = 1024
try:
    path = sys.argv[1]
except:
	print("Please input directory name!")
	exit()
   

local_zones = []
threads = []
SERVER_PORT = 53
MY_PORT = 53

ROOT_DNS_SERVERS = ['198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
					'192.112.36.4', '128.63.2.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', 
					'199.7.83.42', '202.12.27.33']

def signal_handler(code, frame):
	print("DNS Server is shutting down")
	serversocket.close()
	sys.exit()

def read_conf():
	if os.path.isdir(path):
		for filename in os.listdir(path):
			full_path = path + "/" + filename
			if os.path.isfile(full_path):
				domain_name = filename[:filename.rfind(".")]
				zone = easyzone.zone_from_file(domain_name, full_path)
				local_zones.append(zone)

	else:
		print("Not directory")
		exit(1)	


def generate_my_request(server_name, q_id):
	my_request = dns_pack(q_id, server_name[::-1])
	my_request.set_flags(0, 0, 0, 0, 1, 1, 0)
	my_request.set_counts(1, 0, 0, 0)
	my_request.answer += my_request.get_bin_data('NS', server_name)
	my_request.answer += struct.pack('!H', 1)
	my_request.answer += struct.pack('!H', 1)

	return my_request.get()


def recursive_search (q_id, domain, message, cur_msg, client_address, servers_list = ROOT_DNS_SERVERS):
	resp = b''
	for root_address in servers_list:
		resp = send_to_server(cur_msg, root_address)
		if resp:
			break


	#None of the root servers found record, domain doesn't exist
	if not resp:
		response = dns_pack(q_id, '')
		response.set_flags(1, 0, 0, 0, 0, 1, 3)
		response.set_counts(1, 0, 0, 0)
		serversocket.sendto(response.get(), client_address)
		return None

	msg, servers, change = parse_dns_response(message, resp, domain, client_address)
	if not servers:
		flags = msg[3] | (1 << 7) #set RA flag
		msg = msg[:3] +  struct.pack('!B', flags) + msg[4:]
		serversocket.sendto(msg, client_address)
	if not msg:
		for server_name in servers:
			my_message = generate_my_request(server_name, q_id)
			if recursive_search(q_id, domain, message, my_message, client_address) is not None:
				break
	else:
		if change == 0:
			return recursive_search(q_id, domain, message, cur_msg, client_address, servers)	
		else:
			return recursive_search(q_id, domain, message, message, client_address, servers)		



def send_to_server (message, address):
	clientSocket = socket(AF_INET, SOCK_DGRAM)
	clientSocket.sendto(message, (address, SERVER_PORT))
	clientSocket.settimeout(5)
	try:
		msg, server_address = clientSocket.recvfrom(BYTES_TO_READ)
		clientSocket.settimeout(None)	
	except timeout:
		return None
		
	return msg


def parse_dns_response(root_msg, message, domain, client_address):
	response = dns_unpack(message)
	domain_name, ans_type, ans_class = response.read_query()
	if response.t_ans is not 0 or response.t_authrr == 1:
		if domain_name == domain:
			return (message, [], 0)
		else:
			server_addresses = response.read_data(response.t_ans)
			return root_msg, server_addresses, 1
	else:
		if response.t_authrr > 0:
			server_names = response.read_data(response.t_authrr)
		if response.t_addrr > 0:
			server_addresses = response.read_data(response.t_addrr - 1)	
		if server_addresses:
			return (message, server_addresses, 0)
		elif server_names:
			return ('', server_names, 0)
			
			


def send_response(message, address):
	# print("anooooooooooother")
	request = dns_unpack(message)
	domain = request.domain_name()
	req_type = request.qtype()
	req_class = request.qclass()
	response = dns_pack(request.tid, domain)

	if not req_type:
		response.set_flags(1, request.opcode, 0, 0, 0, 1, 4)
		response.set_counts(0, 0, 0, 0)
		serversocket.sendto(response.get(), address)
		return
	
	for zone in local_zones:
		# print(zone.names.keys())
		if domain in zone.names.keys():
			try:
				items = zone.names[domain].records(req_type).items
				response.set_counts(1, len(items), 0, 0)
				response.set_flags(1, 0, 1, 0, 1, 1, 0)
				response.answer += message[12:request.pointer]
			except AttributeError:
				#======="autority section"
				response.set_counts(1, 0, 1, 0)
				req_type = "SOA"
				items = zone.names[zone.domain].records(req_type).items
				response.set_flags(1, 0, 1, 0, 1, 1, 0)
				response.answer += message[12:request.pointer]
			

			for item in items: 
				response.generate_response(req_type, zone.root, item)


			serversocket.sendto(response.get(), address)
			return

		elif any (name in domain for name in zone.names.keys()):
			response.set_counts(1, 0, 0, 0)
			response.set_flags(1, 0, 1, 0, 1, 1, 9)
			serversocket.sendto(response.get(), address)
			return
			
	recursive_search(request.tid, domain, message, message, address)	


read_conf()

serversocket = socket(AF_INET, SOCK_DGRAM)
serversocket.bind(('localhost', MY_PORT))

signal.signal(signal.SIGINT, signal_handler)

print("The server is ready to receive")

while True:
    message, clientAddress = serversocket.recvfrom(512)
    serve_client = threading.Thread(target=send_response, args=(message,clientAddress, ))
    threads.append(serve_client)
    serve_client.start()
	   


