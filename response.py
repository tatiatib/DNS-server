import struct
record_types = {"A" : 1,"NS": 2, "MX":15, "TXT":16,  "AAAA":28, "SOA":6, "CNAME":5}
pointer_to_name = 49164
class dns_pack():

	def __init__(self, id, domain):
		self.domain = domain
		self.id = id
		self.answer = b''
		self.pointer = 0
		self.flags = 0
		self.q_count = None
		self.an_count = None
		self.ns_count = None
		self.ar_count = None
		
	def set_flags(self, QR, opcode, AA, TC, RD, RA, rcode):
		self.flags = self.flags | QR << 15 		#qr
		self.flags = (opcode << 14) | self.flags #opcode
		self.flags = (AA << 10) | self.flags 	#AA
		self.flags = (TC << 9) | self.flags 	#TC
		self.flags = (RD << 8) | self.flags 	#RD
		self.flags = (RA << 7) | self.flags 	#RA
		self.flags = rcode  | self.flags 		#orcode
	

	def set_counts(self, q_count, an_count, ns_count , ar_count):
		self.q_count = q_count
		self.an_count = an_count
		self.ns_count = ns_count
		self.ar_count = ar_count


	def get(self):
		head = struct.pack('!6H', self.id, self.flags, self.q_count, self.an_count, self.ns_count, self.ar_count)
		return head + self.answer

	def generate_response(self, qtype, zone, item):
		ttl = int(zone.ttl) if zone.ttl is not None else 116
		self.answer += struct.pack('!H', pointer_to_name)
		self.answer += struct.pack('!H', record_types[qtype])
		self.answer += struct.pack('!H', 1)
		self.answer += struct.pack('!I', ttl)
		data = self.get_bin_data(qtype, item)
		self.answer += struct.pack('!H', len(data))
		self.answer += data

	def get_bin_data(self, qtype, item):
		if qtype == "A":
			octets = item.split(".")
			return b''.join(struct.pack('!B', int(octet)) for octet in octets)

		if qtype == "AAAA":
			octets = item.split(":")
			size = len(octets)
			if size < 8:
				index = octets.index('')
				for i in range(8 - size):
					octets.insert(index, '0000') 
			return b''.join( struct.pack('!H', int(octet, 16) if octet else 0) for octet in octets)

		if qtype == "NS":
			if self.domain in item:
				item = item[:item.rfind(self.domain) - 1]
				sufix = struct.pack('!H', pointer_to_name)
			else:
				sufix = struct.pack('!B', 0)
			
			ns_res = b''
			tokens = item.split('.')
			for token in tokens:
				if token:
					prefix = bytes(token, 'utf-8')
					ns_res += struct.pack('!B', len(prefix)) + prefix	
				
			return ns_res + sufix

		


		if qtype == 'TXT':
			txt = bytes(item[1:-1], 'utf-8')
			return struct.pack('!B', len(txt)) + txt

		if qtype == "SOA":
			soa_res = b''
			items = item.split(" ")
			soa_primary_name = self.get_bin_data("NS", items[0])
			mailbox = self.get_bin_data("NS", items[1])
			soa_res += soa_primary_name + mailbox
			items = items[2:]
			for feature in items:
				soa_res += struct.pack('!I', int(feature))

			return soa_res	


		if qtype == "CNAME":
			return self.get_bin_data("NS", item)

		if qtype == "MX":
			return struct.pack('!H', int(item[0])) + self.get_bin_data("NS", item[1])

	