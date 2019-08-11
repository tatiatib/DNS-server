import struct


record_types = {1: "A", 2:"NS", 15:"MX", 16:"TXT",  28:"AAAA", 6:"SOA", 5:"CNAME"}

class dns_unpack():

	def __init__(self, message):
		self.message = message
		self.pointer = 12
		dns_header = self.message[:self.pointer]
		h = struct.unpack('!6H', dns_header)
		self.tid, self.flags, self.t_question, self.t_ans, self.t_authrr, self.t_addrr = h
		self.opcode = ((self.flags << 1) >> 12)
		self.QR = (self.flags >> 15 ) & 1
		self.AA = ((self.flags << 5) >> 15) & 1
		self.TC = ((self.flags << 6) >> 15) & 1
		self.RD = ((self.flags << 7) >> 15) & 1
		self.RA = ((self.flags << 8) >> 15) & 1
		self.RCODE = (self.flags >> 12)
		

	def domain_name(self):
		res = ""
		cur_length = struct.unpack('!B', self.message[self.pointer:self.pointer + 1])
		
		while not cur_length[0] == 0:
			if cur_length[0] > 63:
				res += self.parse_pointer()
				return res

			self.pointer += 1
			domain = self.message[self.pointer:self.pointer + cur_length[0]]
			res += domain.decode("utf-8")+"."
			self.pointer += cur_length[0]
			cur_length = struct.unpack('!B', self.message[self.pointer:self.pointer + 1])

		self.pointer += 1
		# print(res)
		return res

	
	def parse_pointer(self):
		pointer = struct.unpack('!H', self.message[self.pointer:self.pointer + 2])
		self.pointer += 2
		prev = self.pointer
		pointer = pointer[0] - 49152
		self.pointer = pointer
		res = self.domain_name()
		self.pointer = prev
		return res
		


	def qtype(self):
		req_type = struct.unpack('!H', self.message[self.pointer:self.pointer + 2])
		self.pointer += 2
		req_type = req_type[0]
		if req_type in record_types:
			return record_types[req_type]
		return None


	def qclass(self):
		q_class = struct.unpack('!H', self.message[self.pointer:self.pointer + 2])
		self.pointer += 2

		return q_class[0]

	def read_query(self):
		domain = self.domain_name()
		q_type = self.qtype()
		q_class = self.qclass()
		return (domain, q_type, q_class)
	
	def ttl(self):
		ttl_val = struct.unpack('!I', self.message[self.pointer:self.pointer + 4])
		self.pointer += 4

		return ttl_val[0]	

	def read_ipv4_record(self):
		ip  = struct.unpack('!4B', self.message[self.pointer: self.pointer + 4])
		self.pointer += 4
		return ''.join((str(byte) + ".") for byte in ip)[:-1]

	def read_ipv6_record(self):
		
		ip  = struct.unpack('!8H', self.message[self.pointer: self.pointer + 16])
		self.pointer += 16
		return ip

	def read_data(self, n_answers):
		r_data = []
		for i in range(n_answers):
			if(self.pointer >= len(self.message)):
				break
			
			domaine_name, ans_type, ans_class = self.read_query()			
			ttl = self.ttl()
			data_length = struct.unpack('!H', self.message[self.pointer:self.pointer + 2])[0]
			self.pointer += 2
			if ans_type is 'A' :
				data = self.read_ipv4_record()
			else:
				if ans_type == 'AAAA':
					data = self.read_ipv6_record()
					continue
				else:	
					data = self.domain_name()
					
			r_data.append(data)
			
		return r_data