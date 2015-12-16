from asn1tinydecoder import asn1_node_root, asn1_get_all, asn1_get_value, \
						asn1_get_value_of_type, asn1_node_next, asn1_node_first_child, \
						asn1_read_length, asn1_node_is_child_of, \
						bytestr_to_int, bitstr_to_bytestr, \
						asn1_get_type, asn1_get_length, asn1_get_tag_number, asn1_get_tag_type
from oids import oids


def parse_oid(value):
	oid_bytes = [ord(x) for x in value]

	oid2 	= oid_bytes[0] % 40
	oid1 	= (oid_bytes[0] - oid2) / 40

	oid 	= []
	oid.append(oid1)
	oid.append(oid2)

	# initial result value
	result = 0
	# we start with the second byte
	i = 1
	# spin it!
	while i < len(oid_bytes):
		# Get first 7 bits
		seven_bits = (oid_bytes[i] & 0x7F)
		# update result
		result = result | seven_bits

		# Check the value of the last bit of this byte
		if (oid_bytes[i] & 0x80) == 0:
			# Last bit = 0 -> this is the last byte of OID node
			# result is now the value of OID node -> store it!
			oid.append(result)
			# reset result
			result = 0
		else:
			# Last bit = 1 -> this is NOT the last byte of OID node!
			# Just reserve space for 7 bits from next byte
			result = result << 7

		# move to next byte
		i=i+1

	return ".".join([str(x) for x in oid])


def get_oid_desc(oid):
	if oids.get(oid) is not None:
		return oids[oid]["d"]
	return oid


def der_to_json(crl_der, (ixs,ixf,ixl), last_byte=None):
	i 	= (ixs,ixf,ixl)
	ret = []
	
	if last_byte is None:
		last_byte = ixl

	while 1:
		i_tag 	= asn1_get_tag_number(crl_der, i)
		i_type 	= asn1_get_tag_type(i_tag)

		if ord(crl_der[i[0]]) & 0x20 == 0x20:
			# constructed type = 6th bit of first octet is set to 1
			j 	= asn1_node_first_child(crl_der, i)
			val = der_to_json(crl_der, j, i[2])
		else:
			# primitive type
			val = asn1_get_value(crl_der, i)
			val = decode_value(val, i_type)

		ret.append( {"{}".format(i_type if i_type is not None else i_tag) : val} )

		if i[2] >= last_byte:
			break
		i = asn1_node_next(crl_der, i)

	return ret


def decode_value(value, value_type):
	if value_type == 'INTEGER':
		# TODO: long int
		try:
			t = ord(value)
			value = t
		except:
			value = value
	if value_type == 'OBJECT IDENTIFIER':
		value = parse_oid(value)
	if value_type == 'BIT STRING':
		value = bitstr_to_bytestr(value)

	return value	


def extract_csr_info_json(crl_der, byte_strings=False):
		csr_json = {}

		# ROOT
		r = asn1_node_root(crl_der)

		# DATA
		d = asn1_node_first_child(crl_der,r)

		# VERSION
		d = asn1_node_first_child(crl_der,d)
		csr_json["version"] = decode_value(asn1_get_value(crl_der,d), 'INTEGER')

		# SUBJECT
		der_subject = {}
		d = asn1_node_next(crl_der,d)
		for x in der_to_json(crl_der, d)[0]['SEQUENCE']:
			key = x['SET'][0]['SEQUENCE'][0]['OBJECT IDENTIFIER']
			val = x['SET'][0]['SEQUENCE'][1]['UTF8String']
			der_subject[get_oid_desc(key)] = val
		csr_json["subject"] = der_subject


		if byte_strings == False:
			return csr_json

		# RSA Encryption
		d = asn1_node_next(crl_der,d)
		subject_json = der_to_json(crl_der, d)[0]['SEQUENCE']
		key = subject_json[0]['SEQUENCE'][0]['OBJECT IDENTIFIER']
		key = get_oid_desc(key)
		csr_json[key] = subject_json[1]['BIT STRING']

		return csr_json


def main():
	cert_file = open('/Users/mpavelka/Desktop/EvalWildFuse/seacat/var/csr/proc/d294acea87059ee7d1fdf1584825b9e414af460493543f3a100e63a380aa65da.csr')
	der = cert_file.read()
	i = asn1_node_root(der)
	import pprint
	pp = pprint.PrettyPrinter(indent=4)
	pp.pprint(der_to_json(der, i))

if __name__ == '__main__':
	main()
