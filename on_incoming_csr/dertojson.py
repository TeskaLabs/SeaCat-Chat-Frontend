from asn1tinydecoder import asn1_node_root, asn1_get_all, asn1_get_value, \
						asn1_get_value_of_type, asn1_node_next, asn1_node_first_child, \
						asn1_read_length, asn1_node_is_child_of, \
						bytestr_to_int, bitstr_to_bytestr, \
						asn1_get_type, asn1_get_length, asn1_get_tag_number


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


def asn1_SEQ_to_json(crl_der, i, verbose=False):
	last_byte = i[2]
	i = asn1_node_first_child(crl_der, i)

	key 		= 0
	ret_json 	= {}
	next_key	= None
	while 1:
		tag_nr = asn1_get_tag_number(crl_der, i)
		str_key = "{}({})".format(key,tag_nr)

		if next_key is not None:
			str_key = "{}".format(next_key)
			next_key = None

		# value
		if tag_nr == 0x06:
			# OBJECT IDENTIFIER
			# it's value will be the key for next value
			next_key = asn1_get_value(crl_der, i)
			next_key = parse_oid(next_key)
			from oids import oids
			if oids.get(next_key) is not None:
				next_key = oids[next_key]["d"]

		elif tag_nr == 0x10:
			# SEQUENCE / SEQUENCE OF
			ret_json[str_key] = asn1_SEQ_to_json(crl_der, i)

		elif tag_nr == 0x11:
			# SET / SET OF
			j = asn1_node_first_child(crl_der, i)
			key_val = asn1_SEQ_to_json(crl_der, j)
			ret_json.update(key_val)

		elif tag_nr == 0x02:
			# INTEGER
			ret_json[str_key] = ord(asn1_get_value(crl_der, i))
			# TODO: long integers

		elif tag_nr == 0x0C:
			# UTF8String
			ret_json[str_key] = asn1_get_value(crl_der, i)

		else:
			ret_json[str_key] = asn1_get_value(crl_der, i)


		if i[2] >= last_byte:
			break
		i 	= asn1_node_next(crl_der, i)
		key = key + 1

	return ret_json


def extract_csr_info(crl_der):
		csr_json = {}

		# ROOT
		i = asn1_node_root(crl_der)

		# DATA
		i = asn1_node_first_child(crl_der,i)
		csr_json["csr"] = {}

		# VERSION
		i = asn1_node_first_child(crl_der,i)
		value = asn1_get_value(crl_der,i)
		csr_json["csr"]["version"] = ord(asn1_get_value(crl_der,i))

		# SUBJECT
		i = asn1_node_next(crl_der,i)
		csr_json["csr"]["subject"] = asn1_SEQ_to_json(crl_der, i)

		return csr_json

