from asn1tinydecoder import asn1_node_root, asn1_get_all, asn1_get_value, \
						asn1_get_value_of_type, asn1_node_next, asn1_node_first_child, \
						asn1_read_length, asn1_node_is_child_of, \
						bytestr_to_int, bitstr_to_bytestr, \
						asn1_get_type, asn1_get_length, asn1_get_tag_number


def parse_oid(value):
	oid_bytes = [ord(x) for x in value]
	b = oid_bytes[0] % 40
	a = (oid_bytes[0] - b) / 40
	oid_array = ["{}".format(a), "{}".format(b)]

	for x in oid_bytes[1:]:
		oid_array.append("{}".format(x))

	oid = ".".join(oid_array)
	from oids import oids
	if oids.get(oid) is not None:
		return oids[oid]["d"]
	
	return ".".join(oid_array)


def asn1_SEQ_to_json(crl_der, i, limit=0):
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

		elif tag_nr == 0x0C:
			# UTF8String
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

