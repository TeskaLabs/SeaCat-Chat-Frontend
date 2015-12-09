import ConfigParser, argparse, sys, getopt, os, json
import time, datetime
import hashlib
from asn1dertools import extract_csr_info_json


config = ConfigParser.ConfigParser()


def filename_to_ticket(filename, timestamp_expires=None):
	if timestamp_expires is None:
		timestamp_expires = int(time.time())+5*24*60*60 # 5 days... TODO: from config

	str_timestamp_expires = str(timestamp_expires)
	ticket = hashlib.sha224(filename+config.get("default", "secret")+str_timestamp_expires).hexdigest()
	return ticket + "_" + str_timestamp_expires



def store_csr_mongo(csr_dict, mongodb_uri, mongodb_db, mongodb_table):
	import pymongo
	Client 	= pymongo.MongoClient(mongodb_uri)
	DB 		= Client[mongodb_db]
	try:
		DB[mongodb_table].insert(csr_dict.copy())
		print "Stored to MongoDB..."
	except Exception as e: print e



def store_csr_frontend(csr_dict, req_url, method='PUT'):
	import urllib2
	opener = urllib2.build_opener(urllib2.HTTPHandler)
	try:
		request = urllib2.Request(
			url=req_url,
			data=json.dumps(csr_dict))
		request.add_header('Content-Type', 'application/json')
		request.get_method = lambda: method
	
		url = opener.open(request)
		print "Sent to frontend..."
	except Exception as e: print e



def process_csr(file_csr, csr_filename):
	# Assemble data
	csr_dict = {
		"filename"	: csr_filename,
		"ticket"	: filename_to_ticket(csr_filename),
		"csr"		: extract_csr_info_json(file_csr.read())
	}
	print csr_dict
	
	# Store to database
	if config.has_section("mongodb"):
		store_csr_mongo(csr_dict,
			mongodb_uri=config.get("mongodb", "uri"),
			mongodb_db=config.get("mongodb", "db"),
			mongodb_table=config.get("mongodb", "table"))
	# Send ticket to frontend
	if config.has_option("frontend", "url"):
		store_csr_frontend(csr_dict, config.get("frontend", "url"))



def main(argv):
	global config

	parser = argparse.ArgumentParser(epilog=get_usage_epilog(), formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-c", "--config", help="path to configuration file", required=True)
	parser.add_argument("-f", "--filename", dest="csr_filename", help="CSR file name (required if csr argument is '-')")
	parser.add_argument("csr", help="CSR file path (if set to '-' CSR is read from stdin)")
	
	args = parser.parse_args()
	
	config.read(args.config)

	if not config.has_option("default", "secret"):
		print "Error: You must provide secret key in config file."
		parser.print_help()
		sys.exit()
	if config.has_section("mongodb"):
		if not config.has_option("mongodb", "uri") \
			or not config.has_option("mongodb", "db") \
			or not config.has_option("mongodb", "table"):
			print "Error: You must specify URI, DB and table name in config file."
			parser.print_help()
			sys.exit(1)

	if args.csr == "-":
		if args.csr_filename is None:
			print "Error: You must specify CSR file name when providing CSR in stdin."
			parser.print_help()
			sys.exit(1)
		# Read CSR from stdin
		file_csr = sys.stdin
	else:
		args.csr_filename 	= os.path.basename(args.csr)
		file_csr 			= open(args.csr)

	process_csr(file_csr, args.csr_filename)


def get_usage_epilog():
	return """
config file:
  [default]
    secert=		secret key used to hashing ticket
  [mongodb]
    uri=		mongoDB URI where CSR will be saved
    db=			database name in MongoDB
    table=		table name in MongoDB
  [frontend]
    url=		frontend URL where CSR will be sent
"""

if __name__ == "__main__":
	main(sys.argv[1:])
