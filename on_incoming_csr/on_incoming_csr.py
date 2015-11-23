import sys, getopt, os, json
import time, datetime
import hashlib
from dertojson import extract_crl_info

_OPTIONS = {
	"SECRET" 			: "app-secret-changeme",
	"MONGODB_URI" 		: None,#"mongodb://localhost:27017/"
	"MONGODB_DB" 		: "scapdb",
	"MONGODB_TABLE"		: "CSR",
	"FRONTEND_REQ_URL" 	: None,# "http://localhost:5000/newcsr"
	"PATH_CSR_NEW" 		: None,# "./new"
	"PATH_CSR_WAITING" 	: None,# "./wait"
}



def read_csr(csr_filename):
	csr_der 	= open(csr_filename)
	ret 		= {}
	ret['csr'] 	= os.path.basename(csr_filename)
	ret.update(extract_crl_info(csr_der.read()))

	return ret



def create_ticket(csr_name, timestamp_expires=None):
	if timestamp_expires is None:
		timestamp_expires = int(time.time())+5*24*60*60 # 5 days

	str_timestamp_expires = str(timestamp_expires)
	ticket = hashlib.sha224(csr_name+_OPTIONS["SECRET"]+str_timestamp_expires).hexdigest()
	return ticket + "_" + str_timestamp_expires



def store_csr_mongo(csr_dict):
	import pymongo
	Client 	= pymongo.MongoClient(_OPTIONS["MONGODB_URI"])
	DB 		= Client[_OPTIONS["MONGODB_DB"]]
	print "Storing to {} in database {} at {}".format(
		_OPTIONS["MONGODB_TABLE"],
		_OPTIONS["MONGODB_DB"],
		_OPTIONS["MONGODB_URI"])
	try:
		DB[_OPTIONS["MONGODB_TABLE"]].insert(csr_dict.copy())
		print "DONE"
	except Exception as e: print e



def store_csr_frontend(req_dict, method='PUT'):
	import urllib2
	opener = urllib2.build_opener(urllib2.HTTPHandler)
	print "{} {} {}".format(str(req_dict), method, _OPTIONS["FRONTEND_REQ_URL"])
	request = urllib2.Request(
		url=_OPTIONS["FRONTEND_REQ_URL"],
		data=json.dumps(req_dict))
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: method
	try:
		url = opener.open(request)
		print "DONE"
	except Exception as e: print e



def process_csr(csr_filename):
	# Create ticket
	filename, ext 	= os.path.splitext(csr_filename)
	ticket = create_ticket(filename)

	# Rename to ticket name
	abspath_csr_filename 	= os.path.abspath(csr_filename)
	abspath_csr_dirname 	= os.path.dirname(abspath_csr_filename)
	new_csr_filename 			= os.path.join(abspath_csr_dirname, ticket+".csr")
	os.rename(abspath_csr_filename, new_csr_filename)

	# Read csr
	csr_dict = read_csr(new_csr_filename)
	
	# Store to database
	if _OPTIONS["MONGODB_URI"] is not None:
		store_csr_mongo(csr_dict)
	# Send ticket to frontend
	if _OPTIONS["FRONTEND_REQ_URL"] is not None:
		store_csr_frontend(csr_dict)

	print "finished processing {} -> {}".format(csr_filename, new_csr_filename)



def process_new_csrs():
	for f in os.listdir(_OPTIONS["PATH_CSR_NEW"]):
		if not f.endswith(".csr"):
			continue

		# Move to folder _OPTIONS["PATH_CSR_WAITING"]
		# This is done first so that there are no time delays
		# and so that the script doesn't process previously processed csrs
		if not os.path.isfile(os.path.join(_OPTIONS["PATH_CSR_NEW"], f)):
			continue
		os.rename(os.path.join(_OPTIONS["PATH_CSR_NEW"], f), os.path.join(_OPTIONS["PATH_CSR_WAITING"], f))

		# Process the csr
		process_csr(os.path.join(_OPTIONS["PATH_CSR_WAITING"], f))



def main(argv):
	try:
		opts, args = getopt.getopt(argv,
			"hn:w:m:d:t:f:",
			[
				"help",
				"new-csrs=",
				"waiting-csrs=",
				"mongodb-uri=",
				"mongodb-name=",
				"mongodb-table=",
				"frontend-url="
			])
	except getopt.GetoptError:
		usage() 
		sys.exit()

	global _OPTIONS

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit()

		elif opt in ("-n", "--new-csrs"):
			_OPTIONS["PATH_CSR_NEW"] = arg

		elif opt in ("-w", "--waiting-csrs"):
			_OPTIONS["PATH_CSR_WAITING"] = arg

		elif opt in ("-m", "--mongodb-uri"):
			_OPTIONS["MONGODB_URI"] = arg

		elif opt in ("-d", "--mongodb-name"):
			_OPTIONS["MONGODB_DB"] = arg

		elif opt in ("-t", "--mongodb-table"):
			_OPTIONS["MONGODB_TABLE"] = arg

		elif opt in ("-f", "--frontend-url"):
			_OPTIONS["FRONTEND_REQ_URL"] = arg

	if _OPTIONS["PATH_CSR_NEW"] is None:
		print "Path to new CSRs not specified."
		usage()
		sys.exit()

	if _OPTIONS["PATH_CSR_WAITING"] is None:
		print "Path to waiting CSRs not specified."
		usage()
		sys.exit()

	process_new_csrs()

def usage():
	print "on_incoming_csr.py -n <newcsrsfolder> -w <waitingcsrsfolder> -m <mongodburi> -d <mongodbname> -t <mongodbtable> -f <frontendurl>"

if __name__ == "__main__":
	main(sys.argv[1:])

