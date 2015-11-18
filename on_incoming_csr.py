import os, json
import time, datetime
import hashlib

_SECRET 			= "app-secret-b3y444aaatch"
_MONGODB_URI 		= None#"mongodb://localhost:27017/"
_MONGODB_DB 		= "scapdb"
_MONGODB_TABLE		= "CSR"
_FRONTEND_REQ_URL 	= None# "http://localhost:5000/newcsr"
_FOLDER_NEW 		= "./new"
_FOLDER_WAITING 	= "./wait"



def read_csr(csr_filename):
	# TODO: decode ASN.1 and put actual data
	return {
		'csr' : os.path.basename(csr_filename),
		'subject' : "somesubject",
		'data' : {
			'extra' : "json_data"
		}
	}



def create_ticket(csr_name, timestamp_expires=int(time.time())+5*24*60*60):
	str_timestamp_expires = str(timestamp_expires)
	ticket = hashlib.sha224(csr_name+_SECRET+str_timestamp_expires).hexdigest()
	return ticket + "_" + str_timestamp_expires



def store_csr_mongo(csr_dict):
	import pymongo
	Client 	= pymongo.MongoClient(_MONGODB_URI)
	DB 		= Client[_MONGODB_DB]
	print "Storing to {} in database {} at {}".format(_MONGODB_TABLE, _MONGODB_DB, _MONGODB_URI)
	try:
		DB[_MONGODB_TABLE].insert(csr_dict.copy())
		print "DONE"
	except Exception as e: print e



def store_csr_frontend(req_dict, method='PUT'):
	import urllib2
	opener = urllib2.build_opener(urllib2.HTTPHandler)
	print "{} {} {}".format(str(req_dict), method, _FRONTEND_REQ_URL)
	request = urllib2.Request(
		url=_FRONTEND_REQ_URL,
		data=json.dumps(req_dict))
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: method
	try:
		url = opener.open(request)
		print "DONE"
	except Exception as e: print e



def process_waiting_csr(csr_filename):
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
	if store_mongo == True:
		store_csr_mongo(csr_dict)
	# Send ticket to frontend
	if _FRONTEND_REQ_URL is not None:
		store_csr_frontend(csr_dict)

	print "finished processing {} -> {}".format(csr_filename, new_csr_filename)



def process_waiting_csrs():
	for f in os.listdir(_FOLDER_NEW):
		if not f.endswith(".csr"):
			continue

		# Move to folder _FOLDER_WAITING
		# This is done first so that there are no time delays
		# and so that the script doesn't process previously processed csrs
		if not os.path.isfile(os.path.join(_FOLDER_NEW, f)):
			continue
		os.rename(os.path.join(_FOLDER_NEW, f), os.path.join(_FOLDER_WAITING, f))

		# Process the csr
		process_waiting_csr(os.path.join(_FOLDER_WAITING, f))



def main():
	process_waiting_csrs()

if __name__ == "__main__":
	main()

