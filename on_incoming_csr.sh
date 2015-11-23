#!/bin/bash

python on_incoming_csr/on_incoming_csr.py \
	-n ../../asn-decoder/new \
	-w ../../asn-decoder/wait \
	-m mongodb://localhost:27017/ \
	-f http://localhost:5000/lulz
