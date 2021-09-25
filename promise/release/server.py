#!/usr/bin/env python2

import os
import signal
import SocketServer
import threading
import tempfile
import sys
import time
import subprocess
import random
import string
from hashlib import sha256



class threadedserver(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class incoming(SocketServer.BaseRequestHandler):
    def setup(self):
        try:
            self.fd, self.filename = tempfile.mkstemp()
        except:
            self.request.send("something super bad happened\n")
            self.request.close()
            return


    def recvline(self):
        line = ""
        while True:
            read = self.request.recv(1)
            if not read or read == "\n":
                break
            line += read
        line += "\n"
        return line

    def handle(self):
        self.request.send("Welcome to TCTF/0CTF!\n")
        chal = ''.join(random.choice(string.letters+string.digits) for _ in xrange(16))
        self.request.send("chal: " + chal + "\n")
        sol = self.request.recv(4)
        if len(sol) != 4 or not sha256(chal + sol).digest().startswith('\0\0\0'):
            self.request.send("wrong answer")
            self.request.close()
            return

        self.request.send("Please send your script and end with \"END\"\n")

        filename = ""
        try:
            data = ""
            while len(data) < 0x10000:
                line = self.recvline()
                if "END" in line:
                    self.request.send("recv END.\n")
                    break
                data += line
            os.write(self.fd, data)
            os.close(self.fd)
        except Exception, e:
            self.request.send("something super bad happened\n")
            self.request.close()
            return

        pid = os.fork()
        if (pid < 0):
            self.request.send("something super bad happened\n")
            self.request.close()
            return

        if pid:
            self.request.close()
            return

        # reparent to init
        if os.fork():
            os._exit(0)

        os.setsid()
        signal.alarm(30)
        self.request.send("start running your script...\n")
        print "running %s" % self.filename
        os.close(0)
        os.close(1)
        os.close(2)
        os.dup2(self.request.fileno(), 0)
        os.dup2(self.request.fileno(), 1)
        os.dup2(self.request.fileno(), 2)
        os.execl("tjs", "tjs", self.filename)

        self.request.flush()
        self.request.send("something real bad happened\n")
        self.request.close()

    def finish(self):
        time.sleep(3)
        print "remove %s" % self.filename
        os.remove(self.filename)


if __name__ == "__main__":
    SocketServer.TCPServer.allow_reuse_addr = True
    server = threadedserver(('0.0.0.0', 8888), incoming)
    server.timeout = 60
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = False
    server_thread.start()
