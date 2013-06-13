#! /usr/bin/python -u

"""
paris-traceroute.py: Poll for newly closed connections and print a traceroute to
the remote address to a log file.
"""

print "Starting paris-traceroute"

from Web100 import *
import errno
import glob
import os
import socket
import subprocess
import sys
import time

def mkdirs(name):
    """ Fake mkdir -p """
    try:
        os.makedirs(name)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(name):
            pass
        else: raise

def postproc(directory):
    """ Remove all write permissions, compute md5sums, etc """
    for logfile in glob.glob(directory + "*"):
        os.chmod(logfile, 0444)
    subprocess.call("find . -type f | xargs md5sum > ../manifest.tmp",
        shell=True, chdir = directory)
    os.rename(directory + "/../manifest.tmp", directory + "/manifest.md5")
    os.chmod(directory + "/manifest.md5", 0555)
    os.chmod(directory, 0555)    # And make it immutable

OLD_DIR = ""
LOG_COUNT = 0
def getlogf(logtime):
    """ Return a logfile. May also cause old logs to be cleaned up. """
    global LOG_COUNT
    logdir = time.strftime("%Y/%m/%d/", time.gmtime(logtime))
    if OLD_DIR and OLD_DIR != logdir:
        postproc(OLD_DIR)
        LOG_COUNT = 0
    mkdirs(logdir + SERVER)
    logname = time.strftime("%Y/%m/%d/%%s%Y%m%dT%TZ_ALL%%d.paris",
                            time.gmtime(logtime)) % (SERVER, LOG_COUNT)
    LOG_COUNT += 1
    return open(logname, "a")

def do_traceroute(rem_address):
    """ Run a paris-traceroute to rem_address """
    # Ignore connections to loopback and Planet Lab Control (PLC)
    if rem_address == "127.0.0.1":
        return
    if rem_address.startswith("128.112.139"):
        return

    # pick/open a logfile as needed, based on the close poll time
    logtime = time.time()
    logf = getlogf(logtime)

    process = subprocess.Popen(["paris-traceroute",
                                "-picmp",
                                "--algo=exhaustive",
                                rem_address],
                               stdout = subprocess.PIPE)
    (proc_out, _) = process.communicate()
    logf.write(proc_out)
    logf.write("\n")
    logf.close()


CACHE_WINDOW = 60 * 10  # 10 minutes
def ip_is_recent(arg):
    """ Returns True if the current time is within CACHE_WINDOW of the given
        time stamp """
    (_, timestamp) = arg
    current_ts = time.time()
    return current_ts <= timestamp + CACHE_WINDOW

class RecentList:
    """ Keeps a list of IP addresses and the timestamps when a traceroute was
        last run against them. """
    def __init__(self):
        self.iplist = []

    def clean(self):
        """ Filter out recently used IP addresses. """
        self.iplist = filter(ip_is_recent, self.iplist)

    def add(self, remote_ip):
        """ Add remote_ip to the recently used list. """
        self.clean()
        self.iplist.append((remote_ip, time.time()))

    def contain(self, remote_ip):
        """ Returns True if the given remote_ip is in the recently used
            list. """
        self.clean()
        for (ip_address, _) in self.iplist:
            if remote_ip == ip_address:
                return True
        return False

def is_valid_ipv4_address(address):
    """ Returns True if address is a valid IPv4 address. """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
    except socket.error:
        return False
    return True

def is_valid_ipv6_address(address):
    """ Returns True if address is a valid IPv6 address. """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except AttributeError:
        # Note: This isn't strictly true, but we just don't know if this is
        # valid or not. As such, we need to be conservative.
        return False
    except socket.error:
        return False
    return True

SERVER = ""
def main():
    """ Listen for closed connections and run a paris-traceroute to the remote
        address for any connections that close. """
    global SERVER
    if len(sys.argv) == 1:
        SERVER = ""
    elif len(sys.argv) == 2:
        SERVER = sys.argv[1]+"/"
    else:
        print "Usage: %s [server_name]" % sys.argv[0]
        sys.exit()

    recent_ips = RecentList()

    while True:
        a = Web100Agent()
        closed = []
        all_connections = a.all_connections()
        newclosed = []
        for connection in all_connections:
            try:
                if connection.read('State') == 1:
                    newclosed.append(connection.cid)
                    if not connection.cid in closed:
                        rem_ip = connection.read("RemAddress")
                        if (is_valid_ipv4_address(rem_ip) and
                            not recent_ips.contain(rem_ip)):
                            print "Running trace to: %s" % rem_ip
                            do_traceroute(rem_ip)
                            recent_ips.add(rem_ip)
                        #else:
                        #    print "Skipping: %s" % rem_ip
            except Exception, e:
                print "Exception:", e
        closed = newclosed
        time.sleep(5)

if __name__ == "__main__":
    main()
