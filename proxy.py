#!/usr/bin/python
# -*- coding:utf-8 -*-
# modified from http://xiaoxia.org/2011/11/14/update-sogou-proxy-program-with-https-support/
__version__ = "0.1"

import httplib
import logging
import os
import random
import select
import socket
import struct
import sys
import threading
import time
import BaseHTTPServer
import ConfigParser
import SocketServer


X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
SERVER_TYPES = [
    ("edu", 3),
    ("ctc", 3),
    ("cnc", 3),
    ("dxt", 3),
]
BUFFER_SIZE = 32768


# Minimize Memory Usage
threading.stack_size(128 * 1024)

def calc_sogou_hash(timestamp, host):
    s = (timestamp + host + "SogouExplorerProxy").encode("ascii")
    code = len(s)
    dwords = int(len(s) / 4)
    rest = len(s) % 4
    v = struct.unpack("%si%ss" % (str(dwords), str(rest)), s)
    for vv in v:
        if type(vv) is str:
            break
        a = (vv & 0xFFFF)
        b = (vv >> 16)
        code += a
        code ^= ((code << 5) ^ b) << 0xb
        # To avoid overflows
        code &= 0xffffffff
        code += code >> 0xb
    if rest == 3:
        code += ord(s[len(s) - 2]) * 256 + ord(s[len(s) - 3])
        code ^= (code ^ (ord(s[len(s) - 1]) * 4)) << 0x10
        code &= 0xffffffff
        code += code >> 0xb
    elif rest == 2:
        code += ord(s[len(s) - 1]) * 256 + ord(s[len(s) - 2])
        code ^= code << 0xb
        code &= 0xffffffff
        code += code >> 0x11
    elif rest == 1:
        code += ord(s[len(s) - 1])
        code ^= code << 0xa
        code &= 0xffffffff
        code += code >> 0x1
    code ^= code * 8
    code &= 0xffffffff
    code += code >> 5
    code ^= code << 4
    code &= 0xffffffff
    code += code >> 0x11
    code ^= code << 0x19
    code &= 0xffffffff
    code += code >> 6
    code &= 0xffffffff
    return hex(code)[2:].rstrip("L").zfill(8)


class ProxyInfo(object):
    host = None
    ip = None
    port = 80


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    remote = None

    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except socket.error:
            pass

    def finish(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except socket.error:
            pass

    # CONNECT Data Transfer
    def remote_connect(self):
        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote.settimeout(None)
        if not ProxyInfo.ip:
            try:
                ProxyInfo.ip = socket.gethostbyname(ProxyInfo.host)
                assert ProxyInfo.ip
            except (socket.gaierror, AssertionError):
                return "Failed to resolve proxy host!"
        try:
            self.remote.connect((ProxyInfo.ip, ProxyInfo.port))
        except socket.error, e:
            return "%d: %s" % (e.errno, e.message)


    def add_sogou_header(self):
        self.headers["X-Sogou-Auth"] = X_SOGOU_AUTH
        self.headers["X-Sogou-Timestamp"] = hex(int(time.time()))[2:].rstrip("L").zfill(8)
        self.headers["X-Sogou-Tag"] = calc_sogou_hash(self.headers["X-Sogou-Timestamp"], self.headers["Host"])

    def remote_send_requestline(self):
        content = self.requestline.encode("ascii") + b"\r\n"
        logging.debug("Request {}: {}".format(self.ident, repr(content)))
        self.remote.sendall(content)

    def remote_send_headers(self):
        # self.headers is a rfc822.Message which has a headers attribute
        self.headers["Connection"] = "close"
        del self.headers["Proxy-Connection"]
        header_text = "\r\n".join(
                [x.rstrip("\r\n") for x in self.headers.headers]) + "\r\n"*2
        if self.server.config["debug"]:
            for line in header_text.split("\n")[:-1]:
                logging.debug("Request {}: {}".format(self.ident, repr(line+"\n")))
        self.remote.sendall(header_text)

    def remote_send_postdata(self):
        if self.command == "POST":
            self.remote.sendall(self.rfile.read(int(self.headers["Content-Length"])))

    def local_write_connect(self):
        fdset = [self.remote, self.connection]
        while True:
            r, w, _ = select.select(fdset, [], [])
            if r:
                for soc in r:
                    i = fdset.index(soc)
                    try:
                        data = soc.recv(BUFFER_SIZE)
                    except socket.error, e:
                        self.send_error(httplib.BAD_GATEWAY, "%d: %s" % (e.errno, e.message))
                    else:
                        if not data:
                            return
                        the_other_soc = fdset[i ^ 1]
                        the_other_soc.sendall(data)

    def local_write_other(self):
        while True:
            response_data = self.http_response.read(BUFFER_SIZE)
            if not response_data:
                break
            self.wfile.write(response_data)

    def local_write_line(self):
        # Reply to the browser
        http_resp = self.http_response
        if self.server.config["debug"]:
            reply = "HTTP/{:.1f} {} {}".format(http_resp.version/10.0,
                    http_resp.status, http_resp.reason)
            logging.debug("Response {}: {}".format(self.ident, reply))
            for k, v in http_resp.getheaders():
                logging.debug("Response {}: {}: {}".format(self.ident, k, v))

        self.http_response.msg["Connection"] = "close"
        del self.http_response.msg["Proxy-Connection"]

        header_text = "\r\n".join([x.rstrip("\r\n") for x in self.http_response.msg.headers]) + "\r\n"*2
        self.wfile.write("HTTP/1.1 {0:>s} {1:>s}\r\n{2:>s}".format(
            str(self.http_response.status), self.http_response.reason, header_text) )

    def build_local_response(self):
        self.http_response = httplib.HTTPResponse(self.remote,
                method=self.command)
        try:
            self.http_response.begin()
        except socket.error, e:
            logging.exception(e.message)

    def add_forward_header(self):
        if self.server.config["send_forward_header"]:
            self.headers["X-Forwarded-For"] = self.server.proxy_forward_ip

    def proxy(self):
        if self.command == "POST" and "Content-Length" not in self.headers:
            self.send_error(httplib.BAD_REQUEST, "POST method without Content-Length header!")
            return
        else:
            error_msg = self.remote_connect()
            if error_msg:
                self.send_error(httplib.BAD_GATEWAY, error_msg)
                return

        if 'Host' not in self.headers:
            self.send_error(httplib.BAD_REQUEST, "Host field missing in HTTP request headers.")
            return
        self.ident = id(self.remote) # current proxy request identification
        self.add_sogou_header()
        self.add_forward_header()
        self.remote_send_requestline()
        self.remote_send_headers()
        self.remote_send_postdata()
        self.build_local_response()
        self.local_write_line()
        if self.command == "CONNECT":
            if self.http_response.status == httplib.OK:
                self.local_write_connect()
            else:
                self.send_error(httplib.BAD_GATEWAY,
                    "CONNECT method but response with status code %d" % self.http_response.status)
        else:
            self.local_write_other()

    def do_proxy(self):
        try:
            return self.proxy()
        except socket.timeout:
            self.send_error(httplib.GATEWAY_TIMEOUT)
        except socket.error, e:
            pass
        except Exception:
            logging.exception("Exception")

    do_HEAD = do_POST = do_GET = do_CONNECT = do_PUT = do_DELETE = do_OPTIONS = do_TRACE = do_proxy


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

def get_forward_ip():
    """synthesize a valid forward IP"""
    base = '220.181.1'
    v1 = random.randint(0, 54)
    v2 = random.randint(0, 254)
    proxy_forward_ip = "{}{}.{}".format(base, v1, v2)
    return proxy_forward_ip

def load_config(config):
    """config: a dict for config options."""
    sys_config_file = "%s.ini" % os.path.splitext(__file__)[0]
    # ~/.config/sogou-proxy/proxy.ini
    home_config_path = os.path.join("$HOME", ".config", "sogou-proxy",
            os.path.basename(sys_config_file))
    home_config_path = os.path.expandvars(home_config_path)
    config_path_list = [sys_config_file, home_config_path]
    config_file = ConfigParser.RawConfigParser(config)
    valid_config_files = config_file.read(config_path_list)
    for config_file_path in valid_config_files:
        logging.info("Load config file at {}".format(config_file_path))

    config["ip"] = config_file.get("listen", "ip")
    config["port"] = config_file.getint("listen", "port")
    config["server_type"] = SERVER_TYPES[config_file.getint("run", "type")]
    config["send_forward_header"] = config_file.getboolean(
            "run", "send_forward_header")

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(
            description="Forward HTTP/HTTPS traffic to SoGou Proxy servers.")
    parser.add_argument("-i", "--ip", action="store",
            help=("IP address of local network interface for the proxy. "
                "Use '-i \"\"' to listen on all the local interfaces."))
    parser.add_argument("-p", "--port", action="store",
            help="Port for the proxy to listen to")
    type_str = ", ".join([x[0] for x in SERVER_TYPES])
    parser.add_argument("-t", "--server-type", action="store",
            help="Proxy type: [{}]".format(type_str))
    parser.add_argument("-f", "--forward-header", action="store_true",
            help="Add X-Forwarded-For header")
    parser.add_argument("-D", "--debug", action="store_true",
            help="Debug run")
    parser.add_argument("--version", action="version",
            version="%(prog)s {}".format(__version__))
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level,
            format="%(asctime)-14s %(levelname)s: %(message)s",
            datefmt="%m-%d %H:%M:%S", stream=sys.stderr)
    logging.debug("args: {}".format(args))

    config = {}
    # Set default values here.
    config["ip"]= "127.0.0.1"
    config["port"] = "8083"
    config["server_type"] = SERVER_TYPES[0]
    config["send_forward_header"] = "False"

    load_config(config)

    config["debug"] = args.debug
    if args.ip is not None:
        config["ip"] = args.ip
    if args.port is not None:
        config["port"] = int(args.port)
    if args.server_type is not None:
        for t in SERVER_TYPES:
            if t[0] == args.server_type.lower():
                config["server_type"] = t
    if args.forward_header:
        config["send_forward_header"] = True

    logging.debug("config: {}".format(config))
    server_type = config["server_type"]
    ProxyInfo.host = "h%d.%s.bj.ie.sogou.com" % (random.randint(0, server_type[1]), server_type[0])

    server = ThreadingHTTPServer((config["ip"], config["port"]), Handler)
    server.config = config
    if hasattr(server, "daemon_threads"):
        server.daemon_threads = True

    print "Sogou Proxy:\n  Running on %s\n  Listening on %s:%d" % (ProxyInfo.host, config["ip"], config["port"])
    if config["send_forward_header"]:
        server.proxy_forward_ip = get_forward_ip()
        print("  Forwarded IP {}".format(server.proxy_forward_ip))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()

if __name__ == "__main__":
    main()
