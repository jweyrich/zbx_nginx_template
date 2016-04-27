#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
is_python_3 = sys.version_info > (3, 0)

import argparse, base64, re, struct, time, socket, datetime, os.path

if is_python_3:
    import urllib.request as urllib # Python 3
    import codecs
else:
    import urllib2 as urllib # Python 2

try:
    import json
except:
    import simplejson as json

parser = argparse.ArgumentParser()
parser.add_argument('--use-ssl', default=False, action="store_true", help='Enable SSL')
parser.add_argument('--ssl-cafile', default='/etc/zabbix/certs/cacert.pem', type=str, help='CA PEM file path')
parser.add_argument('--ssl-certfile', default='/etc/zabbix/certs/agent.crt', type=str, help='Client/Agent certificate file path')
parser.add_argument('--ssl-keyfile', default='/etc/zabbix/certs/agent.key', type=str, help='Client/Agent private key file path')
parser.add_argument('--zabbix-server', default='127.0.0.1', type=str, help='Zabbix server host')
parser.add_argument('--zabbix-port', default=10051, type=int, help='Zabbix server port')
parser.add_argument('--monitored-hostname', default='Zabbix agent', type=str, help='Name of monitored host, like it shows in zabbix web ui')
parser.add_argument('--nginx-auth-username', default=None, type=str, help='Nginx authentication username')
parser.add_argument('--nginx-auth-password', default=None, type=str, help='Nginx authentication password')
parser.add_argument('--nginx-status-module-url', default='http://127.0.0.1:55777/nginx-status', type=str, help='URL to retrieve Nginx status (http_stub_status_module)')
parser.add_argument('--nginx-accesslog', default='/var/log/nginx/access.log', type=str, help='Nginx access log file path')
parser.add_argument('--print-metric', default=-1, type=int, help='Print an specific metric')
parser.add_argument('--skip-nginx-accesslog', default=False, action="store_true", help='Don\'t gather data from the Nginx access log')
parser.add_argument('--skip-nginx-status-module', default=False, action="store_true", help='Don\'t gather data from the Nginx status module (http_stub_status_module)')

args = parser.parse_args()

# grep interval in minutes
time_delta = 1

# Temp file, with log file cursor position
seek_file = '/tmp/nginx_log_stat'

class Metric(object):
    def __init__(self, host, key, value, clock=None):
        self.host = host
        self.key = key
        self.value = value
        self.clock = clock

    def __repr__(self):
        if self.clock is None:
            return 'Metric(%r, %r, %r)' % (self.host, self.key, self.value)
        return 'Metric(%r, %r, %r, %r)' % (self.host, self.key, self.value, self.clock)

def send_to_zabbix(metrics, zabbix_host, zabbix_port):
    j = json.dumps
    metrics_data = []
    for m in metrics:
        clock = m.clock or ('%d' % time.time())
        #print('%s, %s, %s, %s' % (m.host, m.key, m.value, clock))
        metrics_data.append('{"host":%s,"key":%s,"value":%s,"clock":%s}' % (j(m.host), j(m.key), j(m.value), j(clock)))
    
    # Zabbix 3.0 protocol - https://www.zabbix.com/documentation/3.0/manual/appendix/items/activepassive
    data = ('{"request":"sender data","data":[%s]}' % (','.join(metrics_data)))
    data_length = len(data)
    data_header = struct.pack('<Q', data_length) # 8 bytes
    data_to_send = b'ZBXD\x01' + data_header + data.encode('utf-8')
    #print(repr(data_to_send))

    try:
        zabbix = socket.socket()
        sock = zabbix
        if args.use_ssl:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=args.ssl_cafile)
            context.load_cert_chain(certfile=args.ssl_certfile, keyfile=args.ssl_keyfile)

            sock = context.wrap_socket(zabbix, server_hostname=zabbix_host)

        sock.connect((zabbix_host, zabbix_port))
        sock.sendall(data_to_send)

        resp_hdr = _recv_all(sock, 13)
        if not resp_hdr.decode('ascii').startswith('ZBXD\x01') or len(resp_hdr) != 13:
            print('Wrong zabbix response')
            return False

        resp_body_len = struct.unpack('<Q', resp_hdr[5:])[0]
        resp_body = sock.recv(resp_body_len).decode('ascii')

        #sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        resp = json.loads(resp_body)
        #print(resp)
        if resp.get('response') != 'success':
            print('Got error from Zabbix: %s' % resp)
            return False
        return True
    except Exception as e:
        print('Error while sending data to Zabbix %s:' % e)
        #sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return False

def _recv_all(sock, count):
    buf = b''
    while len(buf)<count:
        chunk = sock.recv(count-len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf # type(buf) == bytes

def get(url, login, passwd):
    req = urllib.Request(url)
    if login and passwd:
        base64string = base64.encodestring('%s:%s' % (login, passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)
    q = urllib.urlopen(req)
    if is_python_3:
        res = codecs.decode(q.read(), 'utf-8')
    else:
        res = q.read().decode('utf-8')
    q.close()
    return res

def parse_nginx_stat(data):
    a = {}

    # Active connections
    a['active_connections'] = re.match(r'(.*):\s(\d*)', data[0], re.M | re.I).group(2)
    # Accepts
    a['accepted_connections'] = re.match(r'\s(\d*)\s(\d*)\s(\d*)', data[2], re.M | re.I).group(1)
    # Handled
    a['handled_connections'] = re.match(r'\s(\d*)\s(\d*)\s(\d*)', data[2], re.M | re.I).group(2)
    # Requests
    a['handled_requests'] = re.match(r'\s(\d*)\s(\d*)\s(\d*)', data[2], re.M | re.I).group(3)
    # Reading
    a['header_reading'] = re.match(r'(.*):\s(\d*)(.*):\s(\d*)(.*):\s(\d*)', data[3], re.M | re.I).group(2)
    # Writing
    a['body_reading'] = re.match(r'(.*):\s(\d*)(.*):\s(\d*)(.*):\s(\d*)', data[3], re.M | re.I).group(4)
    # Waiting
    a['keepalive_connections'] = re.match(r'(.*):\s(\d*)(.*):\s(\d*)(.*):\s(\d*)', data[3], re.M | re.I).group(6)
    
    if not is_python_3:
        for key, value in a.iteritems():
            a[key] = value.decode('utf-8')

    return a

def read_seek(file):
    if os.path.isfile(file):
        f = open(file, 'r')
        try:
            result = int(f.readline())
            f.close()
            return result
        except:
            return 0
    else:
        return 0

def write_seek(file, value):
    f = open(file, 'w')
    f.write(value)
    f.close()

#print('[12/Mar/2014:03:21:13 +0400]')

if not args.skip_nginx_accesslog:
    d = datetime.datetime.now()-datetime.timedelta(minutes=time_delta)
    minute = int(time.mktime(d.timetuple()) / 60)*60
    d = d.strftime('%d/%b/%Y:%H:%M')

    total_rps = 0
    rps = [0]*60
    tps = [0]*60
    res_code = {}

    nf = open(args.nginx_accesslog, 'r')

    new_seek = seek = read_seek(seek_file)

    # if new log file, don't do seek
    if os.path.getsize(args.nginx_accesslog) > seek:
        nf.seek(seek)

    line = nf.readline()
    while line:
        if d in line:
            new_seek = nf.tell()
            total_rps += 1
            sec = int(re.match('(.*):(\d+):(\d+):(\d+)\s', line).group(4))
            code = re.match(r'(.*)"\s(\d*)\s', line).group(2)
            if code in res_code:
                res_code[code] += 1
            else:
                res_code[code] = 1

            rps[sec] += 1
        line = nf.readline()

    if total_rps != 0:
        write_seek(seek_file, str(new_seek))

    nf.close()

should_print_metric = (args.print_metric != -1) and re.match(r'nginx\[(.*)\]', args.print_metric, re.M | re.I).group(1) or False
data = get(args.nginx_status_module_url, args.nginx_auth_username, args.nginx_auth_password).split('\n')
data = parse_nginx_stat(data)

data_to_send = []

# Adding the metrics to response
if should_print_metric:
    print(data[metric])

if not args.skip_nginx_status_module:
    for i in data:
        data_to_send.append(Metric(args.monitored_hostname, ('nginx[%s]' % i), data[i]))

if not args.skip_nginx_accesslog:
    # Add the request per seconds to response
    for t in range(0,60):
        data_to_send.append(Metric(args.monitored_hostname, 'nginx[rps]', rps[t], minute+t))

    # Add the response codes stats to response
    for t in res_code:
        data_to_send.append(Metric(args.monitored_hostname, ('nginx[%s]' % t), res_code[t]))


send_to_zabbix(data_to_send, args.zabbix_server, args.zabbix_port)
