#!/bin/env python
#
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-12-15 22:11:10 macan>
#
# Armed with EMACS.
# 
# This file setup a cherrypy http server for Pomegranate storage.
# See detailed documentation at http://github.com/macan/Pomegranate/wiki
#

import cherrypy
import re
import os, time, sys
import getopt
import signal
import cmd
import shlex
from ctypes import *

try:
    libc = CDLL("libc.so.6")
    lib = CDLL("../../lib/libhvfs.so.1.0", mode=RTLD_GLOBAL)
    xnet = CDLL("../../lib/libxnet.so.1.0", mode=RTLD_GLOBAL)
    mds = CDLL("../../lib/libmds.so.1.0", mode=RTLD_GLOBAL)
    root = CDLL("../../lib/libr2.so.1.0", mode=RTLD_GLOBAL)
    api = CDLL("../../lib/libapi.so.1.0", mode=RTLD_GLOBAL)
except OSError, oe:
    print "Can not load shared library: %s" % oe
    sys.exit()

def errcheck(res, func, args):
    if not res: raise IOError
    return res

def cli_start(argv):
    '''init the client object'''
    try:
        opts, args = getopt.getopt(argv, "ht:i:r:",
                                   ["help", "thread=", "id=", 
                                    "ring="])
    except getopt.GetoptError:
        sys.exit()
        
    thread = 1
    id = 0
    fsid = 0
    port = 8412
    ring = "127.0.0.1"

    try:
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_help()
                sys.exit()
            elif opt in ("-t", "--thread"):
                thread = int(arg)
            elif opt in ("-i", "--id"):
                id = int(arg)
            elif opt in ("-r", "--ring"):
                ring = arg
    except ValueError, ve:
        print "Value error: %s" % ve
        sys.exit()

    print "FS Client %d Running w/ (%d threads)..." % (id, 
                                                       thread)

    # init the FS client
    CSTR_ARRAY = c_char_p * 11
    argv = CSTR_ARRAY("pyAMC", "-d", str(id), "-r", ring, "-p", 
                      str(port + id), "-f", str(fsid), 
                      "-y", "client")
    err = api.__core_main(11, argv)
    if err != 0:
        print "api.__core_main() failed w/ %d" % err
        return -1

def cli_statfs(args = None):
    '''Statfs to get the metadata of the file system.
    Usage: statfs'''

    try:
        c_data = c_void_p(None)
        err = api.hvfs_statfs(byref(c_data))
        if err != 0:
            return {"Error" : "api.hvfs_statfs() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result" : string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error" : "ValueError %s" % ve}

    return result

def cli_ls(args = '/'):
    '''List a directory.
    Usage: list /path/to/dir'''
    l = shlex.split(args)
    if len(args) < 1:
        return {"Error": "Invalid argument. See help ls."}
    
    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not support yet."}

    # ok, call api.readdir to list the directory
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_readdir(c_path, c_file, byref(c_data))
        if err != 0:
            return {"Error": ("api.hvfs_readdir() failed w/ %s(%d)"
                              % (os.strerror(-err), err))}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result

def cli_stat(args = '/'):
    '''Stat a file. If any of the dir does not exist,
    we just reject the operations.
    Usage: stat path/to/name
    
    Result description:
    puuid(0x) psalt(0x) uuid(0x) flags(0x) uid gid mode(o) 
    nlink size dev atime ctime mtime dtime version 
    {$symlink/$llfs:fsid$llfs:rfino} [column_no stored_itbid len offset]
    '''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help stat."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.stat to stat the file
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_stat(c_path, c_file, byref(c_data))
        if err != 0:
            return {"Error" :"api.hvfs_stat() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result

def cli_setattr(args = ""):
    '''Set the attributes of a file in current pathname. 
    Usage: setattr /path/to/name key1=value1,key2=value2
    
    Result description:
    the column region is always ZERO (please use stat to get the correct values)
    '''
    l = shlex.split(args)
    if len(l) < 2:
        return {"Error": "Invalid argument. See help setattr."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.fupdate to update the file attributes
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = cast(c_char_p(l[1]), c_void_p)
        err = api.hvfs_fupdate(c_path, c_file, byref(c_data))
        if err != 0:
            return {"Error": "api.hvfs_fupdate() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result

def cli_write(args = "", content = ""):
    '''Copy a file from local file system to Pomegranate.
    Usage: write /path/to/hvfs'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help cpin."}

    l[0] = os.path.normpath(l[0])

    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # write to hvfs and commit metadata (create or update)
    try:
        dlen = len(content)
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_column = c_int(0)
        c_content = c_char_p(content)
        c_len = c_long(dlen)
        c_flag = c_int(0)
        err = api.hvfs_fwrite(c_path, c_file, c_column, c_content, c_len, 
                              c_flag)
        if err != 0:
            return {"Error": "api.hvfs_fwrite() failed w/ %d" % err}
        else:
            result = {"Result": "+OK"}
    except IOError, ioe:
        result = {"Error": "IOError %s" % ioe}
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result

def cli_read(args = ""):
    '''Copy a Pomegranate file to local file system.
    Usage: read /path/to/hvfs'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help cpout."}
    
    l[0] = os.path.normpath(l[0])
    
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # read the metadata to find file offset and read in the file content
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_column = c_int(0)
        c_content = c_void_p(None)
        c_len = c_long(0)
        err = api.hvfs_fread(c_path, c_file, c_column, byref(c_content), byref(c_len))
        if err != 0:
            return {"Error": "api.hvfs_fread() failed w/ %d" % err}
    except IOError, ioe:
        return {"Error": "IOError %s" % ioe}

    c_str = c_char_p(c_content.value)
    content = c_str.value
    leng = c_len.value
    result = {"Result": content, "Len": leng}

    api.hvfs_free(c_content)

    return result

def cli_create(args = ""):
    '''Touch a new file in current pathname. If the dirs 
    are not exist, we do NOT create it automatically. Use mkdir itestad.
    Usage: touch path/to/name'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help touch."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.create to create the file, no recurisive
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_create(c_path, c_file, byref(c_data), 0)
        if err != 0:
            return {"Error": "api.hvfs_create() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        return {"Error": "ValueError %s" % ve}

    return result

def cli_mkdir(args = ""):
    '''Make a new dir in current pathname.
    Usage: mkdir /path/to/dir'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help mkdir."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.create to create the dir
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_create(c_path, c_file, byref(c_data), 1)
        if err != 0:
            return {"Error": "api.hvfs_create() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result

def cli_delete(args = ""):
    '''Delete a file. If any of the dir does not exist,
    we just reject the operation.
    Usage: delete path/to/name'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help delete."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.delete to delete the file
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_fdel(c_path, c_file, byref(c_data), 0)
        if err != 0:
            return {"Error": "api.hvfs_fdel() failed w/ %d" % err}
        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        return {"Error": "ValueError %s" % ve}

    return result

def cli_rmdir(args = ""):
    '''Remove a directory by current path name.
    Usage: rmdir /path/to/dir'''
    l = shlex.split(args)
    if len(l) < 1:
        return {"Error": "Invalid argument. See help rmdir."}

    l[0] = os.path.normpath(l[0])
    path, file = os.path.split(l[0])
    if path == "" or path[0] != '/':
        return {"Error": "Relative path name is not supported yet."}

    # ok, call api.delete to delete the directory
    try:
        c_path = c_char_p(path)
        c_file = c_char_p(file)
        c_data = c_void_p(None)
        err = api.hvfs_readdir(c_path, c_file, byref(c_data))
        if err != 0:
            return {"Error": "api.hvfs_readdir() failed w/ %d" % err}
        if c_data.value != None:
            return {"Error": "Directory '%s/%s' is not empty!" % (path,
                                                                  file)}
        c_data = c_void_p(None)
        err = api.hvfs_fdel(c_path, c_file, byref(c_data), 1)
        if err != 0:
            return {"Error": "api.hvfs_fdel() failed w/ %d" % err}

        c_str = c_char_p(c_data.value)
        string = c_str.value
        result = {"Result": string}
        # free the region
        api.hvfs_free(c_data)
    except ValueError, ve:
        result = {"Error": "ValueError %s" % ve}

    return result


def cli_stop():
    '''Stop the client'''
    api.__core_exit(None)

class Resource(object):
    '''Core HTTP service function for RESTfull API'''

    exposed = True
    cmd_cnt = 0

    def __init__(self, content = None):
        '''init the content'''
        self.content = content

    def GET(self):
        '''handle GET calls'''
        # parse the input
        headers = cherrypy.request.headers
        cmd = dict()
        try:
            cmd.update(headers)
        except KeyError, exp:
            raise cherrypy.HTTPError(400)

        try:
            if 'Command' in cmd:
                self.cmd_cnt = self.cmd_cnt + 1
                if cmd['Command'] == "statfs":
                    self.content = cli_statfs()
                elif cmd['Command'] == 'list':
                    self.content = cli_ls(cmd['Args'])
                elif cmd['Command'] == 'stat':
                    self.content = cli_stat(cmd['Args'])
                elif cmd['Command'] == 'read':
                    self.content = cli_read(cmd['Args'])
                else:
                    self.content = {"Error": "Invalid command."}
                cherrypy.response.headers['Command-Id'] = self.cmd_cnt
                cherrypy.response.headers['Content-Type'] = 'text/html'
            else:
                self.content = {"Error": "No command found."}
        except KeyError, exp:
            raise cherrypy.HTTPError(400, "Can't find the command or arguments.")

        return self.to_html()

    def PUT(self):
        '''handle PUT calls'''
        headers = cherrypy.request.headers
        cmd = dict()
        try:
            cmd.update(headers)
        except KeyError, exp:
            raise cherrypy.HTTPError(400)

        try:
            if 'Command' in cmd:
                self.cmd_cnt = self.cmd_cnt + 1
                if cmd['Command'] == 'create':
                    self.content = cli_create(cmd['Args'])
                elif cmd['Command'] == 'mkdir':
                    self.content = cli_mkdir(cmd['Args'])
                else:
                    self.content = {"Error": "Invalid command."}
                cherrypy.response.headers['Command-Id'] = self.cmd_cnt
                cherrypy.response.headers['Content-Type'] = 'text/html'
            else:
                self.content = {"Error": "No command found."}
        except KeyError, exp:
            raise cherrypy.HTTPError(400, "Can't find the command or arguments.")

        return self.to_html()

    def POST(self):
        '''handle POST calls'''
        headers = cherrypy.request.headers
        cmd = dict()
        try:
            cmd.update(headers)
        except KeyError, exp:
            raise cherrypy.HTTPError(400)

        try:
            if 'Command' in cmd:
                self.cmd_cnt = self.cmd_cnt + 1
                if cmd['Command'] == 'write':
                    self.content = cli_write(cmd['Args'],
                                             cherrypy.request.body.read())
                elif cmd['Command'] == "setattr":
                    self.content = cli_setattr(cmd['Args'])
                else:
                    self.content = {"Error": "Invalid command."}
                cherrypy.response.headers['Command-Id'] = self.cmd_cnt
                cherrypy.response.headers['Content-Type'] = 'text/html'
            else:
                self.content = {"Error": "No command found."}
        except KeyError, exp:
            raise cherrypy.HTTPError(400, "Can't find the command or arguments.")
        except AttributeError:
            raise cherrypy.HTTPError(400, "No request body!")

        return self.to_html()

    def DELETE(self):
        '''handle DELETE calls'''
        # parse the input
        headers = cherrypy.request.headers
        cmd = dict()
        try:
            cmd.update(headers)
        except KeyError, exp:
            raise cherrypy.HTTPError(400)

        try:
            if 'Command' in cmd:
                self.cmd_cnt += 1
                if cmd['Command'] == "delete":
                    self.content = cli_delete(cmd['Args'])
                elif cmd['Command'] == "rmdir":
                    self.content = cli_rmdir(cmd['Args'])
                else:
                    self.content = {"Error": "Invalid command."}
                cherrypy.response.headers['Command-Id'] = self.cmd_cnt
                cherrypy.response.headers['Content-Type'] = 'text/html'
            else:
                self.content = {"Error": "No command found."}
        except KeyError, exp:
            raise cherrypy.HTTPError(400, "Can't find the command or arguments.")

        return self.to_html()


    def to_html(self):
        '''convert the content to html'''
        try:
            if 'Result' in self.content:
                return str(self.content['Result'])
            elif 'Error' in self.content:
                return str(self.content['Error'])
            else:
                return "Unknown error."
        except KeyError:
            return "Unexpected error."

    @staticmethod
    def from_html(data):
        pattern = re.compile(r'\<div\>(?P<name>.*?)\:(?P<value>.*?)\<div\>')
        items = [match.groups() for match in pattern.finditer(data)]
        return dict(items)

class ResourceIndex(Resource):
    '''Index of internal resource'''
    def to_html(self):
        return "SHIT"

def do_exit():
    print "do_exit client()"
    cli_stop()
    raise KeyboardInterrupt

class Root(object):
    pass

root = Root()

#root.hvfs = Resource(Client(sys.argv[1:]))
cli_start(sys.argv[1:])
root.hvfs = Resource({})
root.resource_index = ResourceIndex({'hvfs': 'hvfs'})

conf = {
    'global' : {
        'server.socket_host': '10.10.111.9',
        'server.socket_port': 80,
        },
    '/': {
        'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
        }
    }

#cherrypy.quickstart(root, '/', conf)
cherrypy._global_conf_alias.update(conf)
cherrypy.tree.mount(root, '/', conf)
if hasattr(cherrypy.engine, "signal_handler"):
    cherrypy.engine.signal_handler.subscribe()
if hasattr(cherrypy.engine, "console_control_handler"):
    cherrypy.engine.console_control_handler()
cherrypy.engine.signal_handler.set_handler(signal.SIGINT, do_exit)

try:
    cherrypy.engine.start()
    cherrypy.engine.block()
except KeyboardInterrupt:
    cherrpy.engine.stop()
    print "Aleady exited."

