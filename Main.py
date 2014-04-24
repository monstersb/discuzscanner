#! /usr/bin/python
# -*- coding:utf-8 -*-

import getopt
import sys
import re
import os

from Scanner import Scanner

def str2dict(str, d1, d2):
    t = str.split(d1)
    r = {}
    for i in t:
        td = i.strip().split(d2)
        r[td[0].strip()] = d2.join(td[1:]).strip()
    return r


class Main(object):
    def __init__(self):
        if self.getopt() == False:
            return
        self.run()

    def getopt(self):
        try:
            opts = {i[0]:i[1] for i in getopt.getopt(sys.argv[1:], 'wdsu:c:h:o:')[0]}
            #if opts.has_key('-s'):
            #    self.source = True
            #else:
            #    self.source = False
            self.source = opts.has_key('-s')
            if opts.has_key('-d') + opts.has_key('-w') == 1:
                if opts.has_key('-d'):
                    self.program = 'discuz'
                elif opts.has_key('-w'):
                    self.program = 'wordpress'
            else:
                raise
            self.url = opts['-u']
            if self.source:
                self.headers = None
                self.cookies = None
                re.findall('^.*/$', self.url, re.IGNORECASE)[0]
                if os.path.isdir(self.url) == False:
                    raise
            else:
                #throw error 
                re.findall('^http://[a-z0-9\./-]*/$', self.url, re.IGNORECASE)[0]
                self.headers = str2dict(opts['-h'], ';;;;;', '=')
                #print self.headers
                self.cookies = str2dict(opts['-c'], ';', '=')
                #print self.cookies
            if opts.has_key('-o'):
                self.output = opts['-o']
            else:
                self.output = 'o.html'
            try:
                f = open(self.output, 'w')
                f.close()
            except:
                print 'Could not write to', self.output
                return False
            return True
        except:
            print >> sys.stderr, sys.exc_info()
            print 'Usage:'
            print '\t-d\tdiscuz'
            print '\t-w\twordpress'
            print '\t-u\turl, root path'
            print '\t-c\tcookies'
            print '\t-h\theaders'
            print '\t-o\toutput'
            print '\t-s\twhite box'
            return False


    def run(self):
        #print dir(self)
        scanner = Scanner(self.program, self.url, self.cookies, self.headers, self.output, self.source)
        scanner.run()
        scanner.report()
        pass

if __name__ == '__main__':
    Main()
