import sys
import os
import getopt
import requests
import curses
import ThreadPool
import jinja2

import Rule
import Detector

class Scanner(object):
    def __init__(self, program, urlroot, cookies, headers, output, source = False):
        self.program = program
        self.urlroot = urlroot
        self.cookies = cookies
        self.headers = headers
        self.rules = []
        self.results = []
        self.output = output
        self.source = source

    def getRule(self):
        path = os.path.split(os.path.realpath(__file__))[0]
        for root, dirs, files in os.walk(path):
            #print root, dirs, files
            for filename in files:
                filepath = os.path.join(root, filename)
                if os.path.splitext(filepath)[1] == '.sb':
                    #print self.source
                    rule = Rule.Rule(scanner = self, rfname = filepath, program = self.program, source = self.source)
                    if rule.load():
                        self.rules.append(rule)


    def scan(self):
        if self.source:
            threadpool = ThreadPool.ThreadPool(1)
        else:
            threadpool = ThreadPool.ThreadPool(5)

        for rule in self.rules:
            threadpool.addtask(rule.detect, (), (self.results, rule))
            #if rule.detect():
            #    self.results.append(rule)
        threadpool.start()
        threadpool.wait()
        #threadpool.clear()
        #threadpool.stop()
        pass

    def run(self):
        self.getRule()
        self.scan()


    def report(self):
        curses.setupterm()
        cols = curses.tigetnum('cols')
        result = {}
        #result['Serious'] = 0
        #result['High'] = 0
        #result['Medium'] = 0
        #result['Low'] = 0
        print '-' * cols
        print '| {0} | {1} | {2} |'.format('LEVEL'.ljust(7), 'TYPE'.ljust(20), 'DETAIL'.ljust(cols - 37))
        print '-' * cols
        rresult = []
        acc = 1
        for rule in self.results:
            print '| {0} | {1} | {2} |'.format(rule.severity.ljust(7), rule.type.ljust(20), rule.xurl[:cols - 37].ljust(cols - 37))
            rresult.append({'type':rule.type, 'severity':rule.severity, 'payload':rule.url, 'acc':acc, 'description':rule.description, 'suggestion':rule.suggestion, 'file':rule.file})
            acc = acc + 1
            try:
                result[rule.severity] += 1
            except:
                result[rule.severity] = 1
        print '-' * cols
        for i in result:
            print result[i], i
        trender = {'site':self.urlroot, 'list':rresult}
        env = jinja2.Environment(loader = jinja2.PackageLoader('Scanner', '.'))
        template = env.get_template('report-template.html')
        f = open(self.output, 'w')
        #print trender
        f.write(template.render(trender).encode('utf8'))
        f.close()
        print 'Output: ', os.path.realpath(self.output)
