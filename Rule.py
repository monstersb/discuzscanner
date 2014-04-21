import sys
import os
import json

import Detector


class Rule(object):
    def __init__(self, scanner = None, rfname = None, program = None, source = None, resultwithdirect = False, severity = None, xtype = None, xurl = None, suggestion = None, description = None):
        if resultwithdirect:
            self.scanner = scanner
            self.severity = severity
            self.type = xtype
            self.xurl = xurl
            self.file = xurl
            self.url = os.path.join(self.scanner.urlroot, xurl)
            self.suggestion = suggestion
            self.description = description
            return
        self.scanner = scanner
        self.rfname = rfname
        self._program = program
        self.source = source
        
    def load(self):
        try:
            ruleJson = json.load(open(self.rfname))
            #self.program = ruleJson['program']
            if self._program != ruleJson['program']:
                return False
            if ruleJson.has_key('source') != self.source:
                return False
            if ruleJson.has_key('source') and ruleJson['source'] == False:
                return False
            if ruleJson.has_key('debug'):
                self.debug = True
            else:
                self.debug = False
            #self.debug = ruleJson.has_key('debug')
            #self.url = self.scanner.urlroot + ruleJson['url']
            self.url = os.path.join(self.scanner.urlroot, ruleJson['url'])
            self.xurl = ruleJson['url']
            self.type = ruleJson['type']
            self.severity = ruleJson['severity']
            self.payload = ruleJson['payload']
            self.description = ruleJson['description']
            self.suggestion = ruleJson['suggestion']
            self.file = ruleJson['file']
            if self.source == False:
                self.method = ruleJson['method']
                if ruleJson['cookies']:
                    self.cookies = self.scanner.cookies
                else:
                    self.cookies = {}
                if ruleJson['headers']:
                    self.headers = self.scanner.headers
                else:
                    self.headers = {}
            if ruleJson['detector'] == 'Accurate':
                self.detector = Detector.Accurate(self)
                self.md5 = ruleJson['md5']
            elif ruleJson['detector'] == 'Fuzzy':
                self.detector = Detector.Fuzzy(self)
                self.basis = ruleJson['basis']
                if self.basis == 'keyword':
                    self.keyword = ruleJson['keyword']
            elif ruleJson['detector'] == 'Aduit':
                self.detector = Detector.Aduit(self)
                self.basis = ruleJson['basis']
                if self.basis == 'keyword':
                    self.keyword = ruleJson['keyword']
            elif ruleJson['detector'] == 'Custom':
                exec('self.detector = Detector.' + ruleJson['detectorx'] + '(self)')
                self.customdata = ruleJson['customdata']
            return True
        except:
            print >> sys.stderr, 'Rule error!', sys.exc_info()
            return False

    def detect(self, reserve=()):
        return self.detector.detect()
