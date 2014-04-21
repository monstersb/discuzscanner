import md5
import os
import re
import requests
import shutil
import subprocess

import Rule



class Detector(object):
    def __init__(self, rule):
        self.rule = rule
        pass

    def detect(self):
        pass


class Custom16(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(Custom16, self).__init__(rule)
        pass

    def request(self):
        try:
            if self.rule.method == 'get':
                r = requests.get(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            elif self.rule.method == 'post':
                r = requests.post(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            return r
        except KeyboardInterrupt:
            sys.exit()
        except:
            return None

    def detect(self):
        super(Fuzzy, self).detect()
        r = self.request()
        if self.rule.basis == 'keyword':
            if self.rule.debug:
                open('debug.htm', 'w').write(r.content)
                #print self.rule.keyword
            if len(re.findall(self.rule.keyword, r.content)) > 0:
                return True
            else:
                return False
        return False

class Accurate(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(Accurate, self).__init__(rule)
        pass

    def detect(self):
        super(Accurate, self).detect()
        if self.rule.md5 == self.md5(self.getContent()):
            return True
        else:
            return False

    def getContent(self):
        try:
            if self.rule.method == 'get':
                r = requests.get(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            elif self.rule.method == 'post':
                r = requests.post(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            if r.status_code != 200:
                raise
            return r.content
        except KeyboardInterrupt:
            sys.exit()
        except:
            return None

    def md5(self, content):
        return md5.md5(str(content)).hexdigest()


class Fuzzy(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(Fuzzy, self).__init__(rule)
        pass

    def request(self):
        try:
            if self.rule.method == 'get':
                r = requests.get(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            elif self.rule.method == 'post':
                r = requests.post(self.rule.url, cookies=self.rule.cookies, headers=self.rule.headers)
            return r
        except KeyboardInterrupt:
            sys.exit()
        except:
            return None

    def detect(self):
        super(Fuzzy, self).detect()
        r = self.request()
        if self.rule.basis == 'keyword':
            if self.rule.debug:
                open('debug.htm', 'w').write(r.content)
                #print self.rule.keyword
            if len(re.findall(self.rule.keyword, r.content)) > 0:
                return True
            else:
                return False
        return False

class Aduit(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(Aduit, self).__init__(rule)
        pass

    def detect(self):
        super(Aduit, self).detect()
        try:
            content = open(self.rule.url, 'r').read()
            #print content
            re.findall(self.rule.keyword, content, re.S)[0]
            return True
        except:
            return False
        return True


class UndefinedFunction(Detector):
    def __init__(self, rule):
        super(UndefinedFunction, self).__init__(rule)
        self.rule = rule
        self.filename = self.rule.url
        self.functionname = self.rule.customdata

    def readfile(self, cfname, dfname):
        try:
            return open(os.path.join(os.path.split(cfname)[0], dfname)).read()
        except:
            return ''

    def getinclude(self, content):
        index = (content.find('include') > content.find('require') and content.find('include') or content.find('require'))
        if index < 0:
            return ('', '')
        content = content[index + 7:]
        try:
            fname = re.findall(r'\(([^\?\*/])\)', content, re.S)[0].strip('\'"')
        except:
            fname = ''
        return (fname, content)


    def getcontent(self, fname, content):
        if self.isdefined(content):
            return True
        tfname, tcontent = self.getinclude(content)
        if tfname == '' and tcontent == '':
            return False
        content = self.readfile(fname, tfname)
        self.getcontent(tfname, content)
        return False



    def isdefined(self, content):
        try:
            re.findall('function\s+{0}\s*\('.format(self.functionname), content, re.S)[0]
            return True
        except:
            return False

    def detect(self):
        super(UndefinedFunction, self).detect()


class SWFAduit(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(SWFAduit, self).__init__(rule)

    def decompile(self):
        try:
            pwd = os.path.split(os.path.realpath(__file__))[0] + '/'
            tmpmd5 = md5.md5(self.rule.url).hexdigest()
            shutil.copyfile(self.rule.url, pwd + '/tmp/' + tmpmd5 + '.swf')
            if subprocess.call([pwd + '/flare', pwd + '/tmp/' + tmpmd5 + '.swf']) != 0:
                raise
            return file(pwd + '/tmp/' + tmpmd5 + '.flr', 'r').read()
        except:
            pass
        return ''

    def detect(self):
        super(SWFAduit, self).detect()
        try:
            content = self.decompile()
            #print content
            re.findall(self.rule.customdata, content)[0]
            return True
        except:
            return False
        return True

class Custom22(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(SWFAduit, self).__init__(rule)

    def decompile(self):
        try:
            pwd = os.path.split(os.path.realpath(__file__))[0] + '/'
            tmpmd5 = md5.md5(self.rule.url).hexdigest()
            shutil.copyfile(self.rule.url, pwd + '/tmp/' + tmpmd5 + '.swf')
            if subprocess.call([pwd + '/flare', pwd + '/tmp/' + tmpmd5 + '.swf']) != 0:
                raise
            return file(pwd + '/tmp/' + tmpmd5 + '.flr', 'r').read()
        except:
            pass
        return None

    def detect(self):
        super(SWFAduit, self).detect()
        ascode = self.decompile()
        if 'this.playlistURL = _root.file;' not in ascode:
            return False

class Common(Detector):
    def __init__(self, rule):
        self.rule = rule
        super(Common, self).__init__(rule)

    def getresultlist(self):
        return self.rule.scanner.results

    def addresult(self, bug):
        rule = Rule.Rule(scanner = self.rule.scanner, resultwithdirect = True, severity = bug['severity'], xtype = bug['xtype'], xurl = bug['xurl'], suggestion = bug['suggestion'], description = bug['description'])
        result = self.getresultlist()
        result.append(rule)

    def getuserfile(self):
        oflist = {line.strip() for line in open('discuzfiles.list', 'r').readlines()}
        cflist = set([])
        for path, dirs, files in os.walk(self.rule.url):
            for filename in files:
                cflist.add(os.path.join(path, filename)[len(self.rule.url):])
        return list(cflist - oflist)

    def readfile(self, fname):
        try:
            return open(os.path.join(self.rule.url, fname), 'r').read()
        except:
            return ''

    def aduit(self, fname):
        content = self.readfile(fname)
        blist = [[r'(?:(?:echo)|(?:exit)|(?:die)|(?:var_dump)|(?:print_r)|(?:var_export)|(?:print))\s*\(?[^;]*\$_(?:(?:GET)|(?:POST)|(?:COOKIE))\s*\[.*\][^;]*\)?', {'severity':'Medium', 'xtype':'Reflective XSS', 'suggestion':'filter'}],
                [r'empty\s*\(\s*\$_(?:(?:GET)|(?:POST)|(?:COOKIE))\s*\[.*\]\s*\)?', {'severity':'Low', 'xtype':'Information Leakage', 'suggestion':'isset'}],
                [r'(?:(?:include)|(?:include_once)|(?:require)|(?:require_once))[^;]*\$_(?:(?:GET)|(?:POST)|(?:COOKIE))?\s*\[[^;]*\][^;]*\)?', {'severity':'High', 'xtype':'File Inclusion', 'suggestion':''}],
                [r'(?:(?:eval)|(?:call_user_function_array)|(?:dyn_func)|(?:create_function)|(?:unserialize))[^;]*\$_(?:(?:GET)|(?:POST)|(?:COOKIE))?\s*\[[^;]*\][^;]*\)?', {'severity':'High', 'xtype':'Code Execution', 'suggestion':''}],
                [r'(?:(?:ob_start)|(?:assert)|(?:exec)|(?:system)|(?:shell_exec)|(?:passthru)|(?:pcntl_exec))[^;]*\$_(?:(?:GET)|(?:POST)|(?:COOKIE))?\s*\[[^;]*\][^;]*\)?', {'severity':'High', 'xtype':'Command Execution', 'suggestion':''}],
                ]
        for b in blist:
            print b[0]
            klist = re.findall(b[0], content, re.S)
            print content
            print klist
            for k in klist:
                bug = b[1].copy()
                bug['xurl'] = fname
                bug['description'] = k
                self.addresult(bug)

    def detect(self):
        super(Common, self).detect()
        #for i in open
        flist = self.getuserfile()
        for fname in flist:
            bug = self.aduit(fname)
            if bug:
                self.addresult(bug)
        #self.addresult('High', 'SB', 'asdasdadadasd', '', '')
        return False
