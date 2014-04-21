#! /usr/bin/env python
#  -*- coding = utf-8 -*-

import thread
import time

class ThreadPool:
    def __init__(self, threadcount):
        self.lock = thread.allocate_lock()
        self.flagwait = 0
        self.flagstop = False
        self.tasklist = list()
        self.count = threadcount
    
    def start(self):
        for i in range(self.count):
            thread.start_new_thread(self.task, ())

    def task(self):
        while True:
            self.lock.acquire()
            if self.flagstop == True:
                self.count = self.count - 1
                self.lock.release() 
                break
            if len(self.tasklist) == 0:
                self.lock.release() 
                continue
            t = self.tasklist.pop()
            self.flagwait = self.flagwait + 1
            self.lock.release()
            #r = t[0](t[1])
            try:
                if t[0](t[1]):
                    self.lock.acquire()
                    t[2][0].append(t[2][1])
                    self.lock.release()
            except:
                pass
            #print 'task'
            self.lock.acquire()
            self.flagwait = self.flagwait - 1
            self.lock.release()
    
    def addtask(self, function, parameter, results):
        self.lock.acquire()
        self.tasklist.insert(0, (function, parameter, results))
        self.lock.release() 
    
    def clear(self):
        self.lock.acquire()
        self.tasklist = list()
        self.lock.release() 
    
    def wait(self):
        while True:
            time.sleep(0.1)
            self.lock.acquire()
            if (self.flagstop == True or len(self.tasklist) == 0) and self.flagwait == 0:
                self.lock.release() 
                break
            self.lock.release() 
        self.stop()

    def stop(self):
        self.lock.acquire()
        self.flagstop = True
        self.lock.release() 
        while True:
            time.sleep(0.01)
            self.lock.acquire()
            if self.count == 0:
                break
            self.lock.release() 
