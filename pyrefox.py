#!/usr/bin/env python
#
# pyrefox by gNrg
#

import os
import sqlite3
import json
import base64 # Decrypt
import struct # Structures
from ConfigParser import ConfigParser
from ctypes import * # libnss

# Password Structures
class Spw(Structure):
    _fields_ = [('source',c_ubyte),('data',c_char_p)]
class SItem(Structure):
    _fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]

class Firefox_manager(object):
    def __init__(self, profile_path = None):
        self.profile_path = profile_path
        self.platform = 'linux'
        # Check profile and load libraries
        if not os.path.isdir(self.profile_path):
            raise Exception('Invalid profile path. Exiting...')
        self.libnss = CDLL("libnss3.so") # Load library
        self.ff_version, self.platform_dir, self.app_dir = self.__get_compatibility_info()

    def __get_compatibility_info(self):
        config_file = self.profile_path + '/compatibility.ini'
        if not os.path.isfile(config_file): 
            raise Exception("File 'compatibility.ini' not found. Exiting...")
        config = ConfigParser()
        config.read(config_file)
        major, minor = config.get('Compatibility', 'LastVersion').split('_')[0].split('.')[:2]
        return ((int(major), int(minor)), config.get('Compatibility', 'LastPlatformDir'), config.get('Compatibility', 'LastAppDir'))

    def test_master_password(self, password):
        self.libnss.NSS_Init(profile)
        key_slot = self.libnss.PK11_GetInternalKeySlot()
        r = self.libnss.PK11_CheckUserPassword( c_int(key_slot), c_char_p(password))# == SECsuccess
        self.libnss.PK11_FreeSlot(c_int(key_slot))
        self.libnss.NSS_Shutdown()
        return (r == 0)

    def get_profile_path(self): return self.profile_path
    def get_version(self): return (self.ff_version, self.platform_dir, self.app_dir)

    def get_saved_passwords(self, decrypt = True, masterpass = ''):
        """ Try to get and decrypt saved passwords with no master password setted."""
        db_path = '/'.join((self.profile_path, 'logins.json'))
        if not os.path.isfile(db_path):
            raise Exception("File 'logins.json' not found.")
        with open(db_path, 'rb') as logins:
            login_data = json.load(logins)

        if self.libnss.NSS_Init(self.profile_path) != 0:
            raise Exception('NSS_Init failed')

        slot = self.libnss.PK11_GetInternalKeySlot()
        self.libnss.PK11_CheckUserPassword(slot, masterpass)
        self.libnss.PK11_Authenticate(slot, True, 0)

        spw = Spw()
        spw.source = 0
        spw.data= 0

        uname = SItem()
        passwd = SItem()
        dectext = SItem()
        conn = sqlite3.connect(db_path)
        r = list()
        for row in login_data['logins']:        
            if not decrypt: # not encrypted
                row["encryptedUsername"] = base64.b64decode(row["encryptedUsername"])
                row["encryptedPassword"] = base64.b64decode(row["encryptedPassword"])
                r.append(row)
                continue
            # decrypt users & passwords                
            uname.data  = cast(c_char_p(base64.b64decode(row["encryptedUsername"])),c_void_p)
            uname.len = len(base64.b64decode(row["encryptedUsername"]))
            passwd.data = cast(c_char_p(base64.b64decode(row["encryptedPassword"])),c_void_p)
            passwd.len=len(base64.b64decode(row["encryptedPassword"]))
            if self.libnss.PK11SDR_Decrypt(byref(uname),byref(dectext), 0)==-1:
                raise Exception('Username decrypt exception with:' + str(row))
            row["encryptedUsername"] = string_at(dectext.data,dectext.len)
            if self.libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext), 0)==-1:
                raise Exception('Password decrypt exception with:' + str(row))
            row["encryptedPassword"] = string_at(dectext.data, dectext.len)
            r.append(row)
        self.libnss.NSS_Shutdown()
        conn.close()
        return r

    def get_cookies(self):
        db_path = '/'.join((self.profile_path, 'cookies.sqlite'))
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        r = c.execute('SELECT baseDomain, appId, inBrowserElement, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly FROM moz_cookies;').fetchall()
        conn.close()
        return r

    def get_history(self):
        history_path = '/'.join((self.profile_path, 'places.sqlite'))
        conn = sqlite3.connect(history_path)
        c = conn.cursor()
        r = c.execute("select url, datetime(visit_date/1000000, 'unixepoch') from moz_places, moz_historyvisits where visit_count > 0 and moz_places.id==moz_historyvisits.place_id;")
        conn.close()
        return r

    '''def get_downloads(self):
        conn = sqlite3.connect()
        c = conn.cursor()
        c.execute("SELECT name, source, datetime(endTime/1000000,'unixepoch') FROM moz_downloads;")
        print '\n[*] - Files Downloaded - '
        for row in c:
            print '[+] File: ' + str(row[0]) + ' from source: ' + str(row[1]) + ' at: ' + str(row[2])'''

if __name__ == '__main__':
    profile = raw_input("Profile path: ")
    try:
        ff = Firefox_manager(profile)
        print "\n[[  OK  ]] - Firefox Manager succesfully loaded!\n"
    except Exception as e:
        print "[[ FAIL ]] - " + str(e)
        exit(-1)

    print '[[  OK  ]] - Testing blank master password: ', ff.test_master_password('')
    try:
        passwords = ff.get_saved_passwords(masterpass = "")
        print ''
        for p in passwords:
            print "   " + p["encryptedUsername"] + " : " + p["encryptedPassword"] + "\t\t" + p["hostname"]
    except Exception as e:
        print "[[ FAIL ]] - " + str(e)

    history = ff.get_history()
    cookies = ff.get_cookies()
    #downloads = ff.get_downloads()

    print '\n\tCookies: [ ' + str(len(cookies)) + ' ]\n'
    cks = raw_input('Show cookies?[y/N]: ')
    if cks == 'y' or cks == 'Y':
        for c in cookies:
            print "\n\tHost:\t" + c[5]
            print "\tName:\t" + c[3]
            print "\tExpire:\t" + str(c[7]/1000)
            print "\tSecure:\t" + str((c[10]!=0))
            print "\tHTTPonly:\t" + str((c[11]!=0))
