# -*- coding: utf-8 -*-
import os
import threading
import logging
import logging.handlers
import time
import md5
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5

class GlobalData():
    accumulator_file = '.usagecfg'
    ward_target = 'certi.box'
    factory_log = 'factory.log'
    exit_flag = False
    app_release_flag = False
    mainproc_threads_mutex = None
    dual_notes = 'E:\\.certi'
    
    def __init__(self):
        print 'hello i am GlobalData class'
        pass

    @staticmethod
    def env_init():
        if GlobalData.mainproc_threads_mutex is None:
            GlobalData.mainproc_threads_mutex = threading.Lock()
        is_exist = os.path.exists(GlobalData.dual_notes)
        if is_exist is False:
            with open(GlobalData.dual_notes,'w+') as dual_fs:
                dual_fs.write(' ')
                dual_fs.close()

    @staticmethod
    def logging_basic_cfg_setup():
        if GlobalData.app_release_flag is True:
            logging.basicConfig(filename=GlobalData.factory_log, level=logging.ERROR)
        else:
            logging.basicConfig(level=logging.DEBUG)


class WardThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        certi_exist = os.path.exists(GlobalData.ward_target)
        while certi_exist is True:
            certi_exist = os.path.exists(GlobalData.ward_target)
            if certi_exist is False:
                GlobalData.mainproc_threads_mutex.acquire()
                GlobalData.exit_flag = False
                GlobalData.mainproc_threads_mutex.release()
            time.sleep(0.2)
            logging.debug('loop for Ward...')

        logging.debug('WardThread exit~')



class Accumulator():
    def __init__(self):
        self.priv_key = None
        self.pub_key = None
        self.BS = AES.block_size
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[0:-ord(s[-1])]
        with open ('cust_private.pem') as f:
            key = f.read()
            self.priv_key = RSA.importKey(key)
            f.close()
        with open('cust_public.pem') as f:
            key = f.read()
            self.pub_key = RSA.importKey(key)
            f.close()
        is_exist = os.path.exists(GlobalData.accumulator_file)
        if is_exist is False:
            cipher = Cipher_pkcs1_v1_5.new(self.pub_key)
            cipher_text = cipher.encrypt(self.pad('0'.encode(encoding="utf-8")))
            cipher_file = open(GlobalData.accumulator_file,'wb')
            cipher_file.write(cipher_text)
            cipher_file.close()

            

        logging.debug('Accumulator init done.')
    

    def dldtimes_add(self):
        read_file = open(GlobalData.accumulator_file,'rb')
        orien_text = read_file.read()
        read_file.close()
        cipher = Cipher_pkcs1_v1_5.new(self.priv_key)
        test_text = self.unpad(cipher.decrypt(orien_text,"ERROR"))
        dldtimes = int(test_text)
        if dldtimes > 34:
            return
        dldtimes += 1

        pub_cipher = Cipher_pkcs1_v1_5.new(self.pub_key)
        cipher_text = pub_cipher.encrypt(self.pad(str(dldtimes).encode(encoding="utf-8")))
        cipher_file = open(GlobalData.accumulator_file,'wb')
        cipher_file.write(cipher_text)
        cipher_file.close()

        md5_text = md5.new(cipher_text).hexdigest()
        with open(GlobalData.dual_notes,'w+') as dual_fs:
            dual_fs.write(md5_text)
            dual_fs.close()
        
        # f = open(GlobalData.accumulator_file,'rb')
        # compare_val = md5.new(f.read()).hexdigest()
        # f.close()
        # print 'hi'



if __name__ == '__main__':
    GlobalData.env_init()
    accum_obj = Accumulator()
    accum_obj.dldtimes_add()
    # GlobalData.logging_basic_cfg_setup()
    # ward_ins = WardThread()
    # ward_ins.start()
    # ward_ins.join()
    # print 'main over!'

    # accum = Accumulator()
    # accum.dldtimes_add()