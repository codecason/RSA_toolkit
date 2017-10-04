# -*- coding:utf-8 -*-
import sys, random, pickle
import math
import PyQt4
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
import rsa_method
from rsa_method import RSAMethod, RSAKey
import os, json, hashlib

class MyWindow(QWidget):
    '''自定义窗口类'''
    rsaclass = RSAKey()
    rsa = RSAMethod()
    def __init__(self, parent=None):
        def addBorder(obj):
            obj.setStyleSheet("border:1px solid rgb(0, 255, 0); ")
        def setLabel(label):
            label.setFrameStyle(QFrame.StyledPanel|QFrame.Sunken)

        '''构造函数'''

        super(MyWindow, self).__init__(parent)
        self.setFixedSize(QSize(800, 480))
        # No setTitle?     to be modified.
        self.bodyWideget = QWidget(self)

        self.pri_label = QLabel("PRIVATE KEY")
        self.pub_label = QLabel("PUBLIE KEY")
        self.pri_row = QLineEdit()
        self.pub_row = QLineEdit()
        # 设置公钥和私钥的值
        n, e, d, p, q = self.rsaclass.getKey()
        self.pub_row.setText(repr(n) + "," + repr(e))
        self.pri_row.setText(repr(n) + "," + repr(d))
        # 设置布局
        self.grid = QGridLayout()
        self.subgrid = QGridLayout()
        self.textgrid = QGridLayout()

        #3个按钮的设置
        self.en_button = MyButton(self)
        self.en_button.setText(u"加密")
        # self.en_button.move(250, 20)
        self.en_button.clicked.connect(self.en_clicked)
        self.de_button = MyButton(self)
        self.de_button.setText(u"解密")
        # self.de_button.move(400, 20)
        self.de_button.clicked.connect(self.de_clicked)
        self.ge_button = MyButton(self)
        self.ge_button.setFixedSize(100, 30)
        self.ge_button.setText(u"产生新的密钥")
        self.ge_button.clicked.connect(self.generate)
        QObject.connect(self.de_button, SIGNAL("de_clicked()"), self.de_clicked)

        self.subgrid.addWidget(self.pri_label, 0, 0)
        self.subgrid.addWidget(self.pri_row, 0, 1)
        self.subgrid.addWidget(self.pub_label, 1, 0)
        self.subgrid.addWidget(self.pub_row, 1, 1)
        self.subgrid.addWidget(self.ge_button, 2, 1, Qt.AlignRight)
        self.grid.addLayout(self.subgrid, 0, 0, 1, 8)

        # text and encrypt text
        self.in_label = QLabel("plain_text")
        self.out_label = QLabel("encrypt_text")
        self.in_row = QTextEdit()
        self.out_row = QTextEdit()
        self.in_row.setText(u"你好,这里是RSA样例演示")
        addBorder(self.in_row)
        addBorder(self.out_row)
        # self input and output
        width = 5
        self.textgrid.addWidget(self.in_label, 0, 0, 1, width)
        self.textgrid.addWidget(self.in_row, 1, 0, 1, width)
        self.textgrid.addWidget(self.out_label, 2, 0, 1, width)
        self.textgrid.addWidget(self.out_row, 3, 0, 1, width)
        self.textgrid.addWidget(self.en_button, 4, 3, 1, 1, Qt.AlignRight)
        self.textgrid.addWidget(self.de_button, 4, 4, 1, 1, Qt.AlignLeft)
        self.grid.addLayout(self.textgrid, 1, 0, 4, width)

        # select : export file, signature, key
        self.right_grid = QGridLayout()
        self.filegrid = QVBoxLayout()

        # self.export_label = QLabel("EXPORT OPTIONS")
        # addBorder(self.export_label)
        self.options = QComboBox(self)
        self.options.addItems(['Export text', 'Export key', 'Export signature(SHA512)'])

        # qframe = QFrame()
        self.outfname = QLineEdit(self)
        self.outfname.setText('dump_file.json')
        # export button
        exportbtn = QToolButton()
        exportbtn.setText("Export to")
        QObject.connect(exportbtn, SIGNAL("clicked()"), self.export)
        # self.filegrid.addWidget(self.export_label)
        self.filegrid.addWidget(self.options)
        self.filegrid.addWidget(exportbtn)
        self.filegrid.addWidget(self.outfname)
        self.right_grid.addLayout(self.filegrid, 0, 0)

        # filedialog open/pop up
        label, self.fpath, filebtn = QLabel("Load File"), QLineEdit(), QToolButton()
        filebtn.setText("...")
        filebtn.clicked.connect(self.openFile)

        self.filegrid2 = QHBoxLayout()
        self.filegrid2.addWidget(label)
        self.filegrid2.addWidget(self.fpath)
        self.filegrid2.addWidget(filebtn)
        self.right_grid.addLayout(self.filegrid2, 1, 0)
        ## Load key, save key, use key
        self.grid.addLayout(self.right_grid, 1, 5, 8, 3)
        self.setLayout(self.grid)


    def usekey(self, usetype, **kwargs):
        def loadkey():
            def testKeyValid(n, e, d, p, q):
                if p * q != n or p <= 1 or q <= 1:
                    return False
                phi = (p - 1) * (q - 1)
                if e * d % phi != 1:
                    return False
                return True

            filename = QFileDialog().getOpenFileName(self)
            print 'load key in usekey'
            if filename == None or filename == '':
                self.popInfo("No select files!")
                return
            try:
                #Read file-> test valid -> set UI -> use a new rsaclass
                handle = open(filename, 'r')
                keys = json.load(handle)
                n = long(keys["pub_key"][0])
                e = long(keys["pub_key"][1])
                d = long(keys["priv_key"][1])
                p, q = long(keys["p"]), long(keys["q"])
                valid = testKeyValid(n, e, d, p, q)
                if not valid:
                    self.popInfo("Load key invalid!")
                    return
                # unicode: u'11L' -> str '11L'
                self.pub_row.setText(str(n) + "," + str(e))
                self.pri_row.setText(str(n) + "," + str(d))
                self.rsaclass.setKey(n, e, d, p, q)
                self.popInfo("Load key success!")
            except BaseException as e:
                self.popInfo("Load key failed!" + repr(e))

        def savekey(filename, data):
            try:
                self.rsaclass.dumps(filename, data)
            except Exception as e:
                print e

        if usetype == 'load':
            print 'load enter...'
            loadkey()
        else:
            print 'usekey'

    # file encryption
    def encrypt(self, usetype):
        # encrypt window text, file text
        if usetype == None or (usetype != 1 and usetype != 2):
            return None
        if usetype == 1:
            ## TO DO
            print 'encrypt text'
        else:
            text = self.filedata
            filename, res = self.fpath.text(), ''
            if text != None:
                pass
                ## TO DO
                # res, overflow = encryptfile(groups)
            elif filename != None and filename != '':
                pass
            return res

    # openFile -> 新的函数: encrypt 1 (window), encrypt 2 (file)
    def openFile(self):
        openfile = QFileDialog.getOpenFileName(self)
        if openfile != None and openfile != '':
            self.fpath.setText(openfile)
            with open(openfile, 'r') as f:
                self.filedata = f.read()
                print self.filedata
            self.in_row.setText(self.filedata.decode('utf-8'))
            print 'filename is', openfile
        else:
            self.popInfo('Not choose file')
        # msg = QMessageBox()
        # msg.setWindowTitle("close test")
        # msg.setEscapeButton(QMessageBox.Ok)

    def export(self):
        def to_file(data, fname):
            try:
                with open(fname, 'w') as f:
                    f.write(data)
            except BaseException as e:
                print e

        def export_text():
            text = str(self.out_row.toPlainText())
            data = {"text": text}
            fname = self.outfname.text()
            data = json.dumps(data, skipkeys=True)
            to_file(data, fname)

        def export_key():
            keys = {}
            n, e, d, p, q = self.rsaclass.getKey()
            keys['priv_key'], keys['pub_key'] = [n, d], [n, e]
            keys['p'], keys['q'] = str(p), str(q)
            keysrepr = json.dumps(keys, skipkeys=True)
            fname = self.outfname.text()
            to_file(keysrepr, fname)

        def sha_signature():
            fname = self.outfname.text()
            text = str(self.in_row.toPlainText().toUtf8())
            hashtext = b64encode(self.rsaclass.rsa_encode(hashlib.sha512(text).hexdigest()))
            data = {"message": text, "signature": hashtext, "pub_key": self.rsaclass.getKey()[0:2]}
            signature = json.dumps(data, skipkeys=True, ensure_ascii=False)
            to_file(signature, fname)

        usetype = str(self.options.currentText())
        if usetype == 'Export text':
            print 'export' * 10
            export_text()
        elif usetype == 'Export key':
            print 'export2' * 10
            export_key()
        elif usetype == 'Export signature(SHA512)':
            print 'export3' * 10
            sha_signature()
        else:
            return

    def popInfo(self, infos):
        pop = QMessageBox(self)
        pop.setIcon(QMessageBox.Warning)
        pop.setWindowTitle("info")
        pop.setText(infos)
        pop.exec_()

    def en_clicked(self):
        plaintext = self.in_row.toPlainText()
        print repr(plaintext)
        if plaintext != None:
            encryptext = self.rsaclass.rsa_encode(plaintext.toUtf8())
            # encryptext = repr(encryptext)
            # encryptext = b64encode(encryptext)
            # encryptext = repr(encryptext)
            # self.out_row.setText(encryptext + " heheda " + encryptext1)
            self.out_row.setText(b64encode(encryptext))
        else:
            return

    def de_clicked(self):
        encryptext = self.out_row.toPlainText() # TO be modified
        if (encryptext != None):
            encryptbytes = b64decode(encryptext)
            plaintext = self.rsaclass.rsa_decode(encryptbytes)
            self.in_row.setText(plaintext)
        else:
            return

    def generate(self):
        keys = self.rsaclass.gen_keys("")
        self.pri_row.setText(repr(keys["pub_key"])[1:-1])
        self.pub_row.setText(repr(keys["priv_key"])[1:-1])

#is this uesful?
    def Onclick(self):
        QMessageBox.about(self, 'hello world')



class MyButton(QToolButton):
    '''自定义按钮'''
    def __init__(self, parent = None):
        super(MyButton, self).__init__(parent)
        self.setFixedSize(QSize(50, 30))
        self.setStyleSheet('''background-color:#DFE2DB;border:2px solid;font-size:5;''')


class WholeWindow(QMainWindow):
    def __init__(self, parent = None):
        super(WholeWindow, self).__init__(parent)
        mywindow = MyWindow()
        # add menus
        self.setWindowTitle("RSA toolkit")
        stdicon = self.style().standardIcon
        self.setWindowIcon(stdicon(QStyle.SP_BrowserReload))

        tb = self.menuBar()
        loadKeyAction = QAction("Load Key", self)
        QObject.connect(loadKeyAction, SIGNAL("triggered()"), \
            lambda usetype='load': mywindow.usekey(usetype))
        fm = tb.addMenu("Keys")
        fm.addAction(loadKeyAction)

        hpAction = QAction("About", self)
        hp = tb.addMenu("Help")
        hp.addAction(hpAction)
        QObject.connect(hpAction, SIGNAL("triggered()"), self.hpshow)

        #  bind events
        # fm.triggered[QAction].connect(self.fileaction)
        self.setCentralWidget(mywindow)

    def hpshow(self):
        text = \
        '  @RSA tool\n' \
        '  @Copy Right 2016\n' \
        '           --By CodeCason\n' \
        ' The function of the RSA tool is:\n' \
        ' 1. Export and load RSA keys(including priv_key and pub_key);\n' \
        ' 2. Encrypt text/file with e of pub_key and decrypt with d of priv_key;\n' \
        ' 3. Create new RSA keys;\n' \
        ' 4. Create signature in SHA512 for the message;\n' \
        '\n' \
        ' The key file(like rsa_keys.json) should have the key-values:\n' \
        '   q, p, priv_key, pub_key \n' \
        '\n' \
        ' The loaded files, signatures and keys should be in utf-8 or they only contain ascii codes.'
        pop = QMessageBox()
        pop.setWindowTitle("About")
        pop.setText(text)
        pop.exec_()

# https://pythonspot.com/en/pyqt4-gui-tutorial/ ui的反向代码
def main():
    app = QApplication(sys.argv)
    widget = WholeWindow()
    widget.show()
    sys.exit(app.exec_())

########################################################
#Encode:
#QString->utf8str->hex->formatted int->str bytes->base64

########################################################
if __name__ == '__main__':
    main()
