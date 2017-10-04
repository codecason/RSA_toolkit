# -*- coding: utf-8 -*-

from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys

class tooldemo(QMainWindow):
    def __init__(self, parent=None):
        super(tooldemo, self).__init__(parent)
        bar=self.menuBar()
        # menubar/menu/action menu+action->trigger
        file=bar.addMenu("File")
        file.addAction("show")
        file.addAction("add")
        file.addAction("remove")
        file.triggered[QAction].connect(self.processtrigger)
        helpmenu = bar.addMenu("help")
        self.setCentralWidget(QTextEdit())
        self.statusBar= QStatusBar()
        self.b=QPushButton("click here")
        self.setWindowTitle("QStatusBar Example")
        self.setStatusBar(self.statusBar)

    def processtrigger(self,q):
        if (q.text()=="show"):
            self.statusBar.showMessage(q.text()+" is clicked",2000)
        if q.text()=="add":
            self.statusBar.addWidget(self.b)
        if q.text() == "remove":
            self.statusBar.removeWidget(self.b)

class myListWidget(QListWidget):
    def Clicked(self,item):
        QMessageBox.information(self, "ListWidget", "You clicked: "+item.text())

def toolrun():
    app = QApplication(sys.argv)
    listWidget = myListWidget()
#Resize width and height
    listWidget.resize(300,120) 
    listWidget.addItem("Item 1");
    listWidget.addItem("Item 2");
    listWidget.addItem("Item 3");
    listWidget.addItem("Item 4");
    listWidget.setWindowTitle('PyQT QListwidget Demo')
    listWidget.itemClicked.connect(listWidget.Clicked)
    listWidget.show() 
    sys.exit(app.exec_())
