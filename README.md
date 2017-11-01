程序语言：Pthon2.7
需要安装：PyQt 4.8.7x32（32位python）到python安装目录的Lib\site-packages下，并在代码中import PyQt4
### 运行方式:
    没有装python的windows系统不能直接运行该程序，所以已经通过pyinstaller打包，但是还有一个文件夹dist,可以直接在windows下运行RSA_main.exe。
	要打包该代码，使用pyinstaller -w <your_file.py>

### 运行说明：
1. 运行RSA py.py，加密成base64字符串,数字p,q的长度是800bit，n为1600bit, 实现流式的分组加密。
	2. Export to可以导出加密文本、签名、密钥
	3. Keys-> Load Key可以加载密钥
	4. 可以产生新的密钥

**产生一个密钥需要花较多的时间（可能数秒到几分钟）。**