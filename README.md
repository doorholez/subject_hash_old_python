# Introduction
To add a root CA certificate, the certificate should be:  
1. saved as PEM format
2. given a specific name, derived by hashing the subject's distinguished name
3. copied to path `/system/etc/security/cacerts`  

The point 2 can be achieved using `openssl`, but it is unnecessary to install the whole `openssl` only using it to produce the hash name of the certificate. So I did it with Python without any dependency just for fun.

# 简介
手动给安卓系统安装证书需要满足以下三个条件：
1. 证书是PEM格式
2. 证书的名字是一个特定的名字，由证书的subject name字段的哈希值衍生而来
3. 将命名好的证书复制到安卓系统的`/system/etc/security/cacerts`路径下

第二点一般是由`openssl`实现，但是仅仅为了重命名证书就安装一个`openssl`有些没有必要，所以我将这一步写成了Python脚本。

# Usage
Just paste the complete certificate content or the certificate path and press Enter, the name of the certificate will be printed :)

# 用法
把证书的完整内容或者证书的路径粘贴进来并按下回车，证书需要被重命名的名字就会被显示出来 :)

---
If you find a case that it doesn't work, create an issue or add the certificate to the `test_certs` directory with a pull request.  
如果有和预期不符的情况，请在issue提出或者将出问题的证书添加到`test_certs`文件夹并pull request。