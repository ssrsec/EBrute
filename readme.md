利用 Exchange 服务器 Web 接口爆破邮箱账户

参考 [grayddq/EBurst](https://github.com/grayddq/EBurst) 项目使用python3重构

### 使用说明
```angular2html
python3 EBrute.py -h  
```
```                                                           
usage: EBrute.py [-h] -s <check/brute> -d domain [-m name] [-u user.txt] [-p pass.txt] [--ssl <y/n>] [--timeout 10] [--thread 30]

exchange接口爆破

+--------------+---------------------------------------------------------------------------------------------+
| 接口         | 说明                                                                                        |
+==============+=============================================================================================+
| autodiscover | 默认NTLM认证方式，2007版本推出，用于自动配置用户在Outlook中邮箱的相关设置                   |
+--------------+---------------------------------------------------------------------------------------------+
| ews          | 默认NTLM认证方式，Exchange Web Service,实现客户端与服务端之间基于HTTP的SOAP交互             |
+--------------+---------------------------------------------------------------------------------------------+
| mapi         | 默认NTLM认证方式，Outlook连接Exchange的默认方式，在2013和2013之后开始使用，2010 sp2同样支持 |
+--------------+---------------------------------------------------------------------------------------------+
| activesync   | 默认Basic认证方式，用于移动应用程序访问电子邮件                                             |
+--------------+---------------------------------------------------------------------------------------------+
| oab          | 默认NTLM认证方式，用于为Outlook客户端提供地址簿的副本，减轻Exchange的负担                   |
+--------------+---------------------------------------------------------------------------------------------+
| rpc          | 默认NTLM认证方式，早期的Outlook还使用称为Outlook Anywhere的RPC交互                          |
+--------------+---------------------------------------------------------------------------------------------+
| api          | 默认NTLM认证方式                                                                            |
+--------------+---------------------------------------------------------------------------------------------+
| owa          | 默认http认证方式，Exchange owa 接口，用于通过web应用程序访问邮件、日历、任务和联系人等      |
+--------------+---------------------------------------------------------------------------------------------+
| ecp          | 默认http认证方式，Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台               |
+--------------+---------------------------------------------------------------------------------------------+

optional arguments:
  -h, --help        show this help message and exit
  -s <check/brute>  选择模式，检查接口或者爆破
  -d domain         邮箱域名
  -m name           爆破接口，可单选[autodiscover,ews,mapi,activesync,oab,rpc,api,owa,ecp]
  -u user.txt       用户名字段
  -p pass.txt       密码字段
  --ssl <y/n>       是否启用https，默认启用
  --timeout 10      超时等待时间，默认10秒
  --thread 30       线程数量，默认30线程

Example usage:
[检查可用接口] python3 EBrute.py -s check -d example.com
[指定接口爆破] python3 EBrute.py -s brute -d example.com -m rpc -u user.txt -p pass.txt
```