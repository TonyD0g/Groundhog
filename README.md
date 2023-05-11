# Groundhog [Java8]

土拨鼠，一款高随机性的Mysql蜜罐

使用java8开发,**一次编写,到处撒野**

**已发布demo版本**



# 猜想

```md
我认为蜜罐按功能可以分为三种 
1.主要是拖延攻击者攻击时间的.即使用真实环境去搭建,但这个环境是被隔离的
2.主要是反制攻击者的.即重保期间希望获取攻击者的身份信息,从而对攻击者进行溯源反制,不计代价的获取身份信息,意味着容易暴露
3.前两种结合的,两种优缺点平衡

Groundhog只是第二种类型,且由于mysql蜜罐使用的Load data local infile请求,也就是说这个蜜罐通常只有一次攻击方式.(毕竟没有攻击者傻到连接第二次吧?)
所以我们应该探讨的是,如果你只有一次任意文件读取的机会,那如何将这次作用发挥到极致呢

又或者我们不必要使用蜜罐去埋雷等着引爆,我们也可以将mysql蜜罐作为一个信号
对不需要开启mysql端口的内网客户端都布置上mysql蜜罐,如果某一台内网客户端的mysql蜜罐被触发了,意味着内网可能已经失陷.
```



# 特性

```md
1.实现随机salt
2.随机ThreadId,且ThreadId增长随机,开启蜜罐后会一直记住ThreadId(单例模式实现)	
3.增加Mysql拉黑机制：如果连接错误的次数超过了"max_connect_errors"设置的次数，则该IP地址会被拉黑，直到MySQL服务器重启或者超过"connect_timeout"设置的时间段。
4.增加登录验证识别,不会把任意输入的用户名以及密码当成正确的。
5.自动随机选择mysql版本。
6.增加操作日志
7.动态读取wantReanList.txt,随机选一个读取
8.重启或超过connect_timeout会刷新blockIp.txt
9.服务端获取路径时,如果文件不存在,会输出不存在文件的提示
```



# 使用说明

```md
blockIpList.txt: 
记录被mysql蜜罐拉黑的ip,用于模拟真实mysql

correctUserInfo.txt: 
预设的账号密码,你可以填入弱口令进去,只有客户端发来的账号密码正确才给连(我已禁止空密码)

wantReadList.txt:
蜜罐想要读取的文件路径,你可以填入路径,会随机选择一个进行读取

如果读取文件成功,会生成getData文件夹,并保存在getData文件夹中

LFI文件下是常用的文件读取路径,自己发现具有实际价值的,可用于溯源的路径吧

如果蜜罐日志中记录出现大量的同一ip连接蜜罐,但却没有获取文件成功/失败的提示,那么这个ip使用了蜜罐扫描器,大概率红队人员.
	
快速使用:
服务端:
1.打开correctUserInfo.txt,填入预设账号密码,以空格隔开,如root root
2.打开wantReadList.txt,填入想要读取的路径
3.开启Groundhog: java -jar Groundhog.jar

客户端:
Navicat或cmd命令行输入:
.\mysql -h 127.0.0.1 -u root -p --ssl-mode=DISABLED
```

# 对抗

#### 1.与蜜罐识别器([检测目标Mysql数据库是不是蜜罐](https://github.com/BeichenDream/WhetherMysqlSham))对抗：

**(只是未连接前的对抗,因为mysql蜜罐的特殊性,连上只要输入命令就暴露了,所以只有一次攻击机会)**

![1](/Pic/1.jpg)



#### 随机salt:

![2](/Pic/2.jpg)

#### 随机ThreadId和随机增长

![](/Pic/3.jpg)



#### 2.各类扫描器扫描结果

- 不能直接利用,能扫出来是mysql,但需要使用cmd/Navicat连接才能利用:

  -  kscan1.85

  - Ladon911

  - Yasso

  - fscan

    等一众端口扫描器,只扫端口不爆破

- 可以直接利用,扫描器只要扫描了就中招:

  - SNETCracker1.0 (需要关闭蜜罐的密码验证,否则不成功)

- 爆破端口，但依旧无法利用

  - PortBruteWin

# TODO

- 支持大文件传输



# 学习来源

[Mysql蜜罐反制Cobalt Strike - 先知社区](https://xz.aliyun.com/t/11631)

[溯源反制之MySQL蜜罐研究](https://mp.weixin.qq.com/s?__biz=MzAwMzYxNzc1OA==&mid=2247490831&idx=1&sn=4cf03a7f8e8415867cd15c25e43a177e&scene=21#wechat_redirect)

[浅谈Mysql蜜罐识别 ](https://mp.weixin.qq.com/s/f30RvhYlB97dXnjzv4_H_Q)

[GitHub - BeichenDream/WhetherMysqlSham: 检测目标Mysql数据库是不是蜜罐](https://github.com/BeichenDream/WhetherMysqlSham)

[MySQL 是怎样通讯的？ - 掘金](https://juejin.cn/post/7079972884029898766#heading-5)

[从一道CTF题目看Gopher攻击MySql - FreeBuf网络安全行业门户](https://www.freebuf.com/news/159342.html)

[MySQL参数max_connect_errors分析释疑 - 潇湘隐者 - 博客园](https://www.cnblogs.com/kerrycode/p/8405862.html)

[51ak带你看MYSQL5.7源码1：main入口函数 - 51ak - 博客园](https://www.cnblogs.com/wokofo/articles/8624538.html)

