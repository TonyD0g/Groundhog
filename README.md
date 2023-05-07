# Groundhog [Java8]

土拨鼠，一款高随机性的Mysql蜜罐

使用java8开发,**一次编写,到处撒野**



# 特性

```md
1.实现随机salt
2.随机ThreadId,且ThreadId增长随机,开启蜜罐后会一直记住ThreadId(单例模式实现)	
3.增加Mysql拉黑机制：如果连接错误的次数超过了"max_connect_errors"设置的次数，则该IP地址会被拉黑，直到MySQL服务器重启或者超过"connect_timeout"设置的时间段。
4.增加登录验证识别,不会把任意输入的用户名以及密码当成正确的。
5.自动随机选择mysql版本。
```



# TODO

- 增加操作日志

- 设置connect_timeout
- 重启刷新blockIp.txt
- 成功欺骗扫描器
