Open source qbue kms write in go.

## kube kms
魔方kms，使用go开源的kms系统，由于没有HSM，因此使用服务器上的证书私钥做密钥派生拿到数据库的rootkey，服务器的安全性依靠这张证书私钥来保证。

## 目前支持的功能
+ 用户管理：使用 grpc 的 tls 双向认证做权限控制，每张 CA 签发出来的证书对应一个用户，每个用户证书里面的 subject 需要有不同的 appkey 内容。初始化时如果没有创建root用户，会要求输入root user的name，然后生成root user的证书和私钥。后续对第三方用户签发证书私钥可以由root user进行管理。root user拥有一切权限，root user可以创建其他角色；查看ak；吊销用户证书等功能。
+ 密钥管理：密钥三层拆封，rootkey ===> key encryption key ===> access key.用户需要先申请创建namespace（kek也会创建，是透明的）。之后即可在该namespace下创建对应的accesskey。对用户而言，kek是透明的
+ 密钥可见性：用户可见的为Access key，按照namespace, name索引。创建密钥后默认只有用户可读可写，如果用户授权给其他用户相应的读/写权限，其他用户可以执行相应的操作。
+ KEK自动轮转，KEK的本身只会新建，不会更新已有的内容，每次本质都是将namespace对应的KEK新建，并且指定namespace使用该新建KEK。
+ Access key自动轮转，Access Key自动轮转是在特定时刻生成新的内容，并读取当前namespace对应的KEK，使用该新建KEK加密存储。
+ 角色管理：可以将namespace的read/wirte权限赋予给某个role，再将某个role赋予给相对应的用户（用户使用appkey区分），从而用户可以作为某个namespace下面的mainter。


+ 自动轮转：


## 待完成功能
+ kek轮转，定期更新所管理的access key

## 依赖
+ 使用 postgresql 做数据持久化
+ 使用 grpc 的双向 tls 做认证
+ 依赖 casbin做rbac的管理

## 测试方法
grpcurl或者grpcui
只列出grpcui的命令
```
grpcui -cert .\credentials\client\client.pem.example -key .\credentials\client/client.key.example -insecure 127.0.0.1:8000
```

## 一些快捷命令
生成proto文件
```
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/qkms.proto
```

启动命令
```
go run .\server\server.go --logtostderr
```

[![qLzGr9.jpg](https://s1.ax1x.com/2022/04/05/qLzGr9.jpg)](https://imgtu.com/i/qLzGr9)
