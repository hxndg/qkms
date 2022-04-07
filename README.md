Open source qbue kms write in go.

## 目前支持的功能
+ 用户可见的为Access key，按照namespace, name索引。创建密钥后默认只有用户可读可写，如果用户授权给第三方，那么第三方可读（第三方需要拥有相应的证书）
+ 密钥三层拆封，rootkey ===> key encryption key ===> access key.用户需要先申请创建key encryption key，即创建namespace。之后即可在该namespace下创建对应的accesskey
+ 使用 grpc 的 tls 双向认证做权限控制，每张 CA 签发出来的证书是一个用户，每个用户证书里面的 subject 需要有不同的 appkey 内容。用户创建 ak 后可以授权给其它用户读取或者更新

## 待完成功能
+ kek轮转，定期更新所管理的access key
+ kms管理员，用户，维护者身份区别，目前没有特意区分管理员等账户信息
+ 账户信息需要记录到数据库当中。

## 依赖
+ 使用 postgresql 做数据持久化
+ 使用 grpc 的双向 tls 做认证

[![qLzGr9.jpg](https://s1.ax1x.com/2022/04/05/qLzGr9.jpg)](https://imgtu.com/i/qLzGr9)
