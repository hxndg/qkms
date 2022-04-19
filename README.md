Open source qbue kms write in go.

## kube kms
魔方kms，使用go开源的kms系统，由于没有HSM，因此使用服务器上的证书私钥做密钥派生拿到数据库的rootkey，服务器的安全性依靠这张证书私钥来保证。

## 目前支持的功能
+ 用户管理：使用 grpc 的 tls 双向认证做权限控制，每张 CA 签发出来的证书对应一个用户，每个用户证书里面的 subject 需要有不同的 appkey 内容。用户创建 ak 后可以授权给其它用户读取或者更新，初始化时如果没有创建root用户，那么需要输入一个appkey，这个appkey对应的用户会被授予root权限。root用户可以执行任何操作。规范用法的情况下，只允许root用户颁发证书。
+ 密钥管理：密钥三层拆封，rootkey ===> key encryption key ===> access key.用户需要先申请创建key encryption key，即创建namespace。之后即可在该namespace下创建对应的accesskey。对用户而言，kek是透明的，
+ 密钥可见性：用户可见的为Access key，按照namespace, name索引。创建密钥后默认只有用户可读可写，如果用户授权给其他用户相应的读/写权限，其他用户可以执行相应的操作。


## 待完成功能
+ kek轮转，定期更新所管理的access key
+ kms管理员，用户，维护者身份区别，目前没有特意区分管理员等账户信息
+ 账户信息需要记录到数据库当中。

## 依赖
+ 使用 postgresql 做数据持久化
+ 使用 grpc 的双向 tls 做认证

[![qLzGr9.jpg](https://s1.ax1x.com/2022/04/05/qLzGr9.jpg)](https://imgtu.com/i/qLzGr9)
