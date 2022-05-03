Open source qbue kms write in go.

## kube kms
魔方kms，使用go开源的kms系统，由于没有HSM，因此使用服务器上的证书私钥做密钥派生拿到数据库的rootkey，服务器的安全性依靠这张证书私钥来保证。

## 目前支持的功能
+ 用户管理：使用 grpc 的 tls 双向认证做权限控制，每张 CA 签发出来的证书对应一个用户，每个用户证书里面的 subject 需要有不同的 appkey 内容。初始化时如果没有创建root用户，会要求输入root user的name，然后生成root user的证书和私钥。后续对第三方用户签发证书私钥可以由root user进行管理。root user拥有一切权限，root user可以创建其他角色；查看ak；吊销用户证书等功能。
+ 角色管理：可以将namespace的read/wirte权限赋予给某个role，再将某个role赋予给相对应的用户（用户使用appkey区分），从而用户可以作为某个namespace下面的mainter。
+ 密钥管理：密钥三层拆封，rootkey ===> key encryption key ===> access key.用户需要先申请创建key encryption key，即创建namespace。之后即可在该namespace下创建对应的accesskey。对用户而言，kek是透明的，
+ 密钥可见性：用户可见的为Access key，按照namespace, name索引。创建密钥后默认只有用户可读可写，如果用户授权给其他用户相应的读/写权限，其他用户可以执行相应的操作。


## 待完成功能
+ kek轮转，定期更新所管理的access key

## 依赖
+ 使用 postgresql 做数据持久化
+ 使用 grpc 的双向 tls 做认证
+ 依赖 casbin做rbac的管理

[![qLzGr9.jpg](https://s1.ax1x.com/2022/04/05/qLzGr9.jpg)](https://imgtu.com/i/qLzGr9)
