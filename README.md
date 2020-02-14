# SpringBoot_JWT
 springboot整合jwt实现token登录验证

**博客地址：** https://blog.csdn.net/ljlj8888/article/details/104168218

**JWT官网： [https://jwt.io/](https://links.jianshu.com/go?to=https%3A%2F%2Fjwt.io%2F)**

## 什么是JWT

**Json web token (JWT)**, 是为了在网络应用环境间传递声明而执行的一种基于`JSON`的开放标准（(RFC 7519).**定义了一种简洁的，自包含的方法用于通信双方之间以`JSON`对象的形式安全的传递信息。**因为数字签名的存在，这些信息是可信的，**JWT可以使用`HMAC`算法或者是`RSA`的公私秘钥对进行签名。**

### JWT请求流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200204125650853.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2xqbGo4ODg4,size_16,color_FFFFFF,t_70)

**1. 用户使用账号和面发出post请求；**
 **2. 服务器使用私钥创建一个jwt；**
 **3. 服务器返回这个jwt给浏览器；**
 **4. 浏览器将该jwt串在请求头中像服务器发送请求；**
 **5. 服务器验证该jwt；**
 **6. 返回响应的资源给浏览器。**

## JWT的主要应用场景

身份认证在这种场景下，一旦用户完成了登陆，在接下来的每个请求中包含JWT，**可以用来验证用户身份以及对路由，服务和资源的访问权限进行验证。**由于它的开销非常小，可以轻松的在不同域名的系统中传递，所有目前在**单点登录（SSO）**中比较广泛的使用了该技术。 信息交换在通信的双方之间使用JWT对数据进行编码是一种非常安全的方式，**由于它的信息是经过签名的，可以确保发送者发送的信息是没有经过伪造的。**

### 优点

**1.简洁(Compact): 可以通过`URL`，`POST`参数或者在`HTTP header`发送，因为数据量小，传输速度也很快
 2.自包含(Self-contained)：负载中包含了所有用户所需要的信息，避免了多次查询数据库
 3.因为`Token`是以`JSON`加密的形式保存在客户端的，所以`JWT`是跨语言的，原则上任何web形式都支持。
 4.不需要在服务端保存会话信息，特别适用于分布式微服务。**

`

## JWT的结构

**JWT是由三段信息构成的，将这三段信息文本用`.`连接一起就构成了JWT字符串。**
 就像这样:
 `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`

**JWT包含了三部分：
 Header 头部(标题包含了令牌的元数据，并且包含签名和/或加密算法的类型)
 Payload 负载 (类似于飞机上承载的物品)
 Signature 签名/签证**

#### 1）Header

**JWT的头部承载两部分信息：token类型和采用的加密算法。**



```json
{ 
  "alg": "HS256",
   "typ": "JWT"
} 
```

**声明类型:这里是jwt
声明加密的算法:通常直接使用 HMAC SHA256**

**加密算法是单向函数散列算法，常见的有MD5、SHA、HAMC。**
 **MD5(message-digest algorithm 5)** （信息-摘要算法）缩写，广泛用于加密和解密技术，常用于文件校验。校验？不管文件多大，经过MD5后都能生成唯一的MD5值
 **SHA (Secure Hash Algorithm，安全散列算法）**，数字签名等密码学应用中重要的工具，安全性高于MD5
 **HMAC (Hash Message Authentication Code)**，散列消息鉴别码，基于密钥的Hash算法的认证协议。用公开函数和密钥产生一个固定长度的值作为认证标识，用这个标识鉴别消息的完整性。常用于接口签名验证

#### 2）Payload

载荷就是存放有效信息的地方。
 **有效信息包含三个部分
 1.标准中注册的声明
 2.公共的声明
 3.私有的声明**

##### 标准中注册的声明 (建议但不强制使用) ：

**`iss`: jwt签发者
 `sub`: 面向的用户(jwt所面向的用户)
 `aud`: 接收jwt的一方
 `exp`: 过期时间戳(jwt的过期时间，这个过期时间必须要大于签发时间)
 `nbf`: 定义在什么时间之前，该jwt都是不可用的.
 `iat`: jwt的签发时间
 `jti`: jwt的唯一身份标识，主要用来作为一次性`token`,从而回避重放攻击。**

##### 公共的声明 ：

**公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.**

##### 私有的声明 ：

**私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为`base64`是对称解密的，意味着该部分信息可以归类为明文信息。**

#### 3）Signature

**jwt的第三部分是一个签证信息**
 **这个部分需要`base64`加密后的`header`和`base64`加密后的`payload`使用`.`连接组成的字符串，然后通过`header`中声明的加密方式进行加盐`secret`组合加密，然后就构成了`jwt`的第三部分。**
 **密钥`secret`是保存在服务端的，服务端会根据这个密钥进行生成`token`和进行验证，所以需要保护好。**



## springboot整合JWT实现token登录验证的简单实现

引入Pom依赖：

```xml
		<!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.9.0</version>
        </dependency>

        <!-- https://mvnrepository.com/artifact/org.json/json -->
        <dependency>
            <groupId>org.json</groupId>
            <artifactId>json</artifactId>
            <version>20190722</version>
        </dependency>
```



在实际的应用中，一般需要一个生成token的工具类和一个拦截器对请求进行拦截。

- token生成工具类
  /utils/TokenUtil.java

```java
package com.ljnt.blog.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ljnt.blog.po.User;

import java.util.Date;

/**
 * @ Program       :  com.ljnt.blog.utils.TokenUtil
 * @ Description   :  token工具类（生成、验证）
 * @ Author        :  lj
 * @ CreateDate    :  2020-1-31 22:15
 */
public class TokenUtil {

    private static final long EXPIRE_TIME= 10*60*60*1000;//token到期时间10小时
    private static final String TOKEN_SECRET="ljdyaishijin**3nkjnj??";  //密钥盐

    /**
     * @Description  ：生成token
     * @author       : lj
     * @param        : [user]
     * @return       : java.lang.String
     * @exception    :
     * @date         : 2020-1-31 22:49
     */
    public static String sign(User user){

        String token=null;
        try {
            Date expireAt=new Date(System.currentTimeMillis()+EXPIRE_TIME);
            token = JWT.create()
                    .withIssuer("auth0")//发行人
                    .withClaim("username",user.getUsername())//存放数据
                    .withExpiresAt(expireAt)//过期时间
                    .sign(Algorithm.HMAC256(TOKEN_SECRET));
        } catch (IllegalArgumentException|JWTCreationException je) {

        }
        return token;
    }


    /**
     * @Description  ：token验证
     * @author       : lj
     * @param        : [token]
     * @return       : java.lang.Boolean
     * @exception    :
     * @date         : 2020-1-31 22:59
     */
    public static Boolean verify(String token){

        try {
            JWTVerifier jwtVerifier=JWT.require(Algorithm.HMAC256(TOKEN_SECRET)).withIssuer("auth0").build();//创建token验证器
            DecodedJWT decodedJWT=jwtVerifier.verify(token);
            System.out.println("认证通过：");
            System.out.println("username: " + decodedJWT.getClaim("username").asString());
            System.out.println("过期时间：      " + decodedJWT.getExpiresAt());
        } catch (IllegalArgumentException |JWTVerificationException e) {
            //抛出错误即为验证不通过
            return false;
        }
        return true;
    }

}

```

- 拦截器类
  /handler/TokenInterceptor.java

```java
package com.ljnt.blog.handler;

import com.ljnt.blog.utils.TokenUtil;
import org.json.JSONObject;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@Component
public class TokenInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        //跨域请求会首先发一个option请求，直接返回正常状态并通过拦截器
        if(request.getMethod().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }
        response.setCharacterEncoding("utf-8");
        String token = request.getHeader("token");
        if (token!=null){
            boolean result= TokenUtil.verify(token);
            if (result){
                System.out.println("通过拦截器");
                return true;
            }
        }
        response.setContentType("application/json; charset=utf-8");
        try {
            JSONObject json=new JSONObject();
            json.put("msg","token verify fail");
            json.put("code","500");
            response.getWriter().append(json.toString());
            System.out.println("认证失败，未通过拦截器");
        } catch (Exception e) {
            return false;
        }
        /**
         * 还可以在此处检验用户存不存在等操作
         */
        return false;
    }
}

```

- 配置拦截器
  /config/WebConfiguration.java
  **继承WebMvcConfigurer类，并加上@Configuration注释进行配置**

  WebMvcConfigurer配置类其实是`Spring`内部的一种配置方式，采用`JavaBean`的形式来代替传统的`xml`配置文件形式进行针对框架个性化定制，可以自定义一些Handler，Interceptor，ViewResolver，MessageConverter。基于java-based方式的spring mvc配置，需要创建一个配置类并实现WebMvcConfigurer 接口

```java
package com.ljnt.blog.config;

import com.ljnt.blog.handler.TokenInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ConcurrentTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @ Program       :  com.ljnt.blog.config.WebConfiguration
 * @ Description   :  web拦截器配置类
 * @ Author        :  lj
 * @ CreateDate    :  2020-1-31 23:23
 */
@Configuration
public class WebConfiguration implements WebMvcConfigurer {

    @Autowired
    private TokenInterceptor tokenInterceptor;

    /**
     * 解决跨域请求
     * @param registry
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedHeaders("*")
                .allowedMethods("*")
                .allowedOrigins("*")
                .allowCredentials(true);
    }

    /**
     * 异步请求配置
     * @param configurer
     */
    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setTaskExecutor(new ConcurrentTaskExecutor(Executors.newFixedThreadPool(3)));
        configurer.setDefaultTimeout(30000);
    }
    
    /**
     * 配置拦截器、拦截路径
     * 每次请求到拦截的路径，就会去执行拦截器中的方法
     * @param configurer
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        List<String> excludePath = new ArrayList<>();
        //排除拦截，除了注册登录(此时还没token)，其他都拦截
        excludePath.add("/register");  //登录
        excludePath.add("/login");     //注册
        excludePath.add("/static/**");  //静态资源
        excludePath.add("/assets/**");  //静态资源
        registry.addInterceptor(tokenInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(excludePath);
        WebMvcConfigurer.super.addInterceptors(registry);

    }
}

```

- 控制器类

```java
package com.ljnt.blog.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ljnt.blog.po.User;
import com.ljnt.blog.utils.TokenUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @ Program       :  com.ljnt.blog.controller.LoginController
 * @ Description   :
 * @ Author        :  lj
 * @ CreateDate    :  2020-1-31 23:38
 */
@RestController
public class LoginController {

    @PostMapping("/login")
    @ResponseBody
    public String login(String username,String password) throws JsonProcessingException {
        //可以在此处检验用户密码
        User user=new User();
        user.setUsername(username);
        user.setPassword(password);
        String token= TokenUtil.sign(user);
        HashMap<String,Object> hs=new HashMap<>();
        hs.put("token",token);
        ObjectMapper objectMapper=new ObjectMapper();
        return objectMapper.writeValueAsString(hs);
    };
}

```

- 测试

  1、登录
  成功登录，获得token

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200204125734580.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2xqbGo4ODg4,size_16,color_FFFFFF,t_70)

  2、不带token访问主页

  返回错误的json

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200204125751347.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2xqbGo4ODg4,size_16,color_FFFFFF,t_70)

  3、带token访问主页

  正常访问

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200204125814883.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2xqbGo4ODg4,size_16,color_FFFFFF,t_70)

  控制台输出：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200204125829136.png)
**git:** [https://github.com/lijian-github/SpringBoot_JWT_token](https://github.com/lijian-github/SpringBoot_JWT_token)
