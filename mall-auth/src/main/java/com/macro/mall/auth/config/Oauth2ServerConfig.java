package com.macro.mall.auth.config;

import com.macro.mall.auth.component.JwtTokenEnhancer;
import com.macro.mall.auth.service.impl.UserServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * 认证服务相关配置
 * Created by macro on 2020/6/19.
 */
@AllArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final UserServiceImpl userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenEnhancer jwtTokenEnhancer;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                // 在内存中存储客户端信息
                .inMemory()
                // 配置后台客户端
                .withClient("admin-app")
                // 客户端身份校验凭证：对123456进行 passwordEncoder.encode 加密
                .secret(passwordEncoder.encode("123456"))
                // 客户端的访问范围
                .scopes("all")
                // 授权类型:"password" 表示客户端可以使用用户名和密码直接获取令牌，"refresh_token" 表示客户端可以使用刷新令牌获取新的访问令牌
                .authorizedGrantTypes("password", "refresh_token")
                // 访问令牌的有效期：24h
                .accessTokenValiditySeconds(3600*24)
                // 刷新令牌的有效期：24h
                .refreshTokenValiditySeconds(3600*24*7)

                .and()
                // 配置前台客户端
                .withClient("portal-app")
                // 客户端身份校验凭证：对123456进行 passwordEncoder.encode 加密
                .secret(passwordEncoder.encode("123456"))
                // 客户端的访问范围
                .scopes("all")
                .authorizedGrantTypes("password", "refresh_token")
                // 访问令牌的有效期：24h
                .accessTokenValiditySeconds(3600*24)
                // 刷新令牌的有效期：24h
                .refreshTokenValiditySeconds(3600*24*7);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer);
        delegates.add(accessTokenConverter());
        enhancerChain.setTokenEnhancers(delegates); //配置JWT的内容增强器
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService) //配置加载用户信息的服务
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(enhancerChain);
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

        //允许客户端使用表单身份验证：即用户名和密码验证
        security.allowFormAuthenticationForClients();
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        // 创建JwtAccessTokenConverter，用于转换OAuth2访问令牌为JWT
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        // 设置KeyPair：KeyPair是用于签名和验证JWT的公钥/私钥对
        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    @Bean
    public KeyPair keyPair() {
        // 创建 KeyStoreKeyFactory对象，用于从密钥库文件中加载KeyPair；"123456"是打开密钥库的密码
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        // 从密钥库中获取密钥对
        KeyPair jwt = keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
        return jwt;
    }

}
