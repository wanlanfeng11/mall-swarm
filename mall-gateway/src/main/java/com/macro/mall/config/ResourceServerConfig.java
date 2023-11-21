package com.macro.mall.config;

import cn.hutool.core.util.ArrayUtil;
import com.macro.mall.authorization.AuthorizationManager;
import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.component.RestAuthenticationEntryPoint;
import com.macro.mall.component.RestfulAccessDeniedHandler;
import com.macro.mall.filter.IgnoreUrlsRemoveJwtFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

/**
 * 资源服务器配置
 * Created by macro on 2020/6/19.
 */
@AllArgsConstructor
@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {
    private final AuthorizationManager authorizationManager;
    private final IgnoreUrlsConfig ignoreUrlsConfig;
    private final RestfulAccessDeniedHandler restfulAccessDeniedHandler;
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
    private final IgnoreUrlsRemoveJwtFilter ignoreUrlsRemoveJwtFilter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 配置 OAuth 2.0 资源服务器
                .oauth2ResourceServer()
                // 使用 JWT 作为资源服务器的令牌解析和验证机制
                .jwt()
                // 自定义的 JWT 认证转换器：负责将 JWT 转换为 Spring Security 的 Authentication 对象
                .jwtAuthenticationConverter(jwtAuthenticationConverter());

        //自定义处理JWT请求头过期或签名错误的结果
        http.oauth2ResourceServer().authenticationEntryPoint(restAuthenticationEntryPoint);

        //添加自定义filter在指定filter之前
        http.addFilterBefore(ignoreUrlsRemoveJwtFilter,SecurityWebFiltersOrder.AUTHENTICATION);

        http.authorizeExchange()
                // 白名单配置，permitall表示立即放行，不会走以下配置的authorizationManager逻辑
                .pathMatchers(ArrayUtil.toArray(ignoreUrlsConfig.getUrls(),String.class)).permitAll()
                // 鉴权管理器配置
                .anyExchange().access(authorizationManager)
                // 配置异常处理
                .and().exceptionHandling()
                // 配置自定义未授权处理
                .accessDeniedHandler(restfulAccessDeniedHandler)
                // 配置自定义未认证处理
                .authenticationEntryPoint(restAuthenticationEntryPoint)
                .and()
                // 禁用CSRF防护
                .csrf().disable();

        return http.build();
    }

    @Bean
    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // 设置权限前缀
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(AuthConstant.AUTHORITY_PREFIX);
        // 设置用于存储权限信息的 JWT 权限名称
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstant.AUTHORITY_CLAIM_NAME);
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

}
