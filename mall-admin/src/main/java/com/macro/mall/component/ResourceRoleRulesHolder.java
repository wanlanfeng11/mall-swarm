package com.macro.mall.component;

import com.macro.mall.service.UmsResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * 资源与角色访问对应关系操作组件，负责初始化绝色与资源的关系
 * Created by macro on 2020/7/17.
 */
@Component
public class ResourceRoleRulesHolder {

    @Autowired
    private UmsResourceService resourceService;


    /**
     * 负责初始化角色与资源的关系，@PostConstruct会在该bean初始化完成后进行初始化回调
     */
    @PostConstruct
    public void initResourceRolesMap(){
        resourceService.initResourceRolesMap();
    }
}
