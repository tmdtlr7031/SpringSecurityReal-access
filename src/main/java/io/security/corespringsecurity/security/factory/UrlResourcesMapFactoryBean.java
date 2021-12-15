package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

// resourceMap 자체를 빈으로 만들기위해 FactoryBean 구현
// + 해당 Map 객체를 스프링에서 관리하는 빈처럼 활용해서 별도의 작업을 할 수 있다는 장점 (이럴 필요없다고 생각하면 알아서 편하게 구현..)
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if (resourceMap == null) {
            init();
        }

        return resourceMap;
    }

    // 최초 한번만 조회-> 하지만 DB 정보가 바뀌면 다시 가져와야 하는 게 맞음. 이건 예제용이라 간단히 한 것.
    // 실무에서는 redis 등을 이용해서 캐싱해놓고 DB 데이터 변경 시 기존 캐시 삭제하는 로직도 필요할 듯
    private void init() {
        resourceMap = securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

}
