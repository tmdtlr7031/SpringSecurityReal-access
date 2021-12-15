package io.security.corespringsecurity.security.metadatasource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class UrlFilterInvocationSecurityMetadatsSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>(); // 요청url, 권한정보 담을 Map

    // UrlResourcesMapFactoryBean에서 DB 데이터 조회한 requestMap 받음
    public UrlFilterInvocationSecurityMetadatsSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap) {
        this.requestMap = requestMap;
    }

    /**
     * 권한정보 추출 로직
     * - object : (FilterInvocation이 들어오게 됨)
     *   - 나중에 메서드 방식에서 사용되는 Invocation도 들어오기 때문에 Object 타입임
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = ((FilterInvocation) object).getRequest(); // 사용자가 요청한 URL 정보

        // DB연동 시 값을 가져오면 없어질 라인.
        // 지금은 초기값으로 주지 않으면 익명 사용자 상태에서 권한이 필요한 페이지 접근 시 (ex. /mypage) null 리턴됨.
//        requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));

        if(requestMap != null){
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)){
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    /**
     *  일단은 DefaultFilterInvocationSecurityMetadataSource 쪽 로직 복붙
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz); // 타입검사.. 메서드 방식도 들어오기 때문!
    }
}
