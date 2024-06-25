package com.cicd.myapi.security.filter;

import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.util.JWTUtil;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

@Slf4j
public class JWTCheckFilter extends OncePerRequestFilter {

    // 필터 생략할것 지정하는 메서드 추가 (OncePerRequestFilter 의 부모에 있는 메서드 오버라이딩)
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestURI = request.getRequestURI();
        log.info("******************** JWTCheckFilter - shouldNotFilter : requestURI:{}", requestURI);
        // Preflight 필터 체크 X (Ajax CORS 요청 전에 날리는 Preflight 는 필터체크하지 않겠다)
        if (request.getMethod().equals("OPTIONS")) {
            return true;
        }
        // /api/member/.. 경로 요청은 필터 체크 X
        if (requestURI.startsWith("/api/member/")) {
            return true;
        }
        // 테스트용 경로
        if (requestURI.startsWith("/apitest")) {
            return true;
        }
        return false;
    }

    // 필터링 로직 작성 (구현 필수)
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("******************** JWTCheckFilter - doFilterInternal");
        String authValue = request.getHeader("Authorization");
        log.info("******************** doFilterInternal - authValue:{}", authValue);
        // -> Bearer ...accessToken
        try {
            String accessToken = authValue.substring(7);
            Map<String, Object> claims = JWTUtil.validateToken(accessToken);
            log.info("******************* doFilterInternal - claims:{}", claims);
            // 인증 정보 claims 로 MemberDTO 구성 -> 시큐리티에 반영해주기 (시큐리티용 권한)
            String email = (String) claims.get("email"); 
            String password = (String) claims.get("password"); 
            String nickname = (String) claims.get("nickname");
            Boolean social = (Boolean) claims.get("social"); 
            List<String> roleNames = (List<String>) claims.get("roleNames");
            MemberUserDetail memberDTO = new MemberUserDetail(email, password, nickname, social, roleNames);
            // 시큐리티에 인증 추가 : JWT 와 SpringSecurity 사이에 로그인 상태가 호환되도록 처리
            UsernamePasswordAuthenticationToken authenticationToken 
                    = new UsernamePasswordAuthenticationToken(memberDTO, password, memberDTO.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response); // 다음 필터 이동하라는 뜻

        } catch (Exception e) {
            // Access Token 검증 예외 처리 (검증 실패하면 직접 만든 예외 발생시키고, 그에따른 처리하기)
            log.error(e.getMessage());
            log.error("******************** JWTCheckFilter error");
            // 에러라고 응답해줄 메세지 생성하고 전송하기
            Gson gson = new Gson();
            String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));
            response.setContentType("application/json");
            PrintWriter writer = response.getWriter();
            writer.println(msg);
            writer.close();
        }
    }
}
