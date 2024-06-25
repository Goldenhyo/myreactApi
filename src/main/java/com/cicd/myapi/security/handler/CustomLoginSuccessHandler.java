package com.cicd.myapi.security.handler;

import com.cicd.myapi.dto.MemberUserDetail;
import com.cicd.myapi.util.JWTUtil;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

// 로그인 성공시 실행할 클래스 (config 등록하면 onAuthenticationSuccess 자동 실행됨)
@Slf4j
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        log.info("******************** CustomLoginSuccessHandler");
        // * 로그인 성공하면 JSON 문자열로 응답해줄 데이터 생성해서 응답해주기
        // #1. 응답 데이터 생성 -> 사용자 정보 넣어줄거임 (로그인 시 authentication 안에 memberDTO 들어가있음)
        MemberUserDetail memberDTO = (MemberUserDetail) authentication.getPrincipal();
        Map<String, Object> claims = memberDTO.getClaims(); // 사용자정보 Map 타입으로 변환
        // JWT 토큰 생성
        String accessToken = JWTUtil.generateToken(claims, 10);
        String refreshToken = JWTUtil.generateToken(claims, 60 * 24);
        claims.put("accessToken", accessToken);
        claims.put("refreshToken", refreshToken);
        // #2. 데이터를 Json 문자열로 변환
        Gson gson = new Gson();
        String jsonStr = gson.toJson(claims);
        // #3. 응답하기 (응답메세지 보내기)
        response.setContentType("application/json; charset=UTF-8"); // 응답데이터의 형태를 헤더정보에 추가
        PrintWriter writer = response.getWriter();
        writer.println(jsonStr);
        writer.close();
    }
}
