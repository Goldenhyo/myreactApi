package com.cicd.myapi.controller;

import com.cicd.myapi.util.CustomJWTException;
import com.cicd.myapi.util.JWTUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;

@RestController
@Slf4j
public class APIRefreshController {

    @RequestMapping("/api/member/refresh")
    public Map<String, Object> refresh(@RequestHeader("Authorization") String authHeader, String refreshToken) {
        // Authorization 필요 -> AccessToken
        // 파라미터 -> RefreshToken
        log.info("******************** APIRefreshHeader - authHeader:{}", authHeader);
        log.info("******************** APIRefreshHeader - refreshToken:{}", refreshToken);
        // refreshToken 없는 경우
        if (refreshToken == null) {
            throw new CustomJWTException("NULL_REFRESH_TOKEN");
        }
        // 헤더값이 맞지 않을 경우
        if (authHeader == null || authHeader.length() < 7) {
            throw new CustomJWTException("INVALID_STRING");
        }
        String accessToken = authHeader.substring(7);
        // AccessToken 만료되지 않은 경우
        if (checkExpiredToken(accessToken) == false) {
            return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
        }
        // -------- AccessToken 만료된 시점
        // RefreshToken 검증하고 claims 리턴받아서 새 토큰 생성시 사용
        Map<String, Object> claims = JWTUtil.validateToken(refreshToken);
        log.info("****************** APIRefreshHeader claims:{}", claims);
        // 새 토큰 생성해서 전달
        String newAccessToken = JWTUtil.generateToken(claims, 10);
        String newRefreshToken = checkRemainTime((Integer) claims.get("exp"))
                ? JWTUtil.generateToken(claims, 60 * 24)
                : refreshToken; // refreshToken 1시간 안남았으면 새로 생성, 아니면 쓰던거 사용
        return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);
    }

    // RefreshToken 남은 유효시간 체크
    private boolean checkRemainTime(Integer exp) {
        Date expDate = new Date((long) exp * 1000);
        long diff = expDate.getTime() - System.currentTimeMillis();
        long diffMin = diff / (1000 * 60);
        return diffMin < 60; // 1시간 미만이면 true, 1시간 이상이면 false
    }

    // 토큰 만료 여부 확인 메서드 (만료=true, 만료X=false)
    private boolean checkExpiredToken(String accessToken) {
        try {
            JWTUtil.validateToken(accessToken); // 문제 생기면 CustomJWTException 예외 발생
        } catch (CustomJWTException e) {
            if (e.getMessage().equals("Expired")) { // 메세지가 Expired = 유효기간 지났다
                return true;
            }
        }
        return false;
    }
}
