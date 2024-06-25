package com.cicd.myapi.security.handler;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(
            HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        log.info("********** CustomAccessDeniedHandler");
        // 에러메세지 json 으로 생성해 상태코드와 함께 전달
        Gson gson = new Gson();
        String json = gson.toJson(Map.of("error", "ERROR_ACCESS_DENIED"));
        response.setContentType("application/json");
        response.setStatus(HttpStatus.FORBIDDEN.value()); // 상태코드 int 타입 == HttpStatus.상태명.value()
        PrintWriter writer = response.getWriter();
        writer.println(json);
        writer.close();
    }
}
