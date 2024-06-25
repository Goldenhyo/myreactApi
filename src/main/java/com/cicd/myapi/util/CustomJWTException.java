package com.cicd.myapi.util;

// JWT 부분에서 예외 발생하면 예외 정보 담아서 예외 발생시킬 클래스 직접 생성
public class CustomJWTException extends RuntimeException{
    // 예외 클래스 생성자
    public CustomJWTException(String msg) {
        super(msg); // RuntimeException 한테 msg 전달
    }
}
