package com.cicd.myapi.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.*;
import java.util.stream.Collectors;

public class MemberUserDetail extends User {
    private String email;
    private String password;
    private String nickname;
    private boolean social;
    private List<String> roleNames = new ArrayList<>();

    public MemberUserDetail(String email, String password, String nickname, boolean social, List<String> roleNames) {
        super(email, password, roleNames.stream()
                .map(str -> new SimpleGrantedAuthority("ROLE_"+str))
                .collect(Collectors.toList())); // 시큐리티를 위한 부모 생성자 호출
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.social = social;
        this.roleNames = roleNames;
    }

    // 현재 사용자 정보를 Map 타입으로 리턴 (JWT 위한 메서드, 추후 JWT 문자열 생성시 사용)
    // MemberDTO 리턴시 User 포함하고 있어서 문제발생 가능 -> Map 타입으로 정보만 리턴
    public Map<String, Object> getClaims() {
        Map<String, Object> map = new HashMap<>();
        map.put("email", email);
        map.put("password", password); // 비번은 나중에 전달 안하는것으로 변경해야함
        map.put("nickname", nickname);
        map.put("social", social);
        map.put("roleNames", roleNames);
        return map;
    }
}
