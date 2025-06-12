package com.kunthea.jwt.dto;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Date;

@Data
@Accessors(chain=true)
public class SignupResponse {
    private String token;
    private long expiresIn;
    private String otp;
    private Integer userId;
    private String username;
    private String fullName;
    private String email;
    private String passwordHash;
    private boolean verified;
    private Date createdAt;
    private String message;
}
