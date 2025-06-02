package com.kunthea.jwt.dto;

import lombok.Data;

@Data
public class OtpRequestDTO {
    private String otp;
    private String email;
}
