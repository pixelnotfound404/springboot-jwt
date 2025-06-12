package com.kunthea.jwt.dto;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class LoginRespon {
    private String token;

    private long expiresIn;


    public String getToken() {
        return token;
    }

}
