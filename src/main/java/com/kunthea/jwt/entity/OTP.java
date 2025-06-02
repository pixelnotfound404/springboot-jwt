package com.kunthea.jwt.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
public class OTP {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String otpCode;

    private LocalDateTime expiryDate;

    @OneToOne
    @JoinColumn(name="id")
    private User user;
}
