package com.kunthea.jwt.repository;

import com.kunthea.jwt.entity.OTP;
import com.kunthea.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepositories extends JpaRepository<OTP, Integer> {
    Optional<OTP> findByUser(User user);
    void deleteByUser(User user);
}
