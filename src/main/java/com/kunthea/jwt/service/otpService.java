package com.kunthea.jwt.service;

import com.kunthea.jwt.entity.OTP;
import com.kunthea.jwt.entity.User;
import com.kunthea.jwt.repository.OtpRepositories;
import com.kunthea.jwt.util.OtpGenerator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class otpService {

    private final OtpRepositories otpRepository;
    private final EmailService emailService;

    private static final int OTP_EXPIRY_MINUTES = 5;

    public otpService(OtpRepositories otpRepository, EmailService emailService) {
        this.otpRepository = otpRepository;
        this.emailService = emailService;
    }

    public String generateAndSendOtp(User user) {

        otpRepository.deleteByUser(user);

        String otpCode = OtpGenerator.generateOtp();

        OTP otp = new OTP();
        otp.setUser(user);
        otp.setOtpCode(otpCode);
        otp.setExpiryDate(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));

        otpRepository.save(otp);



        emailService.sendOtpEmail(user.getEmail(), otpCode);
        return otpCode;
    }

    public boolean verifyOtp(User user, String otpCode) {
        return otpRepository.findByUser(user)
                .filter(otp -> otp.getOtpCode().equals(otpCode))
                .filter(otp -> otp.getExpiryDate().isAfter(LocalDateTime.now()))
                .map(otp -> {
                    otpRepository.delete(otp);
                    return true;
                })
                .orElse(false);
    }
}
