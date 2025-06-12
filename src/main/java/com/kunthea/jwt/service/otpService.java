package com.kunthea.jwt.service;

import com.kunthea.jwt.entity.OTP;
import com.kunthea.jwt.entity.User;
import com.kunthea.jwt.repository.OtpRepositories;
import com.kunthea.jwt.util.OtpGenerator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

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
        Optional<OTP> otpOptional = otpRepository.findByUser(user);

        if (otpOptional.isEmpty()) {
            System.out.println("No OTP found for user");
            return false;
        }

        OTP storedOtp = otpOptional.get();

        boolean isExpired = storedOtp.getExpiryDate().isBefore(LocalDateTime.now());
        boolean codesMatch = storedOtp.getOtpCode().equals(otpCode);

        if (codesMatch && !isExpired) {
            otpRepository.delete(storedOtp);
            return true;
        }

        return false;
    }

}
