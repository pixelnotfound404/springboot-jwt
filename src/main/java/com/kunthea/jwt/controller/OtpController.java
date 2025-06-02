package com.kunthea.jwt.controller;

import com.kunthea.jwt.dto.OtpRequestDTO;
import com.kunthea.jwt.repository.UserRepositories;
import com.kunthea.jwt.service.otpService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/otp")
public class OtpController {
    private final otpService otpService;
    private final UserRepositories userRepository;

    public OtpController(otpService otpService, UserRepositories userRepository) {
        this.otpService = otpService;
        this.userRepository = userRepository;
    }

    @PostMapping("/resend")
    public ResponseEntity<?> resendOtp(@RequestParam String email) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    otpService.generateAndSendOtp(user);
                    return ResponseEntity.ok("OTP resent to your email");
                })
                .orElse(ResponseEntity.badRequest().body("User not found"));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyOtp(@RequestBody OtpRequestDTO otpRequest) {
        return userRepository.findByEmail(otpRequest.getEmail())
                .map(user -> {
                    boolean verified = otpService.verifyOtp(user, otpRequest.getOtp());
                    if (verified) {
                        user.setVerified(true);
                        userRepository.save(user);
                        return ResponseEntity.ok("User verified successfully");
                    } else {
                        return ResponseEntity.badRequest().body("Invalid or expired OTP");
                    }
                })
                .orElse(ResponseEntity.badRequest().body("User not found"));
    }

}
