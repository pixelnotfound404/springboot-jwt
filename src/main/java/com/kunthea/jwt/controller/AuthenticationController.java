package com.kunthea.jwt.controller;

import com.kunthea.jwt.dto.*;
import com.kunthea.jwt.entity.User;
import com.kunthea.jwt.repository.UserRepositories;
import com.kunthea.jwt.service.AuthenticationService;
import com.kunthea.jwt.service.JwtService;
import com.kunthea.jwt.service.otpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final otpService otpService;
    private final UserRepositories userRepository;

    public AuthenticationController(JwtService jwtService,
                                    AuthenticationService authenticationService,
                                    otpService otpService,
                                    UserRepositories userRepository) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.otpService = otpService;
        this.userRepository = userRepository;
    }

    @PostMapping(value = "/signup", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> register(@RequestBody(required = false) RegisterDTO registerUserDto,
                                      @RequestParam(required = false) Map<String, String> formData) {

        RegisterDTO dto = registerUserDto;

        if (dto == null && formData != null) {
            dto = new RegisterDTO();
            dto.setUsername(formData.get("username"));  // This will be used as fullName
            dto.setPassword(formData.get("password"));
            dto.setEmail(formData.get("email"));
        }

        User registeredUser = authenticationService.signup(dto);
        String otpCode = otpService.generateAndSendOtp(registeredUser);
        String jwtToken = jwtService.generateToken(registeredUser);

        // Create comprehensive response
        SignupResponse response = new SignupResponse()
                .setToken(jwtToken)
                .setExpiresIn(jwtService.getExpirationTime())
                .setOtp(otpCode)
                .setUserId(registeredUser.getId())
                .setUsername(dto.getUsername()) // Return original username from DTO
                .setFullName(registeredUser.getFullname())
                .setEmail(registeredUser.getEmail())
                .setPasswordHash(registeredUser.getPassword())
                .setVerified(registeredUser.isVerified())
                .setCreatedAt(registeredUser.getCreatedAt())
                .setMessage("User registered successfully. Please verify your email with the OTP sent.");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    @Transactional
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

    @PostMapping("/resend")
    @Transactional
    public ResponseEntity<Map<String, String>> resendOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        if (email == null || email.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }

        return userRepository.findByEmail(email)
                .map(user -> {
                    String newOtp = otpService.generateAndSendOtp(user);
                    return ResponseEntity.ok(Map.of(
                            "message", "OTP resent to your email",
                            "email", email,
                            "otp", newOtp
                    ));
                })
                .orElse(ResponseEntity.badRequest().body(Map.of("error", "User not found")));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody loginDTO loginUserDto) {
        try {
            User authenticatedUser = authenticationService.authenticate(loginUserDto);

            // Check if user is verified
            if (!authenticatedUser.isVerified()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                        "error", "Please verify your email before logging in",
                        "email", authenticatedUser.getEmail(),
                        "verified", false
                ));
            }

            String jwtToken = jwtService.generateToken(authenticatedUser);

            LoginRespon loginResponse = new LoginRespon()
                    .setToken(jwtToken)
                    .setExpiresIn(jwtService.getExpirationTime());

            return ResponseEntity.ok(Map.of(
                    "message", "Login successful",
                    "token", loginResponse.getToken(),
                    "expiresIn", loginResponse.getExpiresIn(),
                    "user", Map.of(
                            "id", authenticatedUser.getId(),
                            "username", authenticatedUser.getFullname(),
                            "email", authenticatedUser.getEmail()
                    )
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "Authentication failed: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                if (token.trim().isEmpty()) {
                    return ResponseEntity.badRequest().body(Map.of(
                            "error", "Token is empty"
                    ));
                }

                jwtService.blacklistToken(token);

                return ResponseEntity.ok(Map.of(
                        "message", "Successfully logged out"
                ));
            }

            return ResponseEntity.badRequest().body(Map.of(
                    "error", "No valid token found"
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "error", "Logout failed: " + e.getMessage()
            ));
        }
    }



}