package com.kunthea.jwt.controller;

import com.kunthea.jwt.config.LoginRespon;
import com.kunthea.jwt.dto.RegisterDTO;
import com.kunthea.jwt.dto.loginDTO;
import com.kunthea.jwt.entity.User;
import com.kunthea.jwt.service.AuthenticationService;
import com.kunthea.jwt.service.JwtService;
import com.kunthea.jwt.service.otpService;
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

    public AuthenticationController(JwtService jwtService,
                                    AuthenticationService authenticationService,
                                    otpService otpService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.otpService = otpService;
    }

    @PostMapping(value = "/signup", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> register(@RequestBody(required = false) RegisterDTO registerUserDto,
                                      @RequestParam(required = false) Map<String, String> formData) {

        RegisterDTO dto = registerUserDto;

        if (dto == null && formData != null) {
            dto = new RegisterDTO();
            dto.setUsername(formData.get("username"));
            dto.setPassword(formData.get("password"));
            dto.setEmail(formData.get("email"));
        }

        // Register user
        User registeredUser = authenticationService.signup(dto);

        // Generate OTP
        String otpCode = otpService.generateAndSendOtp(registeredUser);

        // Return response with full info
        return ResponseEntity.ok(Map.of(
                "email", registeredUser.getEmail(),
                "username", registeredUser.getFullname(),
                "password", registeredUser.getPassword(),
                "otp", otpCode,
                "message", "User registered successfully. OTP sent to your email."
        ));
    }


    @PostMapping("/login")
    public ResponseEntity<LoginRespon> authenticate(@RequestBody loginDTO loginUserDto) {
        User authenticatedUser = authenticationService.authenticate(loginUserDto);

        String jwtToken = jwtService.generateToken(authenticatedUser);

        LoginRespon loginResponse = new LoginRespon()
                .setToken(jwtToken)
                .setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }
}
