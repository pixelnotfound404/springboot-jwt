package com.kunthea.jwt.controller;

import com.kunthea.jwt.config.LoginRespon;
import com.kunthea.jwt.dto.RegisterDTO;
import com.kunthea.jwt.dto.loginDTO;
import com.kunthea.jwt.entity.User;
import com.kunthea.jwt.service.AuthenticationService;
import com.kunthea.jwt.service.JwtService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;

    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping(value = "/signup", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<User> register(@RequestBody(required = false) RegisterDTO registerUserDto,
                                         @RequestParam(required = false) Map<String, String> formData) {

        // Handle JSON request
        if (registerUserDto != null) {
            User registeredUser = authenticationService.signup(registerUserDto);
            return ResponseEntity.ok(registeredUser);
        }

        // Handle form data request
        RegisterDTO dto = new RegisterDTO();
        // Map form data to DTO
        dto.setUsername(formData.get("username"));
        dto.setPassword(formData.get("password"));
        dto.setEmail(formData.get("email"));

        User registeredUser = authenticationService.signup(dto);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginRespon> authenticate(@RequestBody loginDTO loginUserDto) {
        User authenticatedUser = authenticationService.authenticate(loginUserDto);

        String jwtToken = jwtService.generateToken(authenticatedUser);

        LoginRespon loginResponse = new LoginRespon().setToken(jwtToken).setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }
}
