package com.cgmdevtodoappapi.controller;


import com.cgmdevtodoappapi.payload.request.LoginRequest;
import com.cgmdevtodoappapi.payload.request.SignUpRequest;
import com.cgmdevtodoappapi.payload.response.MessageResponse;
import com.cgmdevtodoappapi.service.UserAppServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private UserAppServiceImp userAppServiceImp;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userAppServiceImp.authenticationAppUser(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        String registerUser = userAppServiceImp.singUpUser(signUpRequest);

        if(registerUser.contains("Error"))
        {
            return ResponseEntity.badRequest().body(new MessageResponse(registerUser));
        }

        return ResponseEntity.ok(new MessageResponse(registerUser));
    }
}
