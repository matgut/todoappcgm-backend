package com.cgmdevtodoappapi.service;

import com.cgmdevtodoappapi.entity.Role;
import com.cgmdevtodoappapi.entity.UserApp;
import com.cgmdevtodoappapi.enumeration.ERole;
import com.cgmdevtodoappapi.payload.request.LoginRequest;
import com.cgmdevtodoappapi.payload.request.SignUpRequest;
import com.cgmdevtodoappapi.payload.response.JwtResponse;
import com.cgmdevtodoappapi.repository.RoleRepository;
import com.cgmdevtodoappapi.repository.UserAppRepository;
import com.cgmdevtodoappapi.security.Jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserAppServiceImp {

    @Autowired
    private UserAppRepository appUserRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    private final static String USER_NOT_FOUND_MSG = "Username %s not found";
    private final static String USER_EXIST_USERNAME_MSG = "Error: Username %s is already taken!";
    private final static String USER_EXIST_EMAIL_MSG = "Error: Email %s is already taken!";


    public String singUpUser(SignUpRequest requestAppUser){

        boolean userExistByUsername = appUserRepository.existsByUsername(requestAppUser.getUsername());
        boolean userExistByEmail    = appUserRepository.existsByEmail(requestAppUser.getUsername());

        if(userExistByUsername){
            return String.format(USER_EXIST_USERNAME_MSG, requestAppUser.getUsername());
        }

        if(userExistByEmail){
            return String.format(USER_EXIST_EMAIL_MSG, requestAppUser.getEmail());
        }

        // Create new user's account
        UserApp user = new UserApp( requestAppUser.getUsername(),
                                    requestAppUser.getEmail(),
                                    encoder.encode(requestAppUser.getPassword())
                                    );
        Set<String> strRoles = requestAppUser.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        appUserRepository.save(user);

        return "User registered successfully!";

    }

    public JwtResponse authenticationAppUser(LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return new JwtResponse( jwt,
                                userDetails.getId(),
                                userDetails.getUsername(),
                                userDetails.getEmail(),
                                roles
                );

    }

}
