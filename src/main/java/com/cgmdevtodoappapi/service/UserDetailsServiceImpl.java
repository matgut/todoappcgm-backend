package com.cgmdevtodoappapi.service;


import com.cgmdevtodoappapi.entity.UserApp;
import com.cgmdevtodoappapi.repository.UserAppRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserAppRepository userAppRepository;

    @Override
    @Transactional
    //obtenemos el objeto User completo usando UserRepository, luego construimos un objeto UserDetails usando el método static build()
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserApp user = userAppRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
        return UserDetailsImp.build(user);
    }
}
