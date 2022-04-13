package com.cgmdevtodoappapi.security;


import com.cgmdevtodoappapi.security.Jwt.AuthEntryPointJwt;
import com.cgmdevtodoappapi.security.Jwt.AuthTokenFilter;
import com.cgmdevtodoappapi.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity//permite a Spring encontrar y aplicar automáticamente la clase a la Seguridad Web global.
@EnableGlobalMethodSecurity(
        // securedEnabled = true,
        // jsr250Enabled = true,
        prePostEnabled = true)//proporciona seguridad AOP en los métodos. Permite @PreAuthorize, @PostAuthorize, también soporta JSR-250
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //Spring Security cargará los detalles del usuario para realizar la autenticación y la autorización. Así que tiene la interfaz UserDetailsService que necesitamos implementar.
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    //La implementación de UserDetailsService se utilizará para configurar el DaoAuthenticationProvider mediante el método AuthenticationManagerBuilder.userDetailsService()
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*Indica a Spring Security cómo configuramos el CORS y el CSRF, cuándo queremos exigir que todos los usuarios se autentiquen o no,
    qué filtro (AuthTokenFilter) y cuándo queremos que funcione (filtro antes de UsernamePasswordAuthenticationFilter), qué Exception Handler se elige (AuthEntryPointJwt).*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests().antMatchers("/api/v1/auth/**").permitAll()
                .antMatchers("/api/v1/test/**").permitAll()
                .anyRequest().authenticated();
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
