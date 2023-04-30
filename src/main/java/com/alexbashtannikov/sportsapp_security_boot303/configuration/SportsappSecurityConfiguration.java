package com.alexbashtannikov.sportsapp_security_boot303.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.sql.DataSource;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SportsappSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Bean
    public AuthenticationSuccessHandler getAuthenticationSuccessHandler(){
        return new AccountAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationManager authecticationProvider() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
        auth.jdbcAuthentication().dataSource(dataSource)
                .usersByUsernameQuery("select email, password, enabled from account where email = ?")
                .authoritiesByUsernameQuery("select email, role from account where email = ?");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                                            .antMatchers("/login", "/api").permitAll()
                                            .antMatchers("/patient/**", "/api/patient/**").hasRole("PATIENT")
                                            .antMatchers("/doctor/**", "/api/doctor/**").hasRole("DOCTOR")
                                            .antMatchers("/admin/**").hasRole("ADMIN")
                .and().formLogin().loginPage("/login")
                .and().logout()
                .and().cors().and().csrf().disable();
    }

    @Bean
    public PasswordEncoder encoder(){
        return NoOpPasswordEncoder.getInstance();
    }
}
