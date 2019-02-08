package com.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

	@Autowired
	private RestAuthenticationSuccessHandler restAuthenticationSuccessHandler;

	@Autowired
	private RestAuthenticationFailureHandler restAuthenticationFailureHandler;
	
	@Bean
	public BCryptPasswordEncoder encoder() { // Encoder
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().exceptionHandling()

				/*
				 * AUTHENTICATION ENTRY POINT In a standard web application, the authentication
				 * process may automatically trigger when an un-authenticated client tries to
				 * access a secured resource. This process usually redirects to a login page so
				 * that the user can enter credentials. However, for a REST Web Service,this
				 * behaviour doesn’t make much sense. We should be able to authenticate only by
				 * a request to the correct URI and if the user is not authenticated all
				 * requests should simply fail with a 401 UNAUTHORIZED status code. Spring
				 * Security handles this automatic triggering of the authentication process with
				 * the concept of an Entry Point – this is a required part of the configuration,
				 * and can be injected via the authenticationEntryPoint method.
				 * 
				 */

				.authenticationEntryPoint(restAuthenticationEntryPoint).and().authorizeRequests()
				.antMatchers("/api/user/**").authenticated()
				.antMatchers("/api/admin/**").hasRole("ADMIN").and()

				/*
				 * FORMLOGIN The most basic configuration defaults to automatically generating a
				 * login page at the URL "/login", redirecting to "/login?error" for
				 * authentication failure.
				 */

				.formLogin().usernameParameter("UserName") // default is username
				.passwordParameter("Password") // default is password
				.loginPage("/authentication/login") // default is /login with an HTTP get
				.failureUrl("/authentication/login?failed") // default is /login?error
				.loginProcessingUrl("/authentication/login/process") // default is /login

				/*
				 * SUCCESS HANDLER By default, form login will answer a successful
				 * authentication request with a 301 MOVED PERMANENTLY status code; this makes
				 * sense in the context of an actual login form which needs to redirect after
				 * login. However, for a RESTful web service, the desired response for a
				 * successful authentication should be 200 OK. We do this by injecting a custom
				 * authentication success handler in the form login filter
				 */

				// FOR MVC: .defaultSuccessUrl("/homepage.html",
				// true).failureUrl("/login.html?error=true")
				.successHandler(restAuthenticationSuccessHandler).failureHandler(restAuthenticationFailureHandler).and()

				.logout().logoutUrl("/perform_logout").invalidateHttpSession(true)
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.ACCEPTED)).and() // We can create a custom LogoutSucessHandler : restLogoutSuccessHandler 

				/*
				 * SESSION CREATION POLICY https://www.baeldung.com/spring-security-session We
				 * can control exactly when our session gets created and how Spring Security
				 * will interact with it: always – a session will always be created if one
				 * doesn’t already exist ifRequired – a session will be created only if required
				 * (default) never – the framework will never create a session itself but it
				 * will use one if it already exists stateless – no session will be created or
				 * used by Spring Security : the direct implication that cookies are not used
				 * and so each and every request needs to be re-authenticated
				 */

				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).sessionFixation()
				.newSession().maximumSessions(2).expiredUrl("/api/expired");

	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		String password = encoder().encode("qwerty");
		auth.inMemoryAuthentication().withUser("nikku").password(password).roles("USER").and().withUser("manager")
				.password(password).credentialsExpired(false).accountExpired(false).accountLocked(false)
				.authorities("WRITE_PRIVILEGES", "READ_PRIVILEGES").roles("ADMIN");
	}

}
