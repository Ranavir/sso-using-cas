-------------------------------------------------------------------------------------------------------------------------------------
													SINGLE SIGN ON (SSO) 
											 Dt.20052016 Logged by Ranavir Dash
-------------------------------------------------------------------------------------------------------------------------------------
Meaning:-
	SSO allows users access to all applications from one logon.
	
Advantages:-
• Improved user productivity.
• Improved developer productivity
• Simplified administration

Disadvantage:-
• Single point of attack

Ways of implementation:-
1 - Active Directory Federation Services (Microsoft	)-Proprietary
2 - Auth0 (Auth0) -Proprietary
3 - CAS / Central Authentication Service( Jasig ) -Open source
4 - Facebook connect (Facebook) -Proprietary
5 - JBoss SSO(Red Hat) -Free Software
-------------------------------------------------------------------------------------------------------------------------------------
								3 - CAS(Note: CAS is authentication, not authorization.)
				Developed by org Jasig(Java in Administration Special Interest Group) in  U.S. state of Colorado
-------------------------------------------------------------------------------------------------------------------------------------
Functionalities offered:-

- CAS supports single sign-on (SSO), proxied authentication,Security Assertion Markup Language (SAML) etc.
- UNI
- LDAP affiliations
- Date and time of last password change

Prerequisites:-

1 - cas server application deployed in app server
2 - Keystore and certificate for ssl communication at cas server deployer
3 - Keystore certificate must be imported to the JRE of the client app system
4 - Your own developed web app implementing the cas client with required configurations

Process Flow:-
1 - Request from web browser to portal app server web application
2 - your application to cas server for login
3 - After successful authentication at cas it creates inmemory cookie(TGT)
4 - Creates a service ticket and using SSL layer communication validates the service ticket
5 - If validation is successful, CAS returns the username to the application
6 - Then do the authorization and go for service

Customizations Required:-
1 - Configurations in web.xml
2 - Configurations during login and logout button click
3 - (Spring)Configuration of datasource,AuthenticationHandler in deployerConfigContext.xml of cas server for database validation
4 - Defining CasAuthenticationFilter,CasAuthenticationEntryPoint,AuthenticationManager,CasAuthenticationProvider,ServiceProperties,Single Logout Filter.
5 - Defining one CustomUserDetailsService for authorization of preauthenticated user


		   
		   


-------------------------------------------------------------------------------------------------------------------------
		New Key generation , Certificate generation and import certificate to client JRE
-------------------------------------------------------------------------------------------------------------------------
link:-https://docs.oracle.com/cd/E19798-01/821-1751/ghlgv/index.html

1- move to The default is domain-dir/config
C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf>keytool -genkey -alias keyAlias -keyalg RSA -validity 360 -keypass techlab -storepass techlab -keystore keystore.jks

--> names entered as localhost
2-Export the generated certificate to the server.cer file (or client.cer if you prefer), using the following command format:


C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf>keytool -export -alias keyAlias -storepass techlab -file server.cer -keystore keystore.jks

o/p- certificate stored as server.cer

3 - Create the cacerts.jks truststore file and add the certificate to the truststore, using the following command format:

C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf> keytool -import -v -trustcacerts -alias keyAlias -file server.cer -keystore cacerts.jks -keypass techlab

4 - check
keytool -list -v  -keystore keystore.jks -storepass techlab

5- add it to jre keystore
> keytool -import -keystore "C:\Program Files\Java\jdk1.7.0_71\jre\lib\security\cacerts" -file "C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf\server.cer" -alias myalias

Here use the password as "changeit" (Its important else you will get message as Either certificate tampered or incorrect password)

Important points during Keystore import:-
1- Check the JRE used by your application server i.e Tomcat here
2- Either you import the keystore to that JRE
3- Or Change the JRE used by tomcat where the keytool is imported 
(If not checked this point you might get PKI exceptions i.e SSL handshaking error with the client)
------------------------------------------------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------------------------------------------
				save the keystore details in server.xml of tomcat inside conf directory
-----------------------------------------------------------------------------------------------------------------------------
<Connector port="8443" protocol="org.apache.coyote.http11.Http11Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLS" keystoreFile="conf/keystore.jks"
	       keystorePass="techlab"/>
		   
-----------------------------------------------------------------------------------------------------------------------------
JAVA_OPTS VALUES OF JVAM SET TO BELOW FOR Perm size exceeded in eclipse Tomcat launch configuration -> arguments tab options
OR 
tomcat bin directory -> tomcat(n)w.exe VM arguements
-----------------------------------------------------------------------------------------------------------------------------
-Xms256m
-Xmx1024m
-XX:MaxPermSize=1024m
------------------------------------------------------------------------------------------------------------------------------
SSL PKI exception for certificate issues in client side Read below
------------------------------------------------------------------------------------------------------------------------------
https://wiki.jasig.org/display/casum/ssl+troubleshooting+and+reference+guide	
------------------------------------------------------------------------------------------------------------------------------
											CAS without Login screen
------------------------------------------------------------------------------------------------------------------------------



https://cas.example.com/cas/login?service=http://app.example.com/myapp/&username=myuser&password=mypass&auto=true

https://cas.example.com/cas/login?service=http%3A%2F%2Fapp.example.com%2Fmyapp%2F&username=myuser&password=mypass&auto=true

https://192.168.0.87:8443/cas-server-webapp/login?service=http%3A%2F%2Flocalhost%3A8080%2Fcasapp1%2Fservice

host.name=cas01.example.org

------------------------------------------------------------------------------------------------------------------------------
							Single Sign Out Working
------------------------------------------------------------------------------------------------------------------------------
In cas server app argumentExtractorsConfiguration.xml file
<bean
 		id="casArgumentExtractor"
 		class="org.jasig.cas.web.support.CasArgumentExtractor"
         p:httpClient-ref="noRedirectHttpClient"
         p:disableSingleSignOut="${slo.callbacks.disabled:false}" />
		 
-This value should be false for single signout to work 
-Also in all the client applications put Single Sign Out fileters entries in web.xml first before loading of any other filters.
--------------------------------------------------------------------------------------------------------------------------------
							Session time out in web.xml
--------------------------------------------------------------------------------------------------------------------------------
	<session-config>  
        <!-- Default to 5 minute session timeouts -->  
        <session-timeout>5</session-timeout>  
    </session-config>  
--------------------------------------------------------------------------------------------------------------------------------
Reference Links
------------------
http://www.developertutorials.com/single-sign-on/
http://www.jusfortechies.com/java/cas/overview.php
https://techannotation.wordpress.com/2014/06/12/cas-and-spring-security-client/
https://idms.rutgers.edu/cas/sample_spring_security.shtml
http://docs.spring.io/spring-security/site/docs/3.1.5.RELEASE/reference/cas.html
http://docs.spring.io/spring-security/site/docs/3.0.x/reference/cas.html
https://wiki.jasig.org/display/CASC/Configuring+the+JA-SIG+CAS+Client+for+Java+using+Spring
https://wiki.jasig.org/display/casc/using+the+cas+client+3.1+with+spring+security
http://stackoverflow.com/questions/13240684/spring-security-with-cas-authentication-and-custom-authorization
https://wiki.jasig.org/display/CAS/Using+CAS+from+external+link+or+custom+external+form
https://wiki.jasig.org/display/CAS/Using+CAS+without+the+Login+Screen
http://www.iamjk.com/2008/09/step-by-step-tutorial-on-cas-part1.html
http://crunchify.com/step-by-step-guide-to-enable-https-or-ssl-correct-way-on-apache-tomcat-server-port-8443/
http://www.mkyong.com/tomcat/how-to-configure-tomcat-to-support-ssl-or-https/
http://www.clintharris.net/2009/self-signed-certificates/
http://stackoverflow.com/questions/11708717/ip-address-as-hostname-cn-when-creating-a-certificate-https-hostname-wrong
ex:-
https://planner.makemytrip.com/?&intid=Homepage_Tab_Inspirock