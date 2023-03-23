package be.sinube.restfusion.restfusion.JWT;


import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import oracle.security.restsec.jwt.JwtException;
import oracle.security.restsec.jwt.JwtToken;
import oracle.security.restsec.jwt.SigningException;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Component
public class GenerateJWTService {

    public static void main(String[] args) {
        generateJWT();
    }

    public static String generateJWT() {

        try{
            String iss = "myissuer.com"; //JWT issuer -iss attribute
            String prn = "my-user"; //JWT principalll -prn attribute

        JwtToken jwtToken = new JwtToken();
        //Fill in all the parameters- algorithm, issuer, expiry time, other claims etc
        jwtToken.setAlgorithm(JwtToken.SIGN_ALGORITHM.RS256.toString());
        jwtToken.setIssuer(iss);
        jwtToken.setPrincipal(prn);
        jwtToken.setType(JwtToken.JWT);
        //jwtToken.setClaimParameter("tenant","123456"); //this will set custom claim parameters,example "tenant" is custom JWT claim with value "123456")

        //iat attribute-time when JWT was generated
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        jwtToken.setIssueTime(now);
        //token expires in 10 minutes
        jwtToken.setExpiryTime(new Date(nowMillis + 10 * 60 * 1000));

        //x5t attribute,read the public key from pem format
        InputStream inStream = new FileInputStream("keys/publickey.cer");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate publicKey = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        jwtToken.setX509CertThumbprint(publicKey);

        //for signing read private key in der format
        RandomAccessFile raf = new RandomAccessFile("keys/jwt.der", "r");
        byte[] buf = new byte[(int) raf.length()];
        raf.readFully(buf);
        raf.close();
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(kspec);
         String jwtString = jwtToken.signAndSerialize(privateKey);

            System.out.println("Oracle party token: ");
            System.out.println(jwtString);


        // sign the token with a private key

        return jwtString;
        }
        catch(IOException | CertificateException e)
        {
            throw new RuntimeException(e);
        } catch (SigningException e) {
            throw new RuntimeException(e);
        } catch (JwtException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

    }

}
