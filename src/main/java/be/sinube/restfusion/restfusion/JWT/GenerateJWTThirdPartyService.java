package be.sinube.restfusion.restfusion.JWT;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class GenerateJWTThirdPartyService {

    public static void main(String[] args) {
        generateJWTThirdParty();
    }

    public static String generateJWTThirdParty() {

        try {
            String iss = "myissuer.com"; //JWT issuer -iss attribute
            String prn = "my-user"; //JWT principalll -prn attribute

            //x5t attribute,read the public key from pem format
            InputStream inStream = new FileInputStream("keys/publickey.cer");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate publicKey = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();


            // Create the header
            Map map = new HashMap<String, Object>();
            map.put("alg", "RS256");
            map.put("typ", "JWT");

            MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
            byte[] sha1 = sha1Digester.digest(publicKey.getEncoded());
            if (sha1 != null && sha1.length > 0) {
                map.put("x5t", Base64.getEncoder().encodeToString(sha1).replace("=", ""));
            }


            //Create the payblaod and sign
            //for signing read private key in der format
            RandomAccessFile raf = new RandomAccessFile("keys/jwt.der", "r");
            byte[] buf = new byte[(int) raf.length()];
            raf.readFully(buf);
            raf.close();
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(kspec);

            Map<String, Object> tokenData = new HashMap<>();
            long nowMillis = System.currentTimeMillis();
            long exp = nowMillis + 10 * 60 * 1000;
            tokenData.put("iss", iss);
            tokenData.put("prn", prn);
            tokenData.put("iat", nowMillis);
            tokenData.put("exp", exp);
            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setClaims(tokenData);
            String vToken = jwtBuilder.setHeader(map).signWith(SignatureAlgorithm.RS256, privateKey).compact();
            System.out.println("Third party token: ");
            System.out.println(vToken);
            return vToken;
        }
        catch(IOException | CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }



}
