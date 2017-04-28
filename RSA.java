
package com.fancyedu.classlib.util.algorithm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


import sun.misc.BASE64Encoder;

public class RSA {

    public static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    /**
     * RSA签名
     * 
     * @param content 待签名数据
     * @param privateKey 商户私钥
     * @param input_charset 编码格式
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String input_charset) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);

            java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);

            signature.initSign(priKey);
            signature.update(content.getBytes(input_charset));

            byte[] signed = signature.sign();

            return Base64.encode(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * RSA验签名检查
     * 
     * @param content 待签名数据
     * @param sign 签名值
     * @param ali_public_key 支付宝公钥
     * @param input_charset 编码格式
     * @return 布尔值
     */
    public static boolean verify(String content, String sign, String ali_public_key, String input_charset) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.decode(ali_public_key);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

            java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update(content.getBytes(input_charset));

            boolean bverify = signature.verify(Base64.decode(sign));
            return bverify;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * 解密
     * 
     * @param content 密文
     * @param private_key 商户私钥
     * @param input_charset 编码格式
     * @return 解密后的字符串
     */
    public static String decrypt(String content, String private_key, String input_charset) throws Exception {
        PrivateKey prikey = getPrivateKey(private_key);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, prikey);

        InputStream ins = new ByteArrayInputStream(Base64.decode(content));
        ByteArrayOutputStream writer = new ByteArrayOutputStream();
        //rsa解密的字节大小最多是128，将需要解密的内容，按128位拆开解密
        byte[] buf = new byte[128];
        int bufl;

        while ((bufl = ins.read(buf)) != -1) {
            byte[] block = null;

            if (buf.length == bufl) {
                block = buf;
            } else {
                block = new byte[bufl];
                for (int i = 0; i < bufl; i++) {
                    block[i] = buf[i];
                }
            }

            writer.write(cipher.doFinal(block));
        }

        return new String(writer.toByteArray(), input_charset);
    }

    /**
     * 得到私钥
     * 
     * @param key 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {

        byte[] keyBytes;

        keyBytes = Base64.decode(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    public static PublicKey getPublicKey(String key) throws Exception{
        byte[] keyBytes;

        keyBytes = Base64.decode(key);
        KeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    public static String ecrypt(String content, String pubkey, String input_charset) throws Exception {

        PublicKey publicKey = getPublicKey(pubkey);
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] b = content.getBytes();
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(b1);
    }
    public static void main(String[] args) throws Exception {


        /**
         * rsa公钥
         **/
        String RSA_PUBLIC_KEY_TEEYA = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCijHSxvcw6d2IonSz7tXDnqvnNAaCFOob74toEqoFggqVyBLMhtsPty6Ki1TbIdkVxwRHHYbd46BEbcPcl6tvPfCFUEZeBZqy8+JAJiZc9MkVX0qKnfvf6KeQBuMifkJYqM84Ndwqlcw8UVkHmH4qlhZYGd07GfmqaBEAmhOyPsQIDAQAB";
        /**
         * rsa私钥
         **/
        String RSA_PRIVATE_KEY_TEEYA = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKKMdLG9zDp3YiidLPu1cOeq+c0B"
                + "oIU6hvvi2gSqgWCCpXIEsyG2w+3LoqLVNsh2RXHBEcdht3joERtw9yXq2898IVQRl4FmrLz4kAmJ"
                + "lz0yRVfSoqd+9/op5AG4yJ+Qliozzg13CqVzDxRWQeYfiqWFlgZ3TsZ+apoEQCaE7I+xAgMBAAEC"
                + "gYA6iBcxNaYH25tWApsDHGfGlDOVVaOmtdeLdjmJephR11maAAU8+6H7y9sJhXtPnf8Nojczs4Us"
                + "nWwjlH76gWKa9i6kTPTMA78hAyVyC7LX/obzfD03R077TNoxWg+KQDZ0UncCyZ1+GlwADG8+/v/e"
                + "N7SvfKFTh0binmN0K2OaTQJBAM1f4TbO+499LHSQblCfdUuRqYA4q8pOBTkKAG4HK55KGHRxajUr"
                + "KdG3x5/SOmDoqbHH4faegOVS1UtglTFB3iMCQQDKng64y7OaHw59T6lxTWVdku5SlHgJ8oiavw59"
                + "vfekkzRENnNH8dzDm8Rs8DmRUo2KjOEiOhfKpELN9fv5cnYbAkEAoKmiIONZbo4I6gNXGWE1PHHu"
                + "PO2YjsHsWgvV/D1FxSXH7cgPwxpKM9LmqsOmgcthfT+WKP0kbsIXNEmRTSBvKwJBAJE1ZWea1USH"
                + "LWMxTEYfKZ4+Rv532O+IGc6NTl1fX7NarAKW41eURpsJb2SDZT5442eAP3jAGXzo69efis3i8jEC"
                + "QDGnKuRqa77vR5IHjRoNJQsZdCCa2l7ybB/bsYaU63rBbxs+uNv7nlmUnbzhTNZ0nCSb2lgaix13" + "YIowJDqwyPk=";

//        String ecryptResult = RSA.ecrypt("111111",RSA_PUBLIC_KEY_TEEYA, "utf-8");
//        System.out.println(ecryptResult);
//        String enResult="2C24i5kkE6fqQQfI3NAV01rCQREWyKfgo3TzI/mj1YaPiIA5t3Vy3PxfHczytC4R+9xtvGgZtywazqhhCFtThaajBAiFXfqobHGUZ1dhOIe0zd1yg+TqvO6FkuhsjLZ9sZOKbAwPJkLiQ/HKIBOILHsZVR1w9tHW1SU4u1XqR+Q=";
        String enResult="UTOgk5QanXG7nxD3Xc7TWJZWnkRJ8A415xmkWpdXdhQKeW5PgI7JyaKPwTO6XilYMdT6EqlyNAS/o12XOjxo2TXwthcujH1fZGlABjHl9Xvqk6e9Tyy4h/w3clqWsWcL98dMz8lvj5Yv6ZYoGl+pTnitpKcaagivX2QS5JnVS1g=";
        String decryptResult = RSA.decrypt(enResult, RSA_PRIVATE_KEY_TEEYA,"utf-8");

        System.out.println(decryptResult);


    }
}
