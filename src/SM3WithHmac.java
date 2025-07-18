import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class SM3WithHmac {

    /**
     * 计算SM3哈希值
     */
    public static String sm3Hash(String data) {
        byte[] bytes = data.getBytes();
        SM3Digest digest = new SM3Digest();
        digest.update(bytes, 0, bytes.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return Hex.toHexString(result);
    }

    /**
     * 计算HMAC-SM3
     */
    public static String hmacSm3(String key, String data) {
        byte[] keyBytes = key.getBytes();
        byte[] dataBytes = data.getBytes();

        SM3Digest digest = new SM3Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(keyBytes));

        hmac.update(dataBytes, 0, dataBytes.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);

        return Hex.toHexString(result);
    }

    public static void main(String[] args) {
        String data = "Hello, HMAC-SM3!";
        String key = "secretKey";

        System.out.println("SM3-HASH: " + sm3Hash(data));//字符串转sm3哈希
        System.out.println("HMAC-SM3: " + hmacSm3(key, data));//sm3哈希与密钥转为hmac
        //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df   --online
        //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df   --java cmd
        //
    }
}