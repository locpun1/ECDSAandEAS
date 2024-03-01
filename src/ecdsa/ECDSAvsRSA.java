package ecdsa;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Scanner;

public class ECDSAvsRSA {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("hập thông điệp (nhập 'exit' để thoát): ");
            String message = scanner.nextLine();

            if ("exit".equalsIgnoreCase(message)) {
                System.out.println("Dừng nhắn tin: ");
                break;
            }

            // Người gửi tạo khóa bí mật (symmetric key) cho AES
            Key secretKey = generateAESKey();

            // Người gửi tạo cặp khóa ECDSA
            KeyPair senderKeyPair = generateECDSAKeyPair();

            // Người gửi tạo thông điệp
            System.out.println("tin nhắn người gửi: " + message);
            byte[] signature = signData(senderKeyPair.getPrivate(), message.getBytes());
            System.out.println("Tin nhắn sau khi được ký: " + signature);

            // Người gửi mã hóa nội dung thông điệp bằng AES
            String encryptedMessage = encryptMessage(message, secretKey);
            System.out.println("Người gửi mã hóa tin nhắn: " + encryptedMessage);

            // Người gửi chuyển tải thông điệp, chữ ký số và khóa mã hóa cho người nhận

            // Người nhận nhận được thông điệp, chữ ký số và khóa mã hóa

            // Người nhận giải mã nội dung thông điệp bằng AES
            String decryptedMessage = decryptMessage(encryptedMessage, secretKey);
            System.out.println("Người nhận giải mã thông điệp vừa nhận được: " + decryptedMessage);

            // Người nhận xác minh chữ ký số
            boolean verificationResult = verifySignature(senderKeyPair.getPublic(), message.getBytes(), signature);
            System.out.println("Người nhận xác minh chữ ký số: " + verificationResult);
            // Hiển thị thông điệp sau khi giải mã và kết quả xác minh chữ ký số
        }
    }

    // Hàm tạo khóa bí mật (symmetric key) cho AES
    private static Key generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");//khai báo 1 khóa sử dung AES
        keyGenerator.init(256);//độ dài 256 bit
        return keyGenerator.generateKey();//trả về 1 cặp khóa
    }

    // Hàm tạo cặp khóa ECDSA
    private static KeyPair generateECDSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");// kởi tạo khóa sử dụng ECDSA
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));//sử dụng đường cong elliptic với tham số secp256r1
        return keyPairGenerator.generateKeyPair();//trả về 1 cặp khóa
    }

    // Hàm ký dữ liệu bằng ECDSA
    private static byte[] signData(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");//tạo đối tượng chữkysy su dung thuat toan SHA256 và ECDSA
        signature.initSign(privateKey);//đối tượng signature su dung khoa rieng tu trong qua trinh ký
        signature.update(data);//cập nhat du lieu can ky vao signature
        return signature.sign();//trả về chữ ký số khi được tạo ra (sign() trả v một mảng byte))
    }

    // Hàm mã hóa thông điệp bằng AES
    private static String encryptMessage(String message, Key secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");//su dung cipher vì nó cung cấp các thuật toán mã hóa giải mã
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);//sử dụng chế độ mã hóa va truyền key để mã hóa
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());//trả về mảng byte va luu vao day vừa khởi tạo
        return Base64.getEncoder().encodeToString(encryptedBytes);//trả về mảng trên và chuyển đổi nó thành chuối base64 giúp dễ dàng truyen tai va luu chữ
    }

    // Hàm giải mã thông điệp bằng AES
    private static String decryptMessage(String encryptedMessage, Key secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);//su dung tinh nang giai ma và su dung key de giai ma
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));//chuyển chuỗi về lại dang byte va dua no vao mang
        return new String(decryptedBytes);//su dung ép kiểu String cho mảng byte và trả về giá trị
    }

    // Hàm xác minh chữ ký số bằng ECDSA
    private static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
