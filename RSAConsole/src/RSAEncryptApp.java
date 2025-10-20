import java.math.BigInteger;
import java.util.*;

public class RSAEncryptApp {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("=== Módulo A — Criptografia (somente estudo, sem padding) ===");

        while (true) {
            System.out.println("\nEscolha o modo: [A]utomático | [M]anual | [S]air");
            String opt = sc.nextLine().trim().toUpperCase(Locale.ROOT);
            if (opt.startsWith("S")) return;

            if (opt.startsWith("A")) autoMode(sc);
            else if (opt.startsWith("M")) manualMode(sc);
            else System.out.println("Opção inválida.");
        }
    }

    static void autoMode(Scanner sc) {
        int nBits = RSAMath.promptInt(sc, "Tamanho de n em bits (ex. 512/1024) [512]: ", 512);
        int primeBits = Math.max(16, nBits / 2);

        BigInteger e = RSAMath.DEFAULT_E, p, q, n, phi;
        while (true) {
            p = RSAMath.probablePrime(primeBits);
            q = RSAMath.probablePrime(primeBits);
            if (p.equals(q)) continue;
            n = p.multiply(q);
            phi = p.subtract(RSAMath.ONE).multiply(q.subtract(RSAMath.ONE));
            if (RSAMath.gcd(e, phi).equals(RSAMath.ONE)) break;
        }

        BigInteger d = RSAMath.modInverse(e, phi);

        printKeyInfo(p, q, n, phi, e, d);
        encryptMenu(sc, n, e);
    }

    static void manualMode(Scanner sc) {
        BigInteger p = RSAMath.promptPrime(sc, "Digite p (primo): ");
        BigInteger q;
        while (true) {
            q = RSAMath.promptPrime(sc, "Digite q (primo e != p): ");
            if (!q.equals(p)) break;
            System.out.println("q não pode ser igual a p.");
        }
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(RSAMath.ONE).multiply(q.subtract(RSAMath.ONE));
        BigInteger e = RSAMath.promptE(sc, phi);
        BigInteger d = RSAMath.modInverse(e, phi);

        printKeyInfo(p, q, n, phi, e, d);
        encryptMenu(sc, n, e);
    }

    static void printKeyInfo(BigInteger p, BigInteger q, BigInteger n, BigInteger phi, BigInteger e, BigInteger d) {
        System.out.println("\n=== Parâmetros gerados ===");
        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("n = p*q = " + n);
        System.out.println("phi(n) = " + phi);
        System.out.println("e = " + e);
        System.out.println("d = " + d);
        System.out.println("\n>> Anote **n** e **d** acima para usar no Módulo B (decifrar). <<");
    }

    static void encryptMenu(Scanner sc, BigInteger n, BigInteger e) {
        while (true) {
            System.out.println("\nMenu (Criptografia):");
            System.out.println("1) Criptografar TEXTO");
            System.out.println("0) Voltar");
            String op = sc.nextLine().trim();
            if ("0".equals(op)) return;
            switch (op) {
                case "1": encryptText(sc, n, e); break;
                default: System.out.println("Opção inválida.");
            }
        }
    }

    static void encryptText(Scanner sc, BigInteger n, BigInteger e) {
        System.out.print("Mensagem (UTF-8): ");
        String msg = sc.nextLine();
        byte[] bytes = msg.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        int blockSize = (n.bitLength() - 1) / 8; // garante m < n
        if (blockSize <= 0) { System.out.println("Módulo muito pequeno para texto."); return; }

        List<BigInteger> blocks = RSAMath.toBlocks(bytes, blockSize);
        List<BigInteger> cipher = new ArrayList<>();
        for (BigInteger m : blocks) cipher.add(RSAMath.modExp(m, e, n));

        System.out.println("Cifrado (hex por bloco, separados por espaço):");
        System.out.println(RSAMath.joinHex(cipher));
    }
}
