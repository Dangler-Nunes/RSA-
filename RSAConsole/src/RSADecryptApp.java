import java.math.BigInteger;
import java.util.*;


public class RSADecryptApp {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("=== Módulo B — Decifrar (somente estudo, sem padding) ===");

        // Recebe n e d
        BigInteger n = RSAMath.promptBigInteger(sc, "Informe n: ");
        BigInteger d = RSAMath.promptBigInteger(sc, "Informe d: ");

        while (true) {
            System.out.println("\nMenu (Decifrar):");
            System.out.println("1) Descriptografar TEXTO (hex por bloco)");
            System.out.println("0) Sair");
            String op = sc.nextLine().trim();
            if ("0".equals(op)) return;

            switch (op) {
                case "1": decryptText(sc, n, d); break;
                default: System.out.println("Opção inválida.");
            }
        }
    }

    static void decryptText(Scanner sc, BigInteger n, BigInteger d) {
        System.out.println("Cole os blocos hex cifrados (separados por espaço), produzidos no Módulo A:");
        String line = sc.nextLine().trim();
        if (line.isEmpty()) { System.out.println("Nada informado."); return; }

        List<BigInteger> cblocks = RSAMath.parseHexBlocks(line);
        List<BigInteger> pblocks = new ArrayList<>();
        for (BigInteger c : cblocks) pblocks.add(RSAMath.modExp(c, d, n));

        byte[] data = RSAMath.fromBlocks(pblocks);
        String text = new String(data, java.nio.charset.StandardCharsets.UTF_8);

        System.out.println("Texto recuperado:");
        System.out.println(text);
    }
}
