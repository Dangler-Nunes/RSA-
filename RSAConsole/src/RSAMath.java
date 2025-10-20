import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class RSAMath {
    private static final SecureRandom random = new SecureRandom();

    public static final BigInteger ZERO = BigInteger.ZERO;
    public static final BigInteger ONE  = BigInteger.ONE;
    public static final BigInteger TWO  = BigInteger.valueOf(2);
    public static final BigInteger THREE = BigInteger.valueOf(3);
    public static final BigInteger DEFAULT_E = BigInteger.valueOf(65537);

    // ===== Entrada robusta (com re-prompt) =====
    public static BigInteger promptBigInteger(Scanner sc, String label) {
        while (true) {
            System.out.print(label);
            String s = sc.nextLine().trim();
            try {
                return new BigInteger(s);
            } catch (Exception ex) {
                System.out.println("Valor inválido. Digite apenas inteiros (sem letras).");
            }
        }
    }

    public static BigInteger promptPrime(Scanner sc, String label) {
        while (true) {
            BigInteger x = promptBigInteger(sc, label);
            if (x.compareTo(TWO) >= 0 && isProbablePrime(x, 16)) return x;
            System.out.println("O valor informado não parece primo. Tente novamente.");
        }
    }

    public static BigInteger promptE(Scanner sc, BigInteger phi) {
        while (true) {
            System.out.print("Digite e (coprimo a phi, ENTER = 65537): ");
            String es = sc.nextLine().trim();
            BigInteger e;
            if (es.isEmpty()) e = DEFAULT_E;
            else {
                try { e = new BigInteger(es); }
                catch (Exception ex) { System.out.println("Valor inválido para e."); continue; }
            }
            if (e.compareTo(ONE) > 0 && e.compareTo(phi) < 0 && gcd(e, phi).equals(ONE)) return e;
            System.out.println("e inválido: requer 1 < e < phi e gcd(e,phi)=1.");
        }
    }

    public static int promptInt(Scanner sc, String label, int def) {
        System.out.print(label);
        String s = sc.nextLine().trim();
        if (s.isEmpty()) return def;
        try { return Integer.parseInt(s); } catch (Exception ignore) { return def; }
    }

    // ===== Aritmética modular =====
    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        base = base.mod(mod);
        BigInteger result = ONE, b = base, e = exp;
        while (e.signum() > 0) {
            if (e.testBit(0)) result = result.multiply(b).mod(mod);
            b = b.multiply(b).mod(mod);
            e = e.shiftRight(1);
        }
        return result;
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        a = a.abs(); b = b.abs();
        while (!b.equals(ZERO)) { BigInteger t = a.mod(b); a = b; b = t; }
        return a;
    }

    // retorna [g, x, y] com ax + by = g
    public static BigInteger[] egcd(BigInteger a, BigInteger b) {
        BigInteger x0 = ONE,  y0 = ZERO;
        BigInteger x1 = ZERO, y1 = ONE;
        BigInteger aa = a, bb = b;
        while (!bb.equals(ZERO)) {
            BigInteger q = aa.divide(bb);
            BigInteger r = aa.subtract(q.multiply(bb));
            aa = bb; bb = r;
            BigInteger nx = x0.subtract(q.multiply(x1));
            BigInteger ny = y0.subtract(q.multiply(y1));
            x0 = x1; y0 = y1; x1 = nx; y1 = ny;
        }
        return new BigInteger[]{ aa, x0, y0 };
    }

    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] gxy = egcd(a.mod(m), m);
        if (!gxy[0].equals(ONE)) throw new ArithmeticException("Sem inverso");
        BigInteger inv = gxy[1].mod(m);
        return inv.signum() < 0 ? inv.add(m) : inv;
    }

    // ===== Miller–Rabin =====
    public static boolean isProbablePrime(BigInteger n, int rounds) {
        if (n.compareTo(TWO) < 0) return false;
        if (n.equals(TWO) || n.equals(THREE)) return true;
        if (n.mod(TWO).equals(ZERO)) return false;

        int[] small = {3,5,7,11,13,17,19,23,29,31,37};
        for (int p : small) {
            BigInteger bp = BigInteger.valueOf(p);
            if (n.equals(bp)) return true;
            if (n.mod(bp).equals(ZERO)) return false;
        }

        BigInteger d = n.subtract(ONE);
        int s = d.getLowestSetBit();
        d = d.shiftRight(s);

        for (int i = 0; i < rounds; i++) {
            BigInteger a = uniformRandom(TWO, n.subtract(ONE));
            BigInteger x = modExp(a, d, n);
            if (x.equals(ONE) || x.equals(n.subtract(ONE))) continue;
            boolean witness = false;
            for (int r = 1; r < s; r++) {
                x = x.multiply(x).mod(n);
                if (x.equals(n.subtract(ONE))) { witness = true; break; }
            }
            if (!witness) return false;
        }
        return true;
    }

    public static BigInteger uniformRandom(BigInteger minInclusive, BigInteger maxInclusive) {
        BigInteger range = maxInclusive.subtract(minInclusive);
        int nbits = Math.max(1, range.bitLength() + 1);
        BigInteger r;
        do { r = new BigInteger(nbits, random); } while (r.compareTo(range) > 0);
        return r.add(minInclusive);
    }

    public static BigInteger probablePrime(int bits) {
        while (true) {
            BigInteger c = new BigInteger(bits, random).setBit(bits - 1).setBit(0);
            if (isProbablePrime(c, 20)) return c;
        }
    }

    // ===== Blocos para texto =====
    public static List<BigInteger> toBlocks(byte[] data, int blockSize) {
        List<BigInteger> out = new ArrayList<>();
        for (int i = 0; i < data.length; i += blockSize) {
            int len = Math.min(blockSize, data.length - i);
            byte[] chunk = Arrays.copyOfRange(data, i, i + len);
            out.add(new BigInteger(1, chunk)); // positivo
        }
        return out;
    }

    public static byte[] fromBlocks(List<BigInteger> blocks) {
        // Remonta sem preencher com zeros à esquerda (evita 0x00 extras)
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        for (BigInteger m : blocks) {
            byte[] b = m.toByteArray();
            // BigInteger pode colocar um 0x00 inicial só para sinal positivo. Remova-o.
            if (b.length > 0 && b[0] == 0x00) {
                b = java.util.Arrays.copyOfRange(b, 1, b.length);
            }
            baos.write(b, 0, b.length);
        }
        return baos.toByteArray();
    }

    public static byte[] toFixed(BigInteger x, int len) {
        byte[] b = x.toByteArray();
        if (b.length == len) return b;
        if (b.length == len + 1 && b[0] == 0) return Arrays.copyOfRange(b, 1, b.length);
        if (b.length < len) {
            byte[] out = new byte[len];
            System.arraycopy(b, 0, out, len - b.length, b.length);
            return out;
        }
        return Arrays.copyOfRange(b, b.length - len, b.length); // truncar apenas zeros à esquerda
    }

    // ===== Utilidades simples =====
    public static String toHex(BigInteger x) { return x.toString(16); }
    public static String joinHex(List<BigInteger> list) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) { if (i > 0) sb.append(' '); sb.append(list.get(i).toString(16)); }
        return sb.toString();
    }
    public static List<BigInteger> parseHexBlocks(String line) {
        String[] parts = line.trim().split("\\s+");
        List<BigInteger> ret = new ArrayList<>();
        for (String p : parts) ret.add(new BigInteger(p, 16));
        return ret;
    }
}
