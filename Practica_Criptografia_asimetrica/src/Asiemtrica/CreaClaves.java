package Asiemtrica;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.io.*;

public class CreaClaves implements Constantes {
	public static void main(String[] args) throws Exception {
		// Generamos las claves publica/privada
		SecureRandom sr = new SecureRandom();
		sr.setSeed(new Date().getTime());
		System.out.println("Generando claves...");
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(TAMANO_CLAVE_RSA, sr);
		KeyPair par_claves = kpg.generateKeyPair();
		System.out.println("Claves generadas");
		// Generamos el fichero de la clave publica
		System.out.print("Indique fichero para" + " la clave publica:");
		BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
		String fichero_publica;
		fichero_publica = teclado.readLine();
		FileOutputStream fos = new FileOutputStream(fichero_publica);
		fos.write(par_claves.getPublic().getEncoded());
		fos.close();
		System.out.println("Fichero con clave publica generado");
		// Generamos el fichero de clave privada
		System.out.print("Indique fichero para la clave privada:");
		String fichero_privada;
		fichero_privada = teclado.readLine();
		System.out.print("La clave privada debe estar encriptada, indique password con la que");
		char[] password;
		password = teclado.readLine().toCharArray();
		System.out.println(Arrays.toString(password));
		// Encriptamos con un PBE
		byte[] salt = new byte[TAMANO_SALT_BYTES];
		sr.nextBytes(salt);
		PBEKeySpec clave_pbe = new PBEKeySpec(password);
		SecretKey clave_secreta_pbe = SecretKeyFactory.getInstance("PBEWithMD5andDES")
				.generateSecret(clave_pbe);
		PBEParameterSpec pbe_param = new PBEParameterSpec(salt, ITERACIONES_PBE);
		Cipher cifrador_pbe = Cipher.getInstance("PBEWithMD5andDES");
		cifrador_pbe.init(Cipher.ENCRYPT_MODE, clave_secreta_pbe, pbe_param);
		byte[] clave_privada_cifrada = cifrador_pbe.doFinal(par_claves.getPrivate().getEncoded());
		fos = new FileOutputStream(fichero_privada);
		fos.write(salt);
		fos.write(clave_privada_cifrada);
		fos.close();
		System.out.println("Fichero con clave privada generado");
	}
}