package Simetrica;

import java.io.*;
import java.security.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.*;

public class EncriptaFichero {
	public static final int ITERACIONES = 1024;
	public static final int TAMANO_SALT_BYTES = 8;
	public static final int TAMANO_BUFFER = 1024;

	public static void main(String args[]) throws Exception {
		// Comprobacion de argumentos

		Scanner reader = new Scanner(System.in);
		String pass;
		String archivo;
		String encriptado;

		System.out.println(
				"Para encriptar indique " + "<password> <fichero_plano> " + "[<fichero_encriptar>] como argumento");
		System.out.println("\nPassword:");
		pass = reader.nextLine();
		System.out.println("\nFichero plano:");
		archivo = reader.nextLine();
		System.out.println("\nFichero encriptado:");
		encriptado = reader.nextLine();
		System.out.println();

		String[] parametros = { pass, archivo, encriptado };

		if (parametros.length < 2 || parametros.length > 3)

		{
			System.out.println(
					"Para encriptar indique " + "<password> <fichero_plano> " + "[<fichero_encriptar>] como argumento");
			return;
		}
		if (!parametros[2].endsWith(".des")) {
			System.out.println("Los ficheros encriptados" + " deben tener la extension .des");
			return;
		}

		System.out.println("- Contenido del fichero plano -");
		lectura(archivo);
		System.out.println();

		// Abrimos los ficheros
		FileInputStream fichero_plano = new FileInputStream(parametros[1]);
		DataOutputStream fichero_encriptado;
		if (parametros.length == 2)
			fichero_encriptado = new DataOutputStream(new FileOutputStream(parametros[1] + ".des"));
		else
			fichero_encriptado = new DataOutputStream(new FileOutputStream(parametros[2]));

		// Generamos un salt aleatorio
		System.out.print("Generando salt...");
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[8];
		sr.nextBytes(salt);

		// Generamos una clave secreta a
		// partir del password
		System.out.print("\rGenerando clave secreta");
		PBEKeySpec objeto_password = new PBEKeySpec(parametros[0].toCharArray());
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey clave_secreta = skf.generateSecret(objeto_password);

		// Generamos los parametros de PBEParameterSpec
		PBEParameterSpec pbeps = new PBEParameterSpec(salt, ITERACIONES);

		// Generamos el cifrador
		Cipher cifrador = Cipher.getInstance("PBEWithMD5AndDES");
		cifrador.init(Cipher.ENCRYPT_MODE, clave_secreta, pbeps);

		// Escribimos en el fichero encriptado los
		// parametros encoded
		System.out.print("\rEscribiendo fichero" + " encriptado...           ");
		AlgorithmParameters ap = cifrador.getParameters();
		byte[] encoded = ap.getEncoded();
		fichero_encriptado.writeInt(encoded.length);
		fichero_encriptado.write(encoded);

		// Escribimos en el fichero encriptado los
		// datos del fichero plano
		byte[] buffer_plano = new byte[TAMANO_BUFFER];
		int leidos = fichero_plano.read(buffer_plano);
		while (leidos > 0) {
			byte[] buffer_encriptado = cifrador.update(buffer_plano, 0, leidos);
			fichero_encriptado.write(buffer_encriptado);
			leidos = fichero_plano.read(buffer_plano);
		}
		fichero_encriptado.write(cifrador.doFinal());

		// Cerramos los ficheros
		fichero_plano.close();
		fichero_encriptado.close();
		System.out.println("\rHecho       ");

		System.out.println("\n- Contenido del fichero encriptado -");
		lectura(encriptado);
	}

	private static void lectura(String archivo) {
		// TODO Auto-generated method stub
		File fichero = new File(archivo);
		Scanner s = null;
		try {
			s = new Scanner(fichero);

			while (s.hasNextLine()) {
				String linea = s.nextLine();
				System.out.println(linea);
			}

		} catch (Exception ex) {
			System.out.println("Mensaje: " + ex.getMessage());
		} finally {
			try {
				if (s != null)
					s.close();
			} catch (Exception ex2) {
				System.out.println("Mensaje 2: " + ex2.getMessage());
			}
		}

	}
}
