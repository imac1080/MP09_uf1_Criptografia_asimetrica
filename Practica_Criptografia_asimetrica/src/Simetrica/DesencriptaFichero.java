package Simetrica;

import java.io.*;
import java.security.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.*;

public class DesencriptaFichero {
	public static final int ITERACIONES = 1024;
	public static final int TAMANO_BUFFER = 1024;

	public static void main(String args[]) throws Exception {

		Scanner reader = new Scanner(System.in);
		String pass;
		String archivo;
		String encriptado;

		System.out.println("Indique <password> " + " <fichero_encriptado> [<fichero_plano>]" + " como argumento");
		System.out.println("\nPassword:");
		pass = reader.nextLine();
		System.out.println("\nFichero encriptado:");
		encriptado = reader.nextLine();
		System.out.println("\nFichero plano:");
		archivo = reader.nextLine();
		System.out.println();

		String[] parametros = { pass, encriptado, archivo };

		// Comprobacion de argumentos
		if (parametros.length < 2 || parametros.length > 3) {
			System.out.println("Indique <password> " + " <fichero_encriptado> [<fichero_plano>]" + " como argumento");
			return;
		}
		if (!parametros[1].endsWith(".des")) {
			System.out.println("Los ficheros encriptados" + " deben tener la extension .des");
			return;
		}

		// Abrimos los ficheros
		System.out.print("Abriendo fichero...");
		DataInputStream fichero_encriptado = new DataInputStream(new FileInputStream(parametros[1]));
		FileOutputStream fichero_plano;
		if (parametros.length == 2)
			fichero_plano = new FileOutputStream(parametros[1].substring(0, parametros[1].length() - 4));
		else
			fichero_plano = new FileOutputStream(parametros[2]);

		// Generamos una clave secreta a partir
		// del password
		System.out.print("\rGenerando clave secreta");
		PBEKeySpec objeto_password = new PBEKeySpec(parametros[0].toCharArray());
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey clave_secreta = skf.generateSecret(objeto_password);

		// Leemos los parametros encoded
		int longitud_encoded = fichero_encriptado.readInt();
		byte[] encoded = new byte[longitud_encoded];
		fichero_encriptado.read(encoded);
		AlgorithmParameters ap = AlgorithmParameters.getInstance("PBEWithMD5AndDES");
		ap.init(encoded);

		// Creamos el cifrador
		Cipher cifrador = Cipher.getInstance("PBEWithMD5andDES");
		cifrador.init(Cipher.DECRYPT_MODE, clave_secreta, ap);

		// Desencriptamos el contenido del fichero
		// encriptado y lo pasamos al fichero plano
		System.out.print("\rDesencriptando fichero...");
		byte[] buffer = new byte[TAMANO_BUFFER];
		int bytes_leidos = fichero_encriptado.read(buffer);
		while (bytes_leidos > 0) {
			fichero_plano.write(cifrador.update(buffer, 0, bytes_leidos));
			bytes_leidos = fichero_encriptado.read(buffer);
		}
		fichero_plano.write(cifrador.doFinal());
		// Cerramos los ficheros
		fichero_encriptado.close();
		fichero_plano.close();
		System.out.println("\rHecho                   ");

		System.out.println("\n- Contenido del fichero desencriptado -");
		lectura(archivo);
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
