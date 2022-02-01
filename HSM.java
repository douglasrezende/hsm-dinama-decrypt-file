package br.douglasrezende.hsm.dinamo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;

public class HSM {

	static final String USER_PASSWORD_SEPARATOR =":";
	static final String PASSWORD_HOST_SEPARATOR ="@";
	static final String B2BWORKFLOWID_FILENAME_SEPARATOR = "_";

	public static void main( String[] args ) throws
	KeyStoreException, NoSuchProviderException,
	NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, TacException
	{
		String b2bWorkFlowId = "";
		String hsmPassword = "";
		String keyAlias = "";
		String hsmUser = "";
		String hsmHost = "";
		String encryptedFileSource = "";
		String decryptedFileDestination = "";

		if(args.length > 0){
			b2bWorkFlowId = B2BWORKFLOWID_FILENAME_SEPARATOR + args[0];
			b2bWorkFlowId = b2bWorkFlowId.trim();
			hsmHost =  args[1];
			hsmHost = hsmHost.trim();
			hsmUser  = args[2];
			hsmUser = hsmUser.trim();
			hsmPassword = args[3];
			hsmPassword = hsmPassword.trim();
			keyAlias = args[4];
			keyAlias = keyAlias.trim();
			encryptedFileSource = args[5];
			encryptedFileSource = encryptedFileSource.trim();
			decryptedFileDestination = args[6];
			decryptedFileDestination = decryptedFileDestination.trim();
		}else {
			System.out.println("ERROR: Necessario informar os parametros: "+ System.lineSeparator() +
					"B2B WorkflowId" +
					System.lineSeparator() +
					"HSM HOST" +
					System.lineSeparator()+
					"HSM USER" +
					System.lineSeparator()+
					"HSM PASSWORD" + System.lineSeparator() +
					"KEY ALIAS"+ System.lineSeparator() + 
					"DIRETORIO DO ARQUIVO CRIPTOGRADO"+System.lineSeparator()+
					"DIRETORIO DO ARQUIVO DESCRIPTOGRADO");
			System.exit(1);
		}


		sendKeyToDecrypt(keyAlias, hsmUser,hsmPassword,hsmHost,encryptedFileSource,decryptedFileDestination,
				b2bWorkFlowId );

	}

	private static void sendKeyToDecrypt(String keyAlias, String hsmUser
			,String hsmPassword,String hsmHost,
			String encryptedFileSource, String decryptedFileDestination,String b2bWorkFlowId ) throws TacException, IOException {

		Dinamo api = new Dinamo();
		try{
			api.openSession(hsmHost, hsmUser, hsmPassword, false);

			byte[] encBlock = Files
					.readAllBytes(Paths.get(encryptedFileSource+b2bWorkFlowId));

			byte[] decBlock = api.decrypt(keyAlias, encBlock, TacNDJavaLib.D_FORCE_ACTUAL_RSA);

			File file = new File(decryptedFileDestination+b2bWorkFlowId);
			FileOutputStream in = new FileOutputStream(file);
			in.write(decBlock);
			in.close();
			System.out.println("Descriptografia do arquivo executada com sucesso, arquivo disponivel no diretorio: "
					+decryptedFileDestination+b2bWorkFlowId);
		}catch(Exception ex){
			ex.printStackTrace();
		}finally{
			api.closeSession();   
		}

	}

}
