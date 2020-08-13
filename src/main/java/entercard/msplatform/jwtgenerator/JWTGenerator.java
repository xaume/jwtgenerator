package entercard.msplatform.jwtgenerator;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * @author jajimene
 *
 */
public class JWTGenerator {

  private static final String KEYSET_FILE = "jwt-keyset.json";

  private static final String KEY_ID = "local";

  private static final String ISSUER = "https://ecapit.entercard.com";

  private static final String SUB = "entercard";

  private static JWSSigner signer;

  private static RSAKey rsaJWK;

  private static JTextArea textArea;

  /**
   *
   * @param args
   * @throws ClassNotFoundException
   * @throws InstantiationException
   * @throws IllegalAccessException
   * @throws UnsupportedLookAndFeelException
   */
  public static void main(String[] args)
      throws ClassNotFoundException, InstantiationException, IllegalAccessException, UnsupportedLookAndFeelException {

    if (args.length > 0) {
      System.out.println(
          "Usage: java -jar jwtgenerator.jar <sub:entercard> <issuer:https://ecapit.entercard.com> <expiresin:60000>");
    }

    initializeSigner();

    /**
     * JAVA SWING
     */

    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

    JFrame frame = new JFrame("JWT Generator");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(640, 320);

    JPanel contentPane = new JPanel(new BorderLayout());

    JToolBar toolbar = new JToolBar("Still draggable");
    toolbar.setFloatable(false);

    textArea = new JTextArea();
    textArea.setLineWrap(true);
    textArea.setMargin(new Insets(5, 5, 5, 5));

    JButton generateBtn = new JButton("Generate");
    Font font = generateBtn.getFont();
    Font newButtonFont = new Font(font.getName(), font.getStyle(), 15);
    generateBtn.setFont(newButtonFont);
    generateBtn.addActionListener(new ActionListener() {

      public void actionPerformed(ActionEvent e) {

        textArea.setText(createJWT());
      }
    });

    ImageIcon icon = createImageIcon("copy.png", "Copy");
    JButton copyButton = new JButton("Copy", icon);
    copyButton.setFont(newButtonFont);
    copyButton.addActionListener(new ActionListener() {

      public void actionPerformed(ActionEvent e) {

        StringSelection stringSelection = new StringSelection(textArea.getText());
        Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
        clpbrd.setContents(stringSelection, null);

        // Components changes for UI feedback
        textArea.grabFocus();
        textArea.selectAll();

      }
    });

    toolbar.add(Box.createHorizontalGlue());
    toolbar.add(generateBtn);
    toolbar.addSeparator();
    toolbar.add(copyButton);

    contentPane.add(textArea, BorderLayout.CENTER);
    contentPane.add(toolbar, BorderLayout.SOUTH);

    frame.setContentPane(contentPane);
    frame.setVisible(true);

    // // On the consumer side, parse the JWS and verify its RSA signature
    // RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();
    // signedJWT = SignedJWT.parse(s);
    //
    // JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
    // log.info("Verified JWT? {}", signedJWT.verify(verifier));
  }

  private static void initializeSigner() {

    try {

      JWKSet localKeys = JWKSet.load(JWTGenerator.class.getClassLoader().getResourceAsStream(KEYSET_FILE));
      JWK signatureKey = localKeys.getKeyByKeyId(KEY_ID);

      rsaJWK = (RSAKey) signatureKey;

      // Create RSA-signer with the private key
      signer = new RSASSASigner(rsaJWK.toPrivateKey());

    } catch (IOException e) {
      e.printStackTrace();
    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }

  }

  /**
   *
   * @return
   * @throws IOException
   * @throws ParseException
   * @throws JOSEException
   */
  private static String createJWT() {

    String jwt = "";

    try {

      // Prepare JWT with claims set
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(SUB)
          .issuer(ISSUER)
          .expirationTime(new Date(new Date().getTime() + 60 * 1000))
          .build();

      SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
          claimsSet);

      // Compute the RSA signature
      signedJWT.sign(signer);

      jwt = signedJWT.serialize();

      // Output in URL-safe format
      System.out.println(jwt);

    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return jwt;
  }

  /** Returns an ImageIcon, or null if the path was invalid. */
  private static ImageIcon createImageIcon(String path, String description) {

    java.net.URL imgURL = JWTGenerator.class.getClassLoader().getResource(path);
    if (imgURL != null) {
      return new ImageIcon(imgURL, description);
    } else {
      System.err.println("Couldn't find file: " + path);
      return null;
    }
  }

}
