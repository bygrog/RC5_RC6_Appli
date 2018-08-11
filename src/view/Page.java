/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package view;

import control.RC5;
import control.RC6;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author D4
 */
public class Page extends javax.swing.JFrame {

    /**
     * Creates new form Page
     */
    private String plaintxt = "";
    private String ciphertxt = "";
    public Page() {
        initComponents();
        //this.setIconImage(new ImageIcon(getClass().getResource("white_ninja.ico")).getImage());
        ButtonGroup bg1 = new ButtonGroup( );
        jRadioButton1.setSelected(true);
        jTextPane1.setEditable(false);
        bg1.add(jRadioButton1);
        bg1.add(jRadioButton2);
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jTextField2 = new javax.swing.JTextField();
        jButton2 = new javax.swing.JButton();
        jRadioButton1 = new javax.swing.JRadioButton();
        jRadioButton2 = new javax.swing.JRadioButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextPane1 = new javax.swing.JTextPane();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem3 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        jLabel1.setText("Plain File");

        jButton1.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        jButton1.setText("ENCYRPT");
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton1MouseClicked(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        jLabel2.setText("Cipher File");

        jButton2.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        jButton2.setText("SAVE");
        jButton2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton2MouseClicked(evt);
            }
        });

        jRadioButton1.setText("RC5");

        jRadioButton2.setText("RC6");

        jTextPane1.setText("BIENVENUE A L'ECOLE NATIONALE SUPERIEURE DES POSTES, DES TELECOMMUNICATIONS ET DES TECHNOLOGIES DE L’INFORMATIONS ET DE LA COMMUNICATIONS.\n\tLes étudiants en formations en cycle d'ingénieur des télécommunications de la promotion 2017 2019 à la suite de leur cours intitulé “FONDAMENTAUX DE SECURITE, SIGNATURE NUMERIQUE, CRYPTOGRAPHIE, FONCTION HACHAGE\" ont développé chacun dans son groupe un logiciel de répondant à un algorithme de sécurité précis.  \n\tLe présent logiciel utilise le chiffrement et le déchiffrent avec le RC5 RC6. Il est développé par :  CHIAKUNG NDIFFOR ROGER, FOUBA BIENVENUE ARSENE ROGER, JIOGO KANA DELANO STEVEN, KEDI JOVANIE, KUETE BERRY ORIAN, tous étudiants en Master 1 à SUP'PTIC promotion 2017 2019.\n\t\t\t\t\t\tEnseignant : Dr BELL GEORGES\n");
        jScrollPane2.setViewportView(jTextPane1);

        jMenu1.setText("File");

        jMenuItem1.setText("Open");
        jMenuItem1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jMenuItem1MousePressed(evt);
            }
        });
        jMenu1.add(jMenuItem1);

        jMenuItem3.setText("Close");
        jMenuItem3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jMenuItem3MousePressed(evt);
            }
        });
        jMenu1.add(jMenuItem3);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Decrypt");
        jMenu2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jMenu2MouseClicked(evt);
            }
        });
        jMenuBar1.add(jMenu2);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(34, 34, 34)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 487, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel1))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jTextField1, javax.swing.GroupLayout.DEFAULT_SIZE, 374, Short.MAX_VALUE)
                            .addComponent(jTextField2))))
                .addContainerGap(42, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(jButton2)
                .addGap(214, 214, 214))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButton1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jRadioButton1)
                        .addGap(18, 18, 18)
                        .addComponent(jRadioButton2)))
                .addGap(203, 203, 203))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 192, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jRadioButton1)
                    .addComponent(jRadioButton2))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jButton1)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addGap(18, 18, 18)
                .addComponent(jButton2)
                .addGap(27, 27, 27))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jMenuItem1MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jMenuItem1MousePressed
        // TODO add your handling code here:
        JFileChooser c = new JFileChooser();
        // Demonstrate "Open" dialog:
        int rVal = c.showOpenDialog(Page.this);
        if (rVal == JFileChooser.APPROVE_OPTION) {
            String chemin = c.getCurrentDirectory().toString()+"\\"+c.getSelectedFile().getName();
            jTextField1.setText(chemin);
            try {
                BufferedReader in = new BufferedReader(new FileReader(chemin));
                //dir.setText(c.getCurrentDirectory().toString());
                String line;
                while((line = in.readLine()) != null)
                {
                    System.out.println(line);
                    plaintxt = plaintxt+line;
                }
                in.close();
                //c = null;
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Page.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Page.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (rVal == JFileChooser.CANCEL_OPTION) {
            jTextField1.setText("You pressed cancel");
            //dir.setText("");
        }
    }//GEN-LAST:event_jMenuItem1MousePressed

    private void jButton2MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton2MouseClicked
        // TODO add your handling code here:
        JFileChooser c = new JFileChooser();
        // Demonstrate "Save" dialog:
        int rVal = c.showSaveDialog(Page.this);
        if (rVal == JFileChooser.APPROVE_OPTION) {
        jTextField2.setText(c.getCurrentDirectory().toString()+"\\"+c.getSelectedFile().getName());
        //dir.setText(c.getCurrentDirectory().toString());
          try {
                System.out.println(c.getCurrentDirectory().toString()+"\\"+c.getSelectedFile().getName());
                FileWriter fw = new FileWriter(c.getCurrentDirectory().toString()+"\\"+c.getSelectedFile().getName());
                BufferedWriter bw = new BufferedWriter(fw);
                //FileWriter fileWriter = new FileWriter("temp.txt");
                //Formatter form = new Formatter(fw);
                //BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                //bufferedWriter.write("roger");
                if(ciphertxt.equals("")) JOptionPane.showMessageDialog(this,"EMPTY CIPHER TEXT","Error",JOptionPane.ERROR_MESSAGE); 
                else{ 
                    System.out.println(" ciphertext "+ciphertxt);
                    //form.format(ciphertxt);
                    bw.write(ciphertxt);
                    bw.flush();
                    bw.close();
                    fw.close();
                    //jTextField1.setText("");
                    ciphertxt = "";
                    JOptionPane.showMessageDialog(null, "FICHIER SAUVEGARDER");
              }
              //PrintWriter writer = new PrintWriter(printbyte(cipherbyte), "UTF-8");
              //fw.close();
          } catch (IOException ex) {
              Logger.getLogger(Page.class.getName()).log(Level.SEVERE, null, ex);
          }
      }
      if (rVal == JFileChooser.CANCEL_OPTION) {
        jTextField2.setText("You pressed cancel");
        //dir.setText("");
      }
    }//GEN-LAST:event_jButton2MouseClicked

    private void jButton1MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseClicked
        // TODO add your handling code here:
        JFrame frame = new JFrame();
        String message = "KEY";
        byte[] cipherbyte;
        String text = JOptionPane.showInputDialog(frame, message);
       
        if (text == null) {
            // User clicked cancel
            JOptionPane.showMessageDialog(this,"EMPTY","Error",JOptionPane.ERROR_MESSAGE); 
        }else{
            if(plaintxt.equals("")){
               JOptionPane.showMessageDialog(this,"AUCUNE FICHIER TEXT SELECTIONNER OU FICHIER VIDE","Error",JOptionPane.ERROR_MESSAGE);  
            }else{
                try {
                    if (jRadioButton1.isSelected()){
                        System.out.println("rc5");
                        cipherbyte = RC5.encrypt(plaintxt,text);
                        ciphertxt = printbyte(cipherbyte)+" :";
                    }else{
                        System.out.println("rc6");
                        cipherbyte = RC6.encrypt(plaintxt,text);
                        ciphertxt = printbyte(cipherbyte)+" ;";
                    }
                    JOptionPane.showMessageDialog(null, "FICHIER ENCRYPTER");  
                    plaintxt = "";
                } catch (Exception ex) {
                    Logger.getLogger(Page.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
        }
        // a jframe here isn't strictly necessary, but it makes the example a little more real
        
        //System.exit(0);
    
    }//GEN-LAST:event_jButton1MouseClicked

    private void jMenu2MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jMenu2MouseClicked
        // TODO add your handling code here:
        new Page1().setVisible(true);
        setVisible(false);
    }//GEN-LAST:event_jMenu2MouseClicked

    private void jMenuItem3MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jMenuItem3MousePressed
        // TODO add your handling code here:
        System.exit(0);
    }//GEN-LAST:event_jMenuItem3MousePressed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Page.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Page.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Page.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Page.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Page().setVisible(true);
            }
        });
    }
    public static String printbyte(byte[] bytetxt){
        String txt = "";
        int i;
        
        for(i=0;i<bytetxt.length-1;i++) txt = txt+bytetxt[i]+" ";
        txt = txt+bytetxt[i];
        return txt;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JRadioButton jRadioButton2;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextPane jTextPane1;
    // End of variables declaration//GEN-END:variables
}
