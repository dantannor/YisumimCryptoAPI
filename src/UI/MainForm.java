package UI;

import java.awt.EventQueue;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTabbedPane;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.filechooser.FileNameExtensionFilter;

import Logic.CryptoLogic;

import java.awt.Label;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class MainForm
{
    
    private JFrame         frame;
    private JTextField     textFieldFileToEncrypt;
    private JTextField     textFieldResultEncrypt;
    private JTextField     textFieldKeyStorePath;
    private JTextField     textFieldKeyStoreAlias;
    private JPasswordField passwordFieldEncrypt;
    private JTextField     textFieldFileToDecrypt;
    private JTextField     textFieldConfigurationPath;
    private JTextField     textFieldKeystoreDecrypt;
    private JTextField     textFieldKeystoreAliasDecrypt;
    private JPasswordField passwordFieldKeyStoreDecrypt;
    private JTextField     textFieldSavePathResult;
    
    /**
     * Launch the application.
     */
    public static void main(String[] args)
    {
        EventQueue.invokeLater(new Runnable()
        {
            public void run()
            {
                try
                {
                    MainForm window = new MainForm();
                    window.frame.setVisible(true);
                } catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        });
    }
    
    /**
     * Create the application.
     */
    public MainForm()
    {
        initialize();
    }
    
    /**
     * Initialize the contents of the frame.
     */
    private void initialize()
    {
        frame = new JFrame();
        frame.setBounds(100, 100, 418, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(
                new BoxLayout(frame.getContentPane(), BoxLayout.X_AXIS));
        
        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        frame.getContentPane().add(tabbedPane);
        
        JPanel panelEncrypt = new JPanel();
        tabbedPane.addTab("Encrypt", null, panelEncrypt, null);
        panelEncrypt.setLayout(null);
        
        textFieldFileToEncrypt = new JTextField();
        textFieldFileToEncrypt.setColumns(10);
        textFieldFileToEncrypt.setBounds(122, 12, 200, 20);
        panelEncrypt.add(textFieldFileToEncrypt);
        
        Label label_1 = new Label("File to encrypt");
        label_1.setBounds(10, 12, 90, 19);
        panelEncrypt.add(label_1);
        
        JButton buttonFileToEncrypt = new JButton("...");
        buttonFileToEncrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Text File", "txt");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonFileToEncrypt);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldFileToEncrypt.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonFileToEncrypt.setBounds(332, 11, 45, 23);
        panelEncrypt.add(buttonFileToEncrypt);
        
        textFieldResultEncrypt = new JTextField();
        textFieldResultEncrypt.setColumns(10);
        textFieldResultEncrypt.setBounds(122, 44, 200, 20);
        panelEncrypt.add(textFieldResultEncrypt);
        
        Label label_2 = new Label("File Result");
        label_2.setBounds(10, 44, 90, 19);
        panelEncrypt.add(label_2);
        
        JButton buttonResultEncrypt = new JButton("...");
        buttonResultEncrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Text File", "txt");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showSaveDialog(buttonResultEncrypt);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldResultEncrypt.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonResultEncrypt.setBounds(332, 43, 45, 23);
        panelEncrypt.add(buttonResultEncrypt);
        
        textFieldKeyStorePath = new JTextField();
        textFieldKeyStorePath.setColumns(10);
        textFieldKeyStorePath.setBounds(122, 76, 200, 20);
        panelEncrypt.add(textFieldKeyStorePath);
        
        Label label_3 = new Label("KeyStore Path");
        label_3.setBounds(10, 76, 90, 19);
        panelEncrypt.add(label_3);
        
        JButton buttonGetKeyStorePath = new JButton("...");
        buttonGetKeyStorePath.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Key Store File", "jks");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonResultEncrypt);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldKeyStorePath.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonGetKeyStorePath.setBounds(332, 75, 45, 23);
        panelEncrypt.add(buttonGetKeyStorePath);
        
        textFieldKeyStoreAlias = new JTextField();
        textFieldKeyStoreAlias.setColumns(10);
        textFieldKeyStoreAlias.setBounds(122, 108, 200, 20);
        panelEncrypt.add(textFieldKeyStoreAlias);
        
        Label label_4 = new Label("KS Alias");
        label_4.setBounds(10, 108, 90, 19);
        panelEncrypt.add(label_4);
        
        passwordFieldEncrypt = new JPasswordField();
        passwordFieldEncrypt.setBounds(122, 140, 200, 20);
        panelEncrypt.add(passwordFieldEncrypt);
        
        Label label_5 = new Label("KS Password");
        label_5.setBounds(10, 140, 80, 19);
        panelEncrypt.add(label_5);
        
        JButton buttonStartEncrypt = new JButton("Encrypt");
        buttonStartEncrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                String inputPath = textFieldFileToEncrypt.getText();
                String outputPath = textFieldResultEncrypt.getText();
                String keyStore = textFieldKeyStorePath.getText();
                String keyStoreAlias = textFieldKeyStoreAlias.getText();
                String keyStorePassword = new String(passwordFieldEncrypt
                        .getPassword());
                
                if ((inputPath == "") || (outputPath == "") || (keyStore == "")
                        || (keyStoreAlias == "") || (keyStorePassword == ""))
                {
                    JOptionPane.showMessageDialog(buttonStartEncrypt,
                            "Please check input variable ");
                } else
                {
                    try
                    {
                        CryptoLogic cryptoLogic = new CryptoLogic(keyStore,
                                keyStoreAlias, keyStorePassword);
                        cryptoLogic.Encrypt(inputPath, outputPath);
                        
                        JOptionPane.showMessageDialog(buttonStartEncrypt,
                                "Greate success");
                    } catch (Exception e2)
                    {
                        JOptionPane.showMessageDialog(buttonStartEncrypt,
                                "Encrypt Fail " + e2.getMessage());
                    }
                }
            }
        });
        buttonStartEncrypt.setBounds(286, 193, 89, 23);
        panelEncrypt.add(buttonStartEncrypt);
        
        JPanel panelDecrypt = new JPanel();
        tabbedPane.addTab("Decrypt", null, panelDecrypt, null);
        panelDecrypt.setLayout(null);
        
        Label label_6 = new Label("File to Decrypt");
        label_6.setBounds(10, 12, 90, 19);
        panelDecrypt.add(label_6);
        
        textFieldFileToDecrypt = new JTextField();
        textFieldFileToDecrypt.setColumns(10);
        textFieldFileToDecrypt.setBounds(122, 12, 200, 20);
        panelDecrypt.add(textFieldFileToDecrypt);
        
        JButton buttonLoadFileToDecrypt = new JButton("...");
        buttonLoadFileToDecrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Text File", "txt");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonLoadFileToDecrypt);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldFileToDecrypt.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonLoadFileToDecrypt.setBounds(332, 11, 45, 23);
        panelDecrypt.add(buttonLoadFileToDecrypt);
        
        JButton buttonLoadConfigurationPath = new JButton("...");
        buttonLoadConfigurationPath.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Config File", "xml");
                chooser.setFileFilter(filter);
                int returnVal = chooser
                        .showOpenDialog(buttonLoadConfigurationPath);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldConfigurationPath.setText(chooser
                            .getSelectedFile().toString());
                }
            }
        });
        buttonLoadConfigurationPath.setBounds(332, 43, 45, 23);
        panelDecrypt.add(buttonLoadConfigurationPath);
        
        textFieldConfigurationPath = new JTextField();
        textFieldConfigurationPath.setColumns(10);
        textFieldConfigurationPath.setBounds(122, 44, 200, 20);
        panelDecrypt.add(textFieldConfigurationPath);
        
        Label label_7 = new Label("Config File");
        label_7.setBounds(10, 44, 90, 19);
        panelDecrypt.add(label_7);
        
        Label label_8 = new Label("KeyStore Path");
        label_8.setBounds(10, 108, 90, 19);
        panelDecrypt.add(label_8);
        
        textFieldKeystoreDecrypt = new JTextField();
        textFieldKeystoreDecrypt.setColumns(10);
        textFieldKeystoreDecrypt.setBounds(122, 108, 200, 20);
        panelDecrypt.add(textFieldKeystoreDecrypt);
        
        JButton buttonKeystoreDecrypt = new JButton("...");
        buttonKeystoreDecrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Key Store File", "jks");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(buttonKeystoreDecrypt);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldKeystoreDecrypt.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonKeystoreDecrypt.setBounds(332, 107, 45, 23);
        panelDecrypt.add(buttonKeystoreDecrypt);
        
        textFieldKeystoreAliasDecrypt = new JTextField();
        textFieldKeystoreAliasDecrypt.setColumns(10);
        textFieldKeystoreAliasDecrypt.setBounds(122, 141, 200, 20);
        panelDecrypt.add(textFieldKeystoreAliasDecrypt);
        
        Label label_9 = new Label("KS Alias");
        label_9.setBounds(10, 142, 90, 19);
        panelDecrypt.add(label_9);
        
        Label label_10 = new Label("KS Password");
        label_10.setBounds(10, 167, 80, 19);
        panelDecrypt.add(label_10);
        
        passwordFieldKeyStoreDecrypt = new JPasswordField();
        passwordFieldKeyStoreDecrypt.setBounds(122, 167, 200, 20);
        panelDecrypt.add(passwordFieldKeyStoreDecrypt);
        
        JButton btnDecrypt = new JButton("Decrypt");
        btnDecrypt.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                String inputFile = textFieldFileToDecrypt.getText();
                String configFile = textFieldConfigurationPath.getText();
                String resultFile = textFieldSavePathResult.getText();
                
                String keyStore = textFieldKeystoreDecrypt.getText();
                String keyStoreAlias = textFieldKeystoreAliasDecrypt.getText();
                String keyStorePassword = new String(
                        passwordFieldKeyStoreDecrypt.getPassword());
                
                if ((inputFile == "") || (configFile == "")
                        || (resultFile == "") || (keyStore == "")
                        || (keyStoreAlias == "") || (keyStorePassword == ""))
                {
                    JOptionPane.showMessageDialog(buttonStartEncrypt,
                            "Please check input variable ");
                } else
                {
                    try
                    {
                        CryptoLogic cryptoLogic = new CryptoLogic(keyStore,
                                keyStoreAlias, keyStorePassword);
                        cryptoLogic.Decrypt(inputFile, configFile, resultFile);
                        
                        JOptionPane.showMessageDialog(buttonStartEncrypt,
                                "Great success");
                    } 
                    catch (Exception e2)
                    {
                        JOptionPane.showMessageDialog(buttonStartEncrypt,
                                "Decrypt Fail " + e2.getMessage());
                    }
                }
            }
        });
        btnDecrypt.setBounds(288, 193, 89, 23);
        panelDecrypt.add(btnDecrypt);
        
        JButton buttonSaveFileResult = new JButton("...");
        buttonSaveFileResult.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Text file", "txt");
                chooser.setFileFilter(filter);
                int returnVal = chooser
                        .showSaveDialog(buttonLoadConfigurationPath);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textFieldSavePathResult.setText(chooser.getSelectedFile()
                            .toString());
                }
            }
        });
        buttonSaveFileResult.setBounds(332, 79, 45, 23);
        panelDecrypt.add(buttonSaveFileResult);
        
        textFieldSavePathResult = new JTextField();
        textFieldSavePathResult.setColumns(10);
        textFieldSavePathResult.setBounds(122, 80, 200, 20);
        panelDecrypt.add(textFieldSavePathResult);
        
        Label label = new Label("File Result");
        label.setBounds(10, 80, 90, 19);
        panelDecrypt.add(label);
    }
}
