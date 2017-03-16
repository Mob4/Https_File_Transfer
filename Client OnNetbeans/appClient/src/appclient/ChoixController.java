/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package appclient;

import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javax.swing.JFileChooser;

/**
 *
 * @author Groupe 7
 */
public class ChoixController implements Initializable {
    @FXML
        private Label labelmsg,errorUpload,errorDownload;
    @FXML
        private TextField downloadTextField,uploadTextField,cheminUpload,cheminDownload;
    @FXML
        private Button btnDownload;
    @FXML
        private Button btnUpload;
    @FXML
        private Button parcourirUpload;
    @FXML
        private Button parcourirDownload;
    @FXML
        private Parent ChoixPane;
    
    private String url="https://localhost:7878/fileserver";
    private static ChoixController instance;

    public ChoixController() {
        instance = this;
    }
    
    public static ChoixController getInstance() {
        return instance;
    }
    
    @FXML
    private void uploadAction(ActionEvent event)  throws IOException, Exception {        
        
            if(!cheminUpload.getText().isEmpty())
            {
                File fileName = new File(cheminUpload.getText());
                
                if(fileName.exists())
                {
                    URI uri = new URI(url+"?upload="+URLEncoder.encode(fileName.getName(), "UTF-8"));

                    Listener listener = new Listener(uri.toString(),fileName.getPath(),"POST");

                    Thread x = new Thread(listener);
                    x.start();

                    System.out.println("You chose " + uri.toString());
                    //lancer fonction du listener pour uploader le fichier
                }
            }else{
                errorUpload.setText("Vous devez choisir un fichier");
            }
        
    }
    
    @FXML
    private void choisirFichier(ActionEvent event)  throws IOException, Exception {        
        JFileChooser fileChooser = new JFileChooser();
        String userDir = System.getProperty("user.home");
        fileChooser.setCurrentDirectory(new File(userDir +"/Desktop"));
        int result = fileChooser.showOpenDialog(null);
        
        if ( result == JFileChooser.APPROVE_OPTION )
        {
            String nomFichier = fileChooser.getSelectedFile().toString();
            cheminUpload.setText(nomFichier);
            File fileName = new File(nomFichier);  
            URI uri = new URI(url+"?upload="+URLEncoder.encode(fileName.getName(), "UTF-8"));
            uploadTextField.setText(uri.toString());
            errorUpload.setText("");
        }else{
            System.out.println("You cancelled the choice");
        }
    }
    
    @FXML
    private void downloadAction(ActionEvent event)  throws IOException, Exception {        
        if(!cheminDownload.getText().isEmpty())
        {
            File fileName = new File(cheminDownload.getText());
            Listener listener = new Listener(downloadTextField.getText(),fileName.getPath(),"GET");
            Thread x = new Thread(listener);
            x.start();
       
        }else{
            errorDownload.setText("Vous devez choisir la destination");
        }
    }
    
    @FXML
    private void choisirDossier(ActionEvent event)  throws IOException, Exception {        
        JFileChooser fileChooser = new JFileChooser();
        String userDir = System.getProperty("user.home");
        fileChooser.setCurrentDirectory(new File(userDir +"/Desktop"));
        
        fileChooser.setFileFilter( new FolderFilter() );
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.setDialogTitle("Enregistrer sous...");
        int result = fileChooser.showOpenDialog(null);
        
        if ( result == JFileChooser.APPROVE_OPTION )
        {
            String nomFichier = fileChooser.getSelectedFile().toString();
            cheminDownload.setText(nomFichier);
            errorDownload.setText("");            
        }else{
            System.out.println("You cancelled the choice");
        }
    }
    
    public void showMsg(String msg){
        Platform.runLater(() -> {
            labelmsg.setText(msg);
        });
    }
    
    private static class FolderFilter extends javax.swing.filechooser.FileFilter {
      @Override
      public boolean accept( File file ) {
        return file.isDirectory();
      }

      @Override
      public String getDescription() {
        return "Vous pouvez selectionner que un dossier";
      }
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
    }    
    
}