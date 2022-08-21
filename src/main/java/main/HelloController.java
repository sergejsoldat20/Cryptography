package main;

import Model.User;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class HelloController {

    @FXML
    public PasswordField passwordField;

    @FXML
    public TextField usernameField;

    @FXML
    public Button loginButton;

    @FXML
    public TextField newUsername;

    @FXML
    public PasswordField newPassword;

    @FXML
    public Button addNewUser;


    @FXML
    public void setLoginButton(MouseEvent event){
        String newName = usernameField.getText();
        String newPass = passwordField.getText();
        if(User.login(newName,newPass)){
            showNewScene();
        }
    }

    @FXML
    public void setAddNewUser(MouseEvent event){
        String newName = newUsername.getText();
        String newPass = newPassword.getText();
        User.addNewUser(newName,newPass);

    }

    public void showNewScene() {
        try {
            Stage newWindow = new Stage();
            newWindow.initModality(Modality.APPLICATION_MODAL);
            FXMLLoader loader = new FXMLLoader(getClass().getResource("QuizView.fxml"));
            QuizController controller = new QuizController();
            Parent root = loader.load();
            Scene scene = new Scene(root);
            newWindow.setScene(scene);
            newWindow.show();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }


}