package main;

import Model.Quiz;
import Service.CryptoService;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Quiz.getAllQuestions();
        CryptoService.createCRL();
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("hello-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 400, 400);
       // stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}