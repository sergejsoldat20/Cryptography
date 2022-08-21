package main;

import Model.Question;
import Model.Quiz;
import Model.User;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;

import java.awt.event.ActionEvent;
import java.util.ArrayList;

public class QuizController {

    public static ArrayList<Question> quizQuestions = new ArrayList<>();

    @FXML
    public Button logOut;
    @FXML
    public Button submit;

    @FXML
    public TextArea questions;

    @FXML
    public TextField questionOneAnswer;

    @FXML
    public TextField questionTwoAnswer;

    @FXML
    public TextField questionThreeAnswer;

    @FXML
    public TextField questionFourAnswer;

    @FXML
    public TextField questionFiveAnswer;

    @FXML
    public Button showResults;

    @FXML
    public TextArea results;

    @FXML
    void initialize(){
        String text = "Putanja do klijentskog sertifikata je: Priprema/Usercerts/" + User.loggedUser.get(0).username + ".p12" + "\n";
        for(Question q : Quiz.getRandomQuestions()){
            text += q.getQuestion() + "\n";
            quizQuestions.add(q);
        }
        questions.setText(text);
    }

  /*  @FXML
    public void setSubmit(ActionEvent event){
        String[] answers = new String[]{questionOneAnswer.getText(),questionTwoAnswer.getText(),
        questionThreeAnswer.getText(), questionFourAnswer.getText(), questionFiveAnswer.getText()};
        int i = 0;
        int correctAnswersCount = 0;
        for(Question q : quizQuestions){
            if(q.getAnswer().equals(answers[i])){
                correctAnswersCount++;
            }
        }
        System.out.println();
    }*/


   /* @FXML
    public void setShowResults(MouseEvent event){
        System.out.println("radi dugmeeeeee");
    }*/

    @FXML
    public void setOnActionButton(MouseEvent event){
        String[] answers = new String[]{questionOneAnswer.getText(),questionTwoAnswer.getText(),
                questionThreeAnswer.getText(), questionFourAnswer.getText(), questionFiveAnswer.getText()};
        int i = 0;
        int correctAnswersCount = 0;

        System.out.println(quizQuestions.size() + " - VELICINA QUIZQUESTIONS");
        for(Question q : quizQuestions) {
            if (q.getAnswer().equals(answers[i])) {
                correctAnswersCount++;
            }
            i++;
        }
        quizQuestions.clear();
        System.out.println(quizQuestions.size() + " - VELICINA QUIZQUESTIONS NAKON BRISANJA");

        User.loggedUser.get(0).result += correctAnswersCount;
        User.writeResults(User.loggedUser.get(0));
        System.out.println(correctAnswersCount);

    }

    @FXML
    public void setOnActionLogOut(MouseEvent event){
        User.logout();
        questions.setText("");
        /*String text = "";
        for(Question q : Quiz.getRandomQuestions()){
            text += q.getQuestion() + "\n";
            quizQuestions.add(q);
        }
        questions.setText(text);*/
        Stage stage = (Stage) logOut.getScene().getWindow();
        stage.close();
    }

    @FXML
    public void setOnActionShowResults(MouseEvent event) {
        results.setText(User.getAllResults());
    }
}
