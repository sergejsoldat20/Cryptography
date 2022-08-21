package Model;

import javafx.beans.property.IntegerProperty;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Quiz {

    public static final String PHOTOS_PATH = "Photos";
   // public static final String QUESTIONS_PATH = "Questions.txt";
    public static ArrayList<Question> allQuestions = new ArrayList<>();
    public static Random random = new Random();


    public static ArrayList<Question> getRandomQuestions() {
        ArrayList<Question> result = new ArrayList<>();
        ArrayList<Integer> qNumbers = new ArrayList<>();
        int numberOfQuestions = 5;
        while(numberOfQuestions > 0){
            int qNumber = random.nextInt(20) + 1;
            if(!qNumbers.contains(qNumber)){
                qNumbers.add(qNumber);
                numberOfQuestions--;
            }
        }
        for(int i = 0; i < 5; i++){
            for(Question q : allQuestions){
                if(q.number == qNumbers.get(i)){
                    result.add(q);
                    System.out.println(q);
                }
            }
        }
        return result;
    }

    public static void getAllQuestions(){
        for(int i = 1; i < 21; i++) {
            String question = Steganography.decode(new File(PHOTOS_PATH + File.separator + i + "_stego.bmp"));
            String[] parsedQuestion = question.split("#");
            Question q = new Question(Integer.parseInt(parsedQuestion[0]), parsedQuestion[1], parsedQuestion[2]);
          //  System.out.println(q);
            allQuestions.add(q);
        }
    }

    public static boolean checkAnswer(Question question, String answer){
        if(question.getAnswer().equals(answer)){
            return true;
        } else {
            return false;
        }
    }

    public static void main(String args[]) throws Exception {

        /*List<String> allLines = Files.readAllLines(Paths.get(QUESTIONS_PATH));
        allLines.stream().forEach(System.out::println);
        for(int i = 1; i < 21; i++){
           String s =  Steganography.decode(new File(PHOTOS_PATH + File.separator + i + "_stego.bmp"));
           System.out.println(s);
        }*/
        getAllQuestions();
        getRandomQuestions();

    }
}
