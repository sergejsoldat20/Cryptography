package Model;

public class Question {

    private String question;
    private String answer;
    public int number;

    public Question(int number, String question, String answer) {
        this.answer = answer;
        this.question = question;
        this.number = number;
    }

    public String getAnswer() {
        return answer;
    }

    public String getQuestion() {
        return question;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    @Override
    public String toString() {
        return "Question{" +
                "question='" + question + '\'' +
                ", answer='" + answer + '\'' +
                ", number=" + number +
                '}';
    }
}
