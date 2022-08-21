module main.kriptografija_sergej_soldat {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.desktop;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires java.sql;


    opens main to javafx.fxml;
    exports main;
}