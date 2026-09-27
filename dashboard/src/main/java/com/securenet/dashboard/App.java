package com.securenet.dashboard;

import java.io.IOException;
import java.util.Objects;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * SecureNet Lab desktop dashboard.
 *
 * <p>Run: {@code mvn clean javafx:run}. Point it at the monitor VM's API with
 * {@code SECURENET_API_URL=http://192.168.56.30:8000} (or -Dsecurenet.api=...).
 */
public class App extends Application {

    private DashboardController controller;

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader loader = new FXMLLoader(
                Objects.requireNonNull(App.class.getResource("/fxml/dashboard.fxml")));
        Parent root = loader.load();
        controller = loader.getController();

        Scene scene = new Scene(root, 1280, 820);
        scene.getStylesheets().add(
                Objects.requireNonNull(App.class.getResource("/css/dashboard.css")).toExternalForm());
        stage.setTitle("SecureNet Lab - Dashboard");
        stage.setScene(scene);
        stage.show();

        controller.start(new ApiClient(ApiClient.configuredBaseUrl()));
    }

    @Override
    public void stop() {
        if (controller != null) {
            controller.stop();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
