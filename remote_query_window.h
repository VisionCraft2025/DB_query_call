#pragma once

#include <QtWidgets/QMainWindow>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDateTimeEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QProgressBar>
#include <QtCore/QTimer>
#include <QtMqtt/QMqttClient>
#include <QtMqtt/QMqttMessage>
#include <QtMqtt/QMqttSubscription>
#include <nlohmann/json.hpp>
#include <memory>

using json = nlohmann::json;

class RemoteQueryWindow : public QMainWindow
{
    Q_OBJECT

public:
    RemoteQueryWindow(QWidget *parent = nullptr);
    ~RemoteQueryWindow();

private slots:
    void onQueryClicked();
    void onConnectClicked();
    void onClearClicked();
    void checkMqttConnection();
    void onMqttError(QMqttClient::ClientError error);

private:
    void setupUI();
    void connectToMqtt();
    void sendQuery();
    void displayResults(const json& results);
    void updateConnectionStatus(bool connected);
    std::string generateQueryId();
    void onMqttConnected();
    void onMqttDisconnected();
    void onMqttMessageReceived(const QMqttMessage &message);
    void onLogMessageReceived(const QMqttMessage &message);
    void addLogToTable(const json& logData);
    bool matchesCurrentFilters(const json& logData);
    void subscribeToLogs();
    void unsubscribeFromLogs();

    // UI Components
    QWidget* m_centralWidget;
    QVBoxLayout* m_mainLayout;
    
    // Connection Controls
    QLineEdit* m_brokerEdit;
    QPushButton* m_connectButton;
    QLabel* m_connectionStatus;
    
    // Query Controls
    QComboBox* m_deviceCombo;
    QComboBox* m_logLevelCombo;
    QComboBox* m_logCodeCombo;
    QComboBox* m_severityCombo;
    QDateTimeEdit* m_startTime;
    QDateTimeEdit* m_endTime;
    QLineEdit* m_limitEdit;
    QPushButton* m_queryButton;
    QPushButton* m_clearButton;
    
    // Results
    QTableWidget* m_resultsTable;
    QTextEdit* m_detailsText;
    QLabel* m_statusLabel;
    QProgressBar* m_progressBar;

    // MQTT
    QMqttClient* m_mqttClient;
    QMqttSubscription* m_subscription;
    QMqttSubscription* m_logSubscription;
    QString m_clientId;
    QString m_currentQueryId;
    QTimer* m_connectionTimer;
    bool m_isConnected;
    bool m_autoReconnect;
    bool m_realTimeEnabled;
};
