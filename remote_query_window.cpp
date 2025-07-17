#include "remote_query_window.h"
#include <QtWidgets/QApplication>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QGroupBox>
#include <QtCore/QDateTime>
#include <QtCore/QUuid>
#include <QtCore/QUrl>
#include <random>
#include <chrono>
#include <iostream>

RemoteQueryWindow::RemoteQueryWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_mqttClient(nullptr)
    , m_subscription(nullptr)
    , m_logSubscription(nullptr)
    , m_isConnected(false)
    , m_autoReconnect(false)
    , m_realTimeEnabled(false)
{
    // 고유한 클라이언트 ID 생성
    m_clientId = "remote_query_" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    
    setupUI();
    
    // MQTT 클라이언트 초기화
    m_mqttClient = new QMqttClient(this);
    m_mqttClient->setClientId(m_clientId);
    m_mqttClient->setKeepAlive(60); // Keep-alive 설정
    
    // MQTT 시그널 연결
    connect(m_mqttClient, &QMqttClient::connected, this, &RemoteQueryWindow::onMqttConnected);
    connect(m_mqttClient, &QMqttClient::disconnected, this, &RemoteQueryWindow::onMqttDisconnected);
    connect(m_mqttClient, &QMqttClient::errorChanged, this, &RemoteQueryWindow::onMqttError);
    
    m_connectionTimer = new QTimer(this);
    connect(m_connectionTimer, &QTimer::timeout, this, &RemoteQueryWindow::checkMqttConnection);
    m_connectionTimer->start(5000); // 5초마다 연결 상태 확인
}

RemoteQueryWindow::~RemoteQueryWindow()
{
    if (m_mqttClient && m_mqttClient->state() == QMqttClient::Connected) {
        m_mqttClient->disconnectFromHost();
    }
}

void RemoteQueryWindow::setupUI()
{
    m_centralWidget = new QWidget(this);
    setCentralWidget(m_centralWidget);
    
    m_mainLayout = new QVBoxLayout(m_centralWidget);
    
    // Connection Group
    auto* connectionGroup = new QGroupBox("MQTT Connection");
    auto* connectionLayout = new QHBoxLayout(connectionGroup);
    
    connectionLayout->addWidget(new QLabel("Broker:"));
    m_brokerEdit = new QLineEdit("mqtt.kwon.pics");
    connectionLayout->addWidget(m_brokerEdit);
    
    m_connectButton = new QPushButton("Connect");
    connectionLayout->addWidget(m_connectButton);
    
    m_connectionStatus = new QLabel("Disconnected");
    m_connectionStatus->setStyleSheet("color: red; font-weight: bold;");
    connectionLayout->addWidget(m_connectionStatus);
    
    m_mainLayout->addWidget(connectionGroup);
    
    // Query Controls Group
    auto* queryGroup = new QGroupBox("Query Parameters");
    auto* controlsLayout = new QGridLayout(queryGroup);
    
    controlsLayout->addWidget(new QLabel("Device:"), 0, 0);
    m_deviceCombo = new QComboBox();
    m_deviceCombo->addItems({"All", "robot_arm_01", "conveyor_01", "feeder_01"});
    controlsLayout->addWidget(m_deviceCombo, 0, 1);
    
    controlsLayout->addWidget(new QLabel("Log Level:"), 0, 2);
    m_logLevelCombo = new QComboBox();
    m_logLevelCombo->addItems({"All", "error", "info"});
    controlsLayout->addWidget(m_logLevelCombo, 0, 3);
    
    controlsLayout->addWidget(new QLabel("Log Code:"), 1, 0);
    m_logCodeCombo = new QComboBox();
    m_logCodeCombo->addItems({"All", "TMP", "COL", "SPD", "MTR", "SNR", "COM", "INF", "WRN", "STS", "MNT", "STR", "SHD"});
    controlsLayout->addWidget(m_logCodeCombo, 1, 1);
    
    controlsLayout->addWidget(new QLabel("Severity:"), 1, 2);
    m_severityCombo = new QComboBox();
    m_severityCombo->addItems({"All", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
    controlsLayout->addWidget(m_severityCombo, 1, 3);
    
    controlsLayout->addWidget(new QLabel("Start Time:"), 2, 0);
    m_startTime = new QDateTimeEdit(QDateTime::currentDateTime().addDays(-1));
    m_startTime->setDisplayFormat("yyyy-MM-dd hh:mm:ss");
    controlsLayout->addWidget(m_startTime, 2, 1);
    
    controlsLayout->addWidget(new QLabel("End Time:"), 2, 2);
    m_endTime = new QDateTimeEdit(QDateTime::currentDateTime());
    m_endTime->setDisplayFormat("yyyy-MM-dd hh:mm:ss");
    controlsLayout->addWidget(m_endTime, 2, 3);
    
    controlsLayout->addWidget(new QLabel("Limit:"), 3, 0);
    m_limitEdit = new QLineEdit("100");
    controlsLayout->addWidget(m_limitEdit, 3, 1);
    
    auto* buttonLayout = new QHBoxLayout();
    m_queryButton = new QPushButton("Send Query");
    m_queryButton->setEnabled(false);
    buttonLayout->addWidget(m_queryButton);
    
    m_clearButton = new QPushButton("Clear Results");
    buttonLayout->addWidget(m_clearButton);
    
    auto* realTimeButton = new QPushButton("Enable Real-time");
    realTimeButton->setCheckable(true);
    buttonLayout->addWidget(realTimeButton);
    
    buttonLayout->addStretch();
    controlsLayout->addLayout(buttonLayout, 3, 2, 1, 2);
    
    connect(realTimeButton, &QPushButton::toggled, [this, realTimeButton](bool checked) {
        m_realTimeEnabled = checked;
        realTimeButton->setText(checked ? "Disable Real-time" : "Enable Real-time");
        if (m_isConnected) {
            if (checked) {
                subscribeToLogs();
            } else {
                unsubscribeFromLogs();
            }
        }
        m_statusLabel->setText(checked ? "Real-time mode enabled" : "Real-time mode disabled");
    });
    
    m_mainLayout->addWidget(queryGroup);
    
    // Progress Bar
    m_progressBar = new QProgressBar();
    m_progressBar->setVisible(false);
    m_mainLayout->addWidget(m_progressBar);
    
    // Results Area
    auto* resultsGroup = new QGroupBox("Query Results");
    auto* resultsLayout = new QVBoxLayout(resultsGroup);
    
    auto* splitter = new QSplitter(Qt::Vertical);
    
    // Results Table
    m_resultsTable = new QTableWidget();
    m_resultsTable->setColumnCount(9);
    QStringList headers = {"ID", "Device", "Device Name", "Level", "Code", "Severity", "Message", "Timestamp", "Location"};
    m_resultsTable->setHorizontalHeaderLabels(headers);
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    splitter->addWidget(m_resultsTable);
    
    // Details Text
    m_detailsText = new QTextEdit();
    m_detailsText->setMaximumHeight(150);
    m_detailsText->setReadOnly(true);
    m_detailsText->setPlaceholderText("Select a row to view detailed information...");
    splitter->addWidget(m_detailsText);
    
    resultsLayout->addWidget(splitter);
    m_mainLayout->addWidget(resultsGroup);
    
    // Status Bar
    m_statusLabel = new QLabel("Ready - Please connect to MQTT broker");
    statusBar()->addWidget(m_statusLabel);
    
    // Connections
    connect(m_connectButton, &QPushButton::clicked, this, &RemoteQueryWindow::onConnectClicked);
    connect(m_queryButton, &QPushButton::clicked, this, &RemoteQueryWindow::onQueryClicked);
    connect(m_clearButton, &QPushButton::clicked, this, &RemoteQueryWindow::onClearClicked);
    
    connect(m_resultsTable, &QTableWidget::itemSelectionChanged, [this]() {
        int row = m_resultsTable->currentRow();
        if (row >= 0 && row < m_resultsTable->rowCount()) {
            QString details = QString("Log Details:\n");
            details += QString("ID: %1\n").arg(m_resultsTable->item(row, 0)->text());
            details += QString("Device: %1 (%2)\n").arg(m_resultsTable->item(row, 1)->text(), m_resultsTable->item(row, 2)->text());
            details += QString("Level: %1, Code: %2, Severity: %3\n").arg(
                m_resultsTable->item(row, 3)->text(),
                m_resultsTable->item(row, 4)->text(),
                m_resultsTable->item(row, 5)->text()
            );
            details += QString("Message: %1\n").arg(m_resultsTable->item(row, 6)->text());
            details += QString("Timestamp: %1\n").arg(m_resultsTable->item(row, 7)->text());
            details += QString("Location: %1").arg(m_resultsTable->item(row, 8)->text());
            
            m_detailsText->setText(details);
        }
    });
    
    setWindowTitle("Factory Remote Query Tool (MQTT)");
    resize(1400, 900);
}

void RemoteQueryWindow::onConnectClicked()
{
    if (m_isConnected) {
        // Disconnect
        m_autoReconnect = false;
        if (m_mqttClient) {
            m_mqttClient->disconnectFromHost();
        }
    } else {
        // Connect
        m_autoReconnect = true;
        connectToMqtt();
    }
}

void RemoteQueryWindow::onQueryClicked()
{
    if (!m_isConnected) {
        QMessageBox::warning(this, "Connection Error", "Please connect to MQTT broker first.");
        return;
    }
    
    // 쿼리 실행 시 항상 최신 데이터를 포함하도록 종료 시간을 현재 시간으로 업데이트합니다.
    // m_endTime->setDateTime(QDateTime::currentDateTime()); // 주석 처리: 사용자가 설정한 종료 시간을 유지하도록 함
    
    sendQuery();
}

void RemoteQueryWindow::onClearClicked()
{
    m_resultsTable->setRowCount(0);
    m_detailsText->clear();
    m_statusLabel->setText("Results cleared");
}

void RemoteQueryWindow::connectToMqtt()
{
    if (m_mqttClient->state() == QMqttClient::Connected) {
        return; // 이미 연결됨
    }
    
    QString brokerAddress = m_brokerEdit->text();
    
    m_mqttClient->setHostname(brokerAddress);
    m_mqttClient->setPort(1883);
    
    m_statusLabel->setText("Connecting to MQTT broker...");
    std::cout << "Attempting to connect to: " << brokerAddress.toStdString() << ":1883" << std::endl;
    m_mqttClient->connectToHost();
}

void RemoteQueryWindow::sendQuery()
{
    try {
        m_currentQueryId = QString::fromStdString(generateQueryId());
        
        json queryPayload;
        queryPayload["query_id"] = m_currentQueryId.toStdString();
        queryPayload["query_type"] = "logs";
        queryPayload["client_id"] = m_clientId.toStdString();
        
        json filters;
        
        QString device = m_deviceCombo->currentText();
        if (device != "All") {
            filters["device_id"] = device.toStdString();
        }
        
        QString logLevel = m_logLevelCombo->currentText();
        if (logLevel != "All") {
            filters["log_level"] = logLevel.toStdString();
        }
        
        QString logCode = m_logCodeCombo->currentText();
        if (logCode != "All") {
            filters["log_code"] = logCode.toStdString();
        }
        
        QString severity = m_severityCombo->currentText();
        if (severity != "All") {
            filters["severity"] = severity.toStdString();
        }
        
        filters["time_range"]["start"] = m_startTime->dateTime().toMSecsSinceEpoch();
        filters["time_range"]["end"] = m_endTime->dateTime().toMSecsSinceEpoch();
        filters["limit"] = m_limitEdit->text().toInt();
        
        queryPayload["filters"] = filters;
        
        QString topic = "factory/query/logs/request";
        QByteArray payload = QByteArray::fromStdString(queryPayload.dump());
        
        m_mqttClient->publish(QMqttTopicName(topic), payload, 1);
        
        m_progressBar->setVisible(true);
        m_progressBar->setRange(0, 0); // Indeterminate progress
        m_queryButton->setEnabled(false);
        m_statusLabel->setText(QString("Query sent (ID: %1). Waiting for response...").arg(m_currentQueryId));
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Query Error", 
            QString("Failed to send query: %1").arg(e.what()));
        m_progressBar->setVisible(false);
        m_queryButton->setEnabled(true);
    }
}

void RemoteQueryWindow::displayResults(const json& results)
{
    try {
        if (!results.contains("data") || !results["data"].is_array()) {
            m_statusLabel->setText("No results received");
            return;
        }
        
        auto data = results["data"];
        m_resultsTable->setRowCount(data.size());
        
        for (size_t i = 0; i < data.size(); ++i) {
            const auto& log = data[i];
            
            m_resultsTable->setItem(i, 0, new QTableWidgetItem(
                QString::fromStdString(log.value("_id", ""))));
            m_resultsTable->setItem(i, 1, new QTableWidgetItem(
                QString::fromStdString(log.value("device_id", ""))));
            m_resultsTable->setItem(i, 2, new QTableWidgetItem(
                QString::fromStdString(log.value("device_name", ""))));
            m_resultsTable->setItem(i, 3, new QTableWidgetItem(
                QString::fromStdString(log.value("log_level", ""))));
            m_resultsTable->setItem(i, 4, new QTableWidgetItem(
                QString::fromStdString(log.value("log_code", ""))));
            m_resultsTable->setItem(i, 5, new QTableWidgetItem(
                QString::fromStdString(log.value("severity", ""))));
            m_resultsTable->setItem(i, 6, new QTableWidgetItem(
                QString::fromStdString(log.value("message", ""))));
            
            // Timestamp 변환
            QString timestamp = "";
            if (log.contains("timestamp") && log["timestamp"].is_number()) {
                int64_t ts = log["timestamp"];
                QDateTime dt = QDateTime::fromMSecsSinceEpoch(ts);
                timestamp = dt.toString("yyyy-MM-dd hh:mm:ss");
            }
            m_resultsTable->setItem(i, 7, new QTableWidgetItem(timestamp));
            
            m_resultsTable->setItem(i, 8, new QTableWidgetItem(
                QString::fromStdString(log.value("location", ""))));
        }
        
        m_resultsTable->resizeColumnsToContents();
        
        int resultCount = data.size();
        m_statusLabel->setText(QString("Query completed. Found %1 logs").arg(resultCount));
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Display Error", 
            QString("Failed to display results: %1").arg(e.what()));
        m_statusLabel->setText("Failed to display results");
    }
}

void RemoteQueryWindow::updateConnectionStatus(bool connected)
{
    m_isConnected = connected;
    
    if (connected) {
        m_connectionStatus->setText("Connected");
        m_connectionStatus->setStyleSheet("color: green; font-weight: bold;");
        m_connectButton->setText("Disconnect");
        m_queryButton->setEnabled(true);
        m_statusLabel->setText("Connected to MQTT broker. Ready to send queries.");
    } else {
        m_connectionStatus->setText("Disconnected");
        m_connectionStatus->setStyleSheet("color: red; font-weight: bold;");
        m_connectButton->setText("Connect");
        m_queryButton->setEnabled(false);
        m_progressBar->setVisible(false);
        m_statusLabel->setText("Disconnected from MQTT broker");
    }
}

std::string RemoteQueryWindow::generateQueryId()
{
    static const char* ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t rand_val = dis(gen);
    
    char query_id[16];
    query_id[15] = 0;
    
    // Timestamp (6 chars) + Random (8 chars)
    for (int i = 0; i < 6; ++i) {
        query_id[i] = ENCODING[ms & 0x1F];
        ms >>= 5;
    }
    for (int i = 6; i < 14; ++i) {
        query_id[i] = ENCODING[rand_val & 0x1F];
        rand_val >>= 5;
    }
    
    return std::string("Q-") + query_id;
}

void RemoteQueryWindow::checkMqttConnection()
{
    if (m_mqttClient) {
        bool connected = (m_mqttClient->state() == QMqttClient::Connected);
        if (connected != m_isConnected) {
            updateConnectionStatus(connected);
            
            // 연결되었지만 구독이 없는 경우 재구독
            if (connected && !m_subscription) {
                QString responseTopic = "factory/query/logs/response";
                m_subscription = m_mqttClient->subscribe(QMqttTopicFilter(responseTopic), 1);
                
                if (m_subscription) {
                    connect(m_subscription, &QMqttSubscription::messageReceived, 
                            this, &RemoteQueryWindow::onMqttMessageReceived);
                    std::cout << "Re-subscribed to: " << responseTopic.toStdString() << std::endl;
                }
            }
        }
        
        // 자동 재연결 로직
        if (!connected && m_autoReconnect && 
            m_mqttClient->state() == QMqttClient::Disconnected) {
            std::cout << "Auto-reconnecting to MQTT broker..." << std::endl;
            connectToMqtt();
        }
    }
}

// Qt MQTT 시그널 핸들러 구현
void RemoteQueryWindow::onMqttConnected()
{
    std::cout << "MQTT Connected" << std::endl;
    
    // 기존 구독이 있다면 정리
    if (m_subscription) {
        m_subscription->unsubscribe();
        m_subscription = nullptr;
    }
    if (m_logSubscription) {
        m_logSubscription->unsubscribe();
        m_logSubscription = nullptr;
    }
    
    // 응답 토픽 구독
    QString responseTopic = "factory/query/logs/response";
    m_subscription = m_mqttClient->subscribe(QMqttTopicFilter(responseTopic), 1);
    
    if (m_subscription) {
        connect(m_subscription, &QMqttSubscription::messageReceived, 
                this, &RemoteQueryWindow::onMqttMessageReceived);
        std::cout << "Subscribed to: " << responseTopic.toStdString() << std::endl;
    } else {
        std::cerr << "Failed to subscribe to: " << responseTopic.toStdString() << std::endl;
    }
    
    // 실시간 모드가 활성화되어 있으면 로그 토픽도 구독
    if (m_realTimeEnabled) {
        subscribeToLogs();
    }
    
    updateConnectionStatus(true);
}

void RemoteQueryWindow::onMqttDisconnected()
{
    std::cout << "MQTT Disconnected" << std::endl;
    
    // 구독 정리
    if (m_subscription) {
        m_subscription = nullptr;
    }
    if (m_logSubscription) {
        m_logSubscription = nullptr;
    }
    
    updateConnectionStatus(false);
}

void RemoteQueryWindow::onMqttMessageReceived(const QMqttMessage &message)
{
    try {
        QString topicStr = message.topic().name();
        QString payloadStr = QString::fromUtf8(message.payload());
        
        std::cout << "Response received on topic: " << topicStr.toStdString() << std::endl;
        std::cout << "Payload size: " << payloadStr.size() << " bytes" << std::endl;
        
        if (topicStr == "factory/query/logs/response") {
            json response = json::parse(payloadStr.toStdString());
            
            std::cout << "Query ID in response: " << response.value("query_id", "none") << std::endl;
            std::cout << "Current Query ID: " << m_currentQueryId.toStdString() << std::endl;
            
            // 현재 쿼리 ID와 일치하는지 확인
            if (response.contains("query_id") && 
                QString::fromStdString(response["query_id"]) == m_currentQueryId) {
                
                m_progressBar->setVisible(false);
                m_queryButton->setEnabled(true);
                
                if (response.contains("status") && response["status"] == "success") {
                    std::cout << "Query successful, displaying results" << std::endl;
                    displayResults(response);
                } else {
                    QString error = QString::fromStdString(response.value("error", "Unknown error"));
                    QMessageBox::warning(this, "Query Error", 
                        QString("Query failed: %1").arg(error));
                    m_statusLabel->setText("Query failed: " + error);
                }
            } else {
                std::cout << "Query ID mismatch, ignoring response" << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing MQTT message: " << e.what() << std::endl;
    }
}

void RemoteQueryWindow::onMqttError(QMqttClient::ClientError error)
{
    QString errorString;
    switch (error) {
        case QMqttClient::NoError:
            return;
        case QMqttClient::InvalidProtocolVersion:
            errorString = "Invalid protocol version";
            break;
        case QMqttClient::IdRejected:
            errorString = "Client ID rejected";
            break;
        case QMqttClient::ServerUnavailable:
            errorString = "Server unavailable";
            break;
        case QMqttClient::BadUsernameOrPassword:
            errorString = "Bad username or password";
            break;
        case QMqttClient::NotAuthorized:
            errorString = "Not authorized";
            break;
        case QMqttClient::TransportInvalid:
            errorString = "Transport invalid";
            break;
        case QMqttClient::ProtocolViolation:
            errorString = "Protocol violation";
            break;
        case QMqttClient::UnknownError:
        default:
            errorString = "Unknown error";
            break;
    }
    
    std::cerr << "MQTT Error: " << errorString.toStdString() << std::endl;
    m_statusLabel->setText("MQTT Error: " + errorString);
}

void RemoteQueryWindow::subscribeToLogs()
{
    if (!m_mqttClient || m_mqttClient->state() != QMqttClient::Connected) {
        return;
    }
    
    QString logTopic = "factory/+/log/+";
    m_logSubscription = m_mqttClient->subscribe(QMqttTopicFilter(logTopic), 1);
    
    if (m_logSubscription) {
        connect(m_logSubscription, &QMqttSubscription::messageReceived,
                this, &RemoteQueryWindow::onLogMessageReceived);
        std::cout << "Subscribed to real-time logs: " << logTopic.toStdString() << std::endl;
    }
}

void RemoteQueryWindow::unsubscribeFromLogs()
{
    if (m_logSubscription) {
        m_logSubscription->unsubscribe();
        m_logSubscription = nullptr;
        std::cout << "Unsubscribed from real-time logs" << std::endl;
    }
}

void RemoteQueryWindow::onLogMessageReceived(const QMqttMessage &message)
{
    try {
        QString topicStr = message.topic().name();
        QString payloadStr = QString::fromUtf8(message.payload());
        
        std::cout << "Real-time log received on topic: " << topicStr.toStdString() << std::endl;
        std::cout << "Payload: " << payloadStr.toStdString() << std::endl;
        
        // 토픽 파싱 (factory/{device_id}/log/{log_level})
        QStringList topicParts = topicStr.split('/');
        if (topicParts.size() != 4 || topicParts[0] != "factory" || topicParts[2] != "log") {
            std::cout << "Invalid topic format, ignoring" << std::endl;
            return;
        }
        
        QString deviceId = topicParts[1];
        QString logLevel = topicParts[3];
        
        json payload = json::parse(payloadStr.toStdString());
        
        // 로그 데이터 구성
        json logData;
        logData["device_id"] = deviceId.toStdString();
        logData["log_level"] = logLevel.toStdString();
        logData["log_code"] = payload.value("log_code", "UNKNOWN");
        logData["message"] = payload.value("message", "");
        logData["timestamp"] = payload.value("timestamp", 
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        
        std::cout << "Parsed log data - Device: " << deviceId.toStdString() 
                  << ", Level: " << logLevel.toStdString()
                  << ", Code: " << logData["log_code"].get<std::string>()
                  << ", Message: " << logData["message"].get<std::string>() << std::endl;
        
        // 현재 필터와 일치하는지 확인
        if (matchesCurrentFilters(logData)) {
            std::cout << "Log matches filters, adding to table" << std::endl;
            addLogToTable(logData);
        } else {
            std::cout << "Log does not match current filters" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing real-time log: " << e.what() << std::endl;
    }
}

bool RemoteQueryWindow::matchesCurrentFilters(const json& logData)
{
    // Device 필터 확인
    QString deviceFilter = m_deviceCombo->currentText();
    QString logDevice = QString::fromStdString(logData.value("device_id", ""));
    if (deviceFilter != "All" && logDevice != deviceFilter) {
        std::cout << "Device filter mismatch: " << deviceFilter.toStdString() 
                  << " vs " << logDevice.toStdString() << std::endl;
        return false;
    }
    
    // Log Level 필터 확인
    QString logLevelFilter = m_logLevelCombo->currentText();
    QString logLevel = QString::fromStdString(logData.value("log_level", ""));
    if (logLevelFilter != "All" && logLevel != logLevelFilter) {
        std::cout << "Log level filter mismatch: " << logLevelFilter.toStdString() 
                  << " vs " << logLevel.toStdString() << std::endl;
        return false;
    }
    
    // Log Code 필터 확인
    QString logCodeFilter = m_logCodeCombo->currentText();
    QString logCode = QString::fromStdString(logData.value("log_code", ""));
    if (logCodeFilter != "All" && logCode != logCodeFilter) {
        std::cout << "Log code filter mismatch: " << logCodeFilter.toStdString() 
                  << " vs " << logCode.toStdString() << std::endl;
        return false;
    }
    
    // 실시간 모드에서는 시간 범위 필터를 더 관대하게 적용
    // 현재 시간 기준으로 1시간 이내의 로그만 허용
    if (logData.contains("timestamp")) {
        int64_t logTime = logData["timestamp"];
        int64_t currentTime = QDateTime::currentMSecsSinceEpoch();
        int64_t oneHourAgo = currentTime - (60 * 60 * 1000); // 1시간 전
        
        if (logTime < oneHourAgo) {
            std::cout << "Log too old for real-time mode" << std::endl;
            return false;
        }
    }
    
    std::cout << "All filters passed" << std::endl;
    return true;
}

void RemoteQueryWindow::addLogToTable(const json& logData)
{
    // 맨 위에 새 행 추가
    m_resultsTable->insertRow(0);
    
    QString deviceId = QString::fromStdString(logData.value("device_id", ""));
    QString logCode = QString::fromStdString(logData.value("log_code", ""));
    
    // 디바이스 정보 매핑
    QString deviceName = "Unknown";
    QString location = "Unknown";
    if (deviceId == "robot_arm_01") {
        deviceName = "Assembly Robot #1";
        location = "Line A - Station 3";
    } else if (deviceId == "conveyor_01") {
        deviceName = "Conveyor Belt #1";
        location = "Line A - Station 1";
    } else if (deviceId == "feeder_01") {
        deviceName = "Feeder #1";
        location = "Line A - Station 2";
    }
    
    // 임시 ID 생성
    QString tempId = QString("RT-%1").arg(QDateTime::currentMSecsSinceEpoch());
    
    // 0번 행(맨 위)에 데이터 설정
    m_resultsTable->setItem(0, 0, new QTableWidgetItem(tempId));
    m_resultsTable->setItem(0, 1, new QTableWidgetItem(deviceId));
    m_resultsTable->setItem(0, 2, new QTableWidgetItem(deviceName));
    m_resultsTable->setItem(0, 3, new QTableWidgetItem(
        QString::fromStdString(logData.value("log_level", ""))));
    m_resultsTable->setItem(0, 4, new QTableWidgetItem(logCode));
    m_resultsTable->setItem(0, 5, new QTableWidgetItem("MEDIUM")); // 기본값
    m_resultsTable->setItem(0, 6, new QTableWidgetItem(
        QString::fromStdString(logData.value("message", ""))));
    
    // 타임스탬프 변환
    QString timestamp = "";
    if (logData.contains("timestamp")) {
        int64_t ts = logData["timestamp"];
        QDateTime dt = QDateTime::fromMSecsSinceEpoch(ts);
        timestamp = dt.toString("yyyy-MM-dd hh:mm:ss");
    }
    m_resultsTable->setItem(0, 7, new QTableWidgetItem(timestamp));
    m_resultsTable->setItem(0, 8, new QTableWidgetItem(location));
    
    // 테이블 크기 조정
    m_resultsTable->resizeColumnsToContents();
    
    // 상태 업데이트
    int totalRows = m_resultsTable->rowCount();
    m_statusLabel->setText(QString("Real-time mode: %1 logs displayed").arg(totalRows));
}
