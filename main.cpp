#include <QtWidgets/QApplication>
#include "remote_query_window.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    app.setApplicationName("Factory Remote Query Tool");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("Factory Monitoring System");
    
    RemoteQueryWindow window;
    window.show();
    
    return app.exec();
}