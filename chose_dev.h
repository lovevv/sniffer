#ifndef CHOSE_DEV_H
#define CHOSE_DEV_H

#include <QDialog>
#include <QStringList>
#include <QByteArray>
#include <stdio.h>
#include <string.h>

namespace Ui {
class chose_dev;
}

class chose_dev : public QDialog
{
    Q_OBJECT

public:
    explicit chose_dev(QWidget *parent = 0);

    ~chose_dev();
signals:
    void request_dev();
    void send_devname_filter(char *name,char *filter);

public slots:
    void recive_command();
    void rev_dev(QStringList list);

private slots:
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();

private:
    char chosename[20];
    char fliterstring[50];//define filter string to compile
    Ui::chose_dev *ui;

  //  QStringList l;
};

#endif // CHOSE_DEV_H
