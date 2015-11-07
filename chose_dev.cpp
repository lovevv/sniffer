#include "chose_dev.h"
#include "ui_chose_dev.h"


chose_dev::chose_dev(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::chose_dev)
{
    ui->setupUi(this);

}

chose_dev::~chose_dev()
{
    delete ui;
}

void chose_dev::recive_command()
{
    emit request_dev();
}

void chose_dev::rev_dev(QStringList list)//need change to long low
{
    int length=0;
  //  qDebug("text is %s",ui->checkBox->text().toLatin1().data());
    for(QStringList::Iterator i=list.begin();i!=list.end();i++){
        length++;
        if(length==1)
            ui->checkBox->setText((*i).toLocal8Bit().data());
        else if(length==2)
            ui->checkBox_2->setText((*i).toLocal8Bit().data());
        else if(length==3)
            ui->checkBox_3->setText((*i).toLocal8Bit().data());
        else if(length==4)
            ui->checkBox_4->setText((*i).toLocal8Bit().data());
        else if(length==5)
            ui->checkBox_5->setText((*i).toLocal8Bit().data());
        else if(length==6)
            ui->checkBox_6->setText((*i).toLocal8Bit().data());
        else if(length==7)
            ui->checkBox_7->setText((*i).toLocal8Bit().data());
        else if(length==8)
            ui->checkBox_8->setText((*i).toLocal8Bit().data());
    }
    qDebug("dev length is %d",length);
    if(length==1){
        ui->checkBox_2->hide();
        ui->checkBox_3->hide();
        ui->checkBox_4->hide();
        ui->checkBox_5->hide();
        ui->checkBox_6->hide();
        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==2){
        ui->checkBox_3->hide();
        ui->checkBox_4->hide();
        ui->checkBox_5->hide();
        ui->checkBox_6->hide();
        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==3){
        ui->checkBox_4->hide();
        ui->checkBox_5->hide();
        ui->checkBox_6->hide();
        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==4){

        ui->checkBox_5->hide();
        ui->checkBox_6->hide();
        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==5){


        ui->checkBox_6->hide();
        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==6){

        ui->checkBox_7->hide();
        ui->checkBox_8->hide();
    }
    else if(length==7){
        ui->checkBox_8->hide();
    }
}

void chose_dev::on_pushButton_clicked()
{

    if(ui->checkBox->isChecked())
        strcpy(chosename,ui->checkBox->text().toLocal8Bit().data());
    if(ui->checkBox_2->isChecked())
        strcpy(chosename,ui->checkBox_2->text().toLocal8Bit().data());
    if(ui->checkBox_3->isChecked())
        strcpy(chosename,ui->checkBox_3->text().toLocal8Bit().data());
    if(ui->checkBox_4->isChecked())
        strcpy(chosename,ui->checkBox_4->text().toLocal8Bit().data());
    if(ui->checkBox_5->isChecked())
        strcpy(chosename,ui->checkBox_5->text().toLocal8Bit().data());
    if(ui->checkBox_6->isChecked())
        strcpy(chosename,ui->checkBox_6->text().toLocal8Bit().data());
    if(ui->checkBox_7->isChecked())
        strcpy(chosename,ui->checkBox_7->text().toLocal8Bit().data());
    if(ui->checkBox_8->isChecked())
        strcpy(chosename,ui->checkBox_8->text().toLocal8Bit().data());
    qDebug("sendname is starting %s",chosename);
    strcpy(fliterstring,ui->textEdit->toPlainText().toLocal8Bit().data());
    qDebug("flitername is in the chose _dev %s",fliterstring);
    emit send_devname_filter(chosename,fliterstring);
    this->close();

}

void chose_dev::on_pushButton_2_clicked()
{
    this->close();
}
