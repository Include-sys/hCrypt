#include "about.h"
#include "ui_about.h"

About::About(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::About)
{
    ui->setupUi(this);
    About::setWindowTitle("About");
    QImage image(":/ico/hCrypt.png");
    ui->imageLabel->setPixmap(QPixmap::fromImage(image));
    ui->imageLabel->setScaledContents(true);

    ui->label_2->setTextFormat(Qt::RichText);
    ui->label_2->setTextInteractionFlags(Qt::TextBrowserInteraction);
    ui->label_2->setOpenExternalLinks(true);
}

About::~About()
{
    delete ui;
}
