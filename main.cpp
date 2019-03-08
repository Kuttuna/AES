#include <QCoreApplication>
#include "cipher.h"

void testAES()
{
    qDebug() << "Testing AES...";

    Cipher cWrapper;
    QString passphrase = "password";

    QByteArray plain = "For the Horde!!!";

    QByteArray encrypted = cWrapper.encryptAES(passphrase.toLatin1(), plain);
    QByteArray decrypted = cWrapper.decryptAES(passphrase.toLatin1(), encrypted);

    qDebug() << plain;
    qDebug() << encrypted.toBase64();
    qDebug() << decrypted;

}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    testAES();

    return a.exec();
}
