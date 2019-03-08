#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <QDebug>
#include <QFile>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PADDING RSA_PCKS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define BLOCKSIZE 256
#define SALTSIZE 8

class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(QObject *parent = nullptr);

    ~Cipher();

    QByteArray encryptAES(QByteArray passphrase, QByteArray &data);

    QByteArray decryptAES(QByteArray passphrase, QByteArray &data);

    QByteArray randomBytes(int size);

private:
    void initialize();

    void finalize();

    QByteArray readFile(QString filename);

    void writeFile(QString filename, QByteArray &data);

signals:

public slots:
};

#endif // CIPHER_H
