#include "cipher.h"

Cipher::Cipher(QObject *parent) : QObject(parent)
{
    initialize();
}

Cipher::~Cipher()
{
    finalize();
}

QByteArray Cipher::encryptAES(QByteArray passphrase, QByteArray &data)
{
    // salt, randomizes everything even if you have same password
    QByteArray msalt = randomBytes(SALTSIZE);

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    // ?? 11:00
    const unsigned char* salt = (const unsigned char*) msalt.constData();
    const unsigned char* password = (const unsigned char*) passphrase.constData();

    // EVP does all stuff, huge time saver
    // sha1: hashing function, hashes an array of data, unique identifier
    // like converts a DVD into 128 character and it represents that data
    // converts key to a secure key
    int i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha1(), salt, password, passphrase.length(),rounds,key,iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(en);

    if(!EVP_EncryptInit_ex(en,EVP_aes_256_cbc(),nullptr,key,iv))
    {
        qCritical() << "EVP_EncryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    char *input = data.data();
    char *out;
    int len = data.size();

    int c_len = len + AES_BLOCK_SIZE, f_len = 0;

    // memory buffer that we have allocated
    unsigned char *cipherText = (unsigned char*)malloc(c_len);

    if(!EVP_EncryptInit_ex(en, nullptr,nullptr,nullptr,nullptr))
    {
        qCritical() << "EVP_EncryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    if(!EVP_EncryptUpdate(en, cipherText, &c_len,(unsigned char*)input, len))
    {
        qCritical() << "EVP_EncryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    if(!EVP_EncryptFinal(en,cipherText + c_len, &f_len))
    {
        qCritical() << "EVP_EncryptFinal() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    len = c_len + f_len;
    out = (char*)cipherText; // "C style" casting --- old
    //out = reinterpret_cast<char*>(cipherText); // c++ style casting
    EVP_CIPHER_CTX_cipher(en);

    //ciphertext


    // 32:01
    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(cipherText), len);
    QByteArray finished;
    finished.append("Handshake__");
    finished.append(msalt); // salt is useless without key, iv. Key is the most important, you can give the iv away
    //finished.append(out, len);
    finished.append(encrypted);

    free(cipherText); // for malloc
    return finished;
}

QByteArray Cipher::decryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt;
    if(QString(data.mid(0,11)) == "Handshake__")
    {
        msalt = data.mid(11,8); //starting position of 8 with 8 bytes
        data = data.mid(19); // on 16th byte the actual data starts
    }
    else // in a production app, you dont do this, hard exit
    {
        qWarning() << "Could not load salt from data!";
        msalt = randomBytes(SALTSIZE); // this will screp up the encryption
    }

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    // ?? 11:00
    const unsigned char* salt = (const unsigned char*)msalt.constData();
    const unsigned char* password = (const unsigned char*)passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha1(), salt, password, passphrase.length(),rounds,key,iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(de);

    if(!EVP_DecryptInit_ex(de,EVP_aes_256_cbc(),nullptr,key,iv))
    {
        qCritical() << "EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    char *input = data.data();
    char *out;
    int len = data.size();

    int p_len = len, f_len = 0;
    unsigned char *plaintext = (unsigned char*)malloc(p_len + AES_BLOCK_SIZE);

    if(!EVP_DecryptUpdate(de, plaintext, &p_len, (unsigned char*)input, len))
    {
        qCritical() << "EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    if(!EVP_DecryptFinal_ex(de,plaintext+p_len, &f_len))
    {
        qCritical() << "EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    len = p_len + f_len;
    out = (char*)plaintext;
    EVP_CIPHER_CTX_cleanup(de);


    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), len);
    free(plaintext);
    return decrypted;
}

/**
 * @brief create and array, fill that array with random bytes
 * @param size
 * @return
 */
QByteArray Cipher::randomBytes(int size)
{
    unsigned char *arr = new unsigned char[size];
    RAND_bytes(arr, size); // fill the array with random bytes

    // you don't really have to do this??
    // needed to convert things back and forth, if a class is being created inqt
    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

void Cipher::initialize()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(nullptr);
}

void Cipher::finalize()
{
    EVP_cleanup(); //easy clean up rather than writing all code
    ERR_free_strings();
}

QByteArray Cipher::readFile(QString filename)
{
    return QByteArray();
}

void Cipher::writeFile(QString filename, QByteArray &data)
{
    QFile file(filename);

    if(!file.open(QFile::WriteOnly))
    {
        qCritical() << file.errorString();
        return;
    }

    file.write(data);
    file.close();
}
