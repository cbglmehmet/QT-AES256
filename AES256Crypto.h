#ifndef AES256CRYPTO_H
#define AES256CRYPTO_H

#include <QDebug>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <QDateTime>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/aes.h>


class AES256Crypto
{

public:
    static std::vector<uint8_t> str2Bytes(const std::string& message);
    static std::string bytes2Str(const std::vector<uint8_t>& bytes);
    static QByteArray encrypt(QString data);
    static QString decrypt(QByteArray data);




};

#endif // AES256CRYPTO_H
