# AES256 Encryption and Decryption in C++ with Qt

This C++ class provides an implementation of AES256 encryption and decryption using the Qt framework.

## Dependencies

This project relies on the OpenSSL library for cryptographic operations. Make sure you have OpenSSL installed on your system before using this class.

## Installation

You can include this AES256 encryption/decryption class in your Qt project by following these steps:

1. Clone this repository:

git clone https://github.com/cbglmehmet/QT-AES256.git

2. Copy the `Aes256Encryption` folder to your project directory.

3. Include the necessary header file in your project.


```cpp
#include "AES256Crypto.h"
```

## Usage
To use this class for encryption and decryption, follow these steps:

1. Encrypt a message:
```cpp
QString message = "mehmet cabaoglu";
QByteArray cryptoData;
cryptoData.clear();
cryptoData.append(AES256Crypto::encrypt(message));
```

2. Decrypt the message:
```cpp
QString result = AES256Crypto::decrypt(cryptoData);
```

## Example
Here's a simple example of how to use the `AES256Crypto` class:
```cpp
#include <QCoreApplication>
#include <QDebug>
#include "AES256Crypto.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);


    QString message = "mehmet cabaoglu";
    QByteArray cryptoData;
    cryptoData.clear();
    cryptoData.append(AES256Crypto::encrypt(message));

    qDebug() << "encrypted : " << cryptoData.toHex();// out = "611767e13a3f00eac3fd9d6bad75744d"
    qDebug() << "decrypted : " << AES256Crypto::decrypt(cryptoData);// out = "mehmet cabaoglu"

    return a.exec();
}
```
## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing
Contributions to this project are welcome. Feel free to open issues and submit pull requests.
