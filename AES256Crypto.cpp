#include "AES256Crypto.h"




#define DECL_OPENSSL_PTR(tname, free_func) \
    struct openssl_##tname##_dtor {            \
        void operator()(tname* v) {        \
            free_func(v);              \
        }                              \
    };                                 \
    typedef std::unique_ptr<tname, openssl_##tname##_dtor> tname##_t


DECL_OPENSSL_PTR(EVP_CIPHER_CTX, ::EVP_CIPHER_CTX_free);


struct error : public std::exception {
private:
    std::string m_msg;

public:
    error(const std::string& message)
        : m_msg(message) {
    }

    error(const char* msg)
        : m_msg(msg, msg + strlen(msg)) {
    }

    virtual const char* what() const noexcept override {
        return m_msg.c_str();
    }
};

struct openssl_error: public virtual error {
private:
    int m_code = -1;
    std::string m_msg;

public:
    openssl_error(int code, const std::string& message)
        : error(message),
          m_code(code) {
        std::stringstream ss;
        ss << "[" << m_code << "]: " << message;
        m_msg = ss.str();

    }

    openssl_error(int code, const char* msg)
        : error(msg),
          m_code(code) {
        std::stringstream ss;
        ss << "[" << m_code << "]: " << msg;
        m_msg = ss.str();
    }

    const char* what() const noexcept override {
        return m_msg.c_str();
    }
};

static void throw_if_error(int res = 1, const char* file = nullptr, uint64_t line = 0) {

    unsigned long errc = ERR_get_error();
    if (res <= 0 || errc != 0) {
        if (errc == 0) {
            return;
        }
        std::vector<std::string> errors;
        while (errc != 0) {
            std::vector<uint8_t> buf(256);
            ERR_error_string(errc, (char*) buf.data());
            errors.push_back(std::string(buf.begin(), buf.end()));
            errc = ERR_get_error();
        }

        std::stringstream ss;
        ss << "\n";
        for (auto&& err : errors) {
            if (file != nullptr) {
                ss << file << ":" << (line - 1) << " ";
            }
            ss << err << "\n";
        }
        const std::string err_all = ss.str();
        throw openssl_error(errc, err_all);
    }
}


static std::vector<uint8_t> m_iv = AES256Crypto::str2Bytes("1234567890123456");
static std::vector<uint8_t> key = AES256Crypto::str2Bytes("12345678901234567890123456789012");// 32 bytes (256 bits key)


static QByteArray temp;
static QString result;
static std::vector<uint8_t> cryptoinput;
static std::vector<uint8_t> cryptooutput;
static std::vector<uint8_t> decryptooutput;
static std::vector<uint8_t> decryptoinput;

std::vector<uint8_t> QStringToVector(const QString& str) {
    QByteArray byteArray = str.toUtf8();
    const char* data = byteArray.constData();
    std::vector<uint8_t> result(data, data + byteArray.size());
    return result;
}

QByteArray AES256Crypto::encrypt(QString data) {
    cryptoinput = QStringToVector(data);

    cryptooutput.resize(cryptoinput.size() * AES_BLOCK_SIZE);
    int inlen = cryptoinput.size();
    int outlen = 0;
    size_t total_out = 0;

    EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
    throw_if_error(1, __FILE__, __LINE__);


    int res;
    res = EVP_EncryptInit(ctx.get(), EVP_aes_256_cbc(), key.data(), m_iv.data());
    throw_if_error(res, __FILE__, __LINE__);
    res = EVP_EncryptUpdate(ctx.get(), cryptooutput.data(), &outlen, cryptoinput.data(), inlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;
    res = EVP_EncryptFinal(ctx.get(), cryptooutput.data()+total_out, &outlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;

    cryptooutput.resize(total_out);

    temp.clear();
    for (int var = 0; var < cryptooutput.size(); ++var) {
        temp.append(cryptooutput[var]);
    }

    return temp;
}

QString AES256Crypto::decrypt(QByteArray data) {

    decryptoinput = std::vector<uint8_t>(data.begin(), data.end());




    decryptooutput.resize(decryptoinput.size() * 3);
    int outlen = 0;
    size_t total_out = 0;

    EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
    throw_if_error();




    int inlen = decryptoinput.size();

    int res;
    res = EVP_DecryptInit(ctx.get(), EVP_aes_256_cbc(), key.data(), m_iv.data());
    throw_if_error(res, __FILE__, __LINE__);
    res = EVP_DecryptUpdate(ctx.get(), decryptooutput.data(), &outlen, decryptoinput.data(), inlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;
    res = EVP_DecryptFinal(ctx.get(), decryptooutput.data()+outlen, &outlen);
    throw_if_error(res, __FILE__, __LINE__);
    total_out += outlen;

    decryptooutput.resize(total_out);

    result.clear();
    for (int var = 0; var < decryptooutput.size(); ++var) {
        result.append(decryptooutput[var]);
    }
    return result;
}




std::vector<uint8_t> AES256Crypto::str2Bytes(const std::string& message) {
    std::vector<uint8_t> out(message.size());
    for(size_t n = 0; n < message.size(); n++) {
        out[n] = message[n];
    }
    return out;
}

std::string AES256Crypto::bytes2Str(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}




