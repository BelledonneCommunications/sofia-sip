#include <iostream>

#include <openssl/ssl.h>

using namespace std;

int main() {
	auto* x509 = X509_new();
	X509_load_cert_file(x509, "./server.pem", X509_FILETYPE_PEM);
	auto* TlsCtx = SSL_CTX_new(TLS_server_method());

	auto* bio = BIO_new_accept("127.0.0.1:5062");
// 	if (BIO_do_accept(bio) <= 0) {
// 		cout << "error: couldn't bind listen socket" << endl;
// 		goto end;
// 	}
// 	cout << "Waiting for connection" << endl;
// 	if (BIO_do_accept(bio) <= 0) {
// 		cout << "error: failure while accepting TCP/IP connection" << endl;
// 		goto end;
// 	}

	auto* ssl = SSL_new(TlsCtx);
	SSL_set_bio(ssl, bio, bio);

	cout << "Waiting for connection" << endl;
	if (SSL_accept(ssl) <= 0) {
		cout << "error: failure while accepting connection" << endl;
		goto end;
	}

	cout << "Connection accepted" << endl;

	cout << "Shutting down" << endl;

	// Cleaning
end:
// 	BIO_free(bio);
	SSL_free(ssl);
	SSL_CTX_free(TlsCtx);
	return 0;
}
