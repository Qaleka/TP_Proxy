package main

import (
	"fmt"
	"os"
	"web_security/cert"
)

func main() {
	certPEM, keyPEM, err := cert.GenCA("MyProxy Root CA")
	if err != nil {
		fmt.Println("Ошибка генерации CA:", err)
		return
	}

	if err := saveFiles(certPEM, keyPEM); err != nil {
		fmt.Println("Ошибка сохранения:", err)
		return
	}

	fmt.Println("Успешно созданы:")
	fmt.Println("- CA сертификат: ca_cert.pem")
	fmt.Println("- Приватный ключ: ca_key.pem")
}

func saveFiles(certPEM, keyPEM []byte) error {
	if err := os.WriteFile("ca_cert.pem", certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка записи ca_cert.pem: %w", err)
	}
	if err := os.WriteFile("ca_key.pem", keyPEM, 0600); err != nil {
		return fmt.Errorf("ошибка записи ca_key.pem: %w", err)
	}
	return nil
}