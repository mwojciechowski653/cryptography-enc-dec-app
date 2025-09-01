# File Encryption and Decryption Application

> Polish version below / Wersja polska poniżej

## Project Description

A project in the field of **cryptography**, aimed at creating an application for encrypting and decrypting files (including entire folders, recursively) using symmetric (**AES**) and asymmetric (**RSA**) algorithms. The extended version of the application introduces certificate management and an administrator role, responsible for issuing and signing user certificates.

The project has **two versions**:

- **MVP – `basic-keys-version`**: the first, simplified version of the application. Supports key pair generation (public key and private key), file encryption, and decryption using AES and RSA. It also provides a simple GUI built with Tkinter.
- **Extended version – `certs-admin-keys-version`**: introduces **X.509 certificates** and an **administrator (authority)** role. The administrator issues and signs user certificates, and during encryption a **header** is created containing a separately encrypted AES key for each recipient (multi-recipient). During decryption, the certificate's validity is verified (validity period + issuer's signature).

Used libraries: **PyCryptodome** (AES/RSA algorithms) and **cryptography** (X.509, signature verification, key serialization). The user interface is based on **Tkinter** (Python standard library). The project requires **Python 3.9+** to run.

## Running the Project

1.  Clone the repository:

```bash
git clone https://github.com/mwojciechowski653/cryptography-enc-dec-app.git
cd cryptography-enc-dec-app
```

2.  Install dependencies:

```bash
pip install -r requirements.txt
```

3.  Run the application

#### Basic version (MVP – `basic-keys-version`):

```bash
cd basic-keys-version
python encrypt.py
```

Before encrypting, you need to choose an option to generate the keys. Afterwards, the encryption/decryption process is guided step by step by the GUI.

#### Extended version (`certs-admin-keys-version`):

```bash
cd certs-admin-keys-version
python main_app.py
```

The workflow of the extended version can be found in the file `Scheme for certs-admin-keys version.png`. Admin credentials: username — **authority**, password — **crypto**.

> Sample test files are available in the `example/` directory (including subdirectories).

## Directory Structure

    cryptography-enc-dec-app/
    ├── basic-keys-version/                         # First version of the application
    │   ├── crypto/                                 # AES, RSA implementations
    │   ├── example/                                # Example files for encryption
    │   ├── utils/                                  # Helper functions
    │   └── encrypt.py                              # Application + GUI
    │
    ├── certs-admin-keys-version/                   # Extended version
    │   ├── certificate/                            # Folder where user certificates are stored
    │   ├── crypto/                                 # Cryptographic algorithms and certificates
    │   ├── example/                                # Example files for encryption
    │   ├── KeyFolder/                              # Folder where admin keys are stored
    │   ├── utils/                                  # Helper functions
    │   ├── coding.py                               # Folder encryption/decryption handling
    │   ├── constants.py                            # Application constants
    │   └── main_app.py                             # Application + GUI
    │
    │── LICENSE                                     # Project license
    │── README.md                                   # Project description
    │── requirements.txt                            # Requirements and dependencies
    └── Scheme for certs-admin-keys version.png     # Extended version workflow diagram

> The `KeyFolder/` and `certificates/` folders in the extended version may be created automatically during first use.

## Authors

The project was created as part of the **Theory of Codes and Cryptography** course at the Universidad de Almeria in 2024.

- **Antoni Gąsior**
  [GitHub](https://github.com/Terrokz)
- **Paulina Korus**
  [GitHub](https://github.com/paulinakorus)
- **Monika Szur**
  [GitHub](https://github.com/m-szur)
- **Marcin Wojciechowski**
  [GitHub](https://github.com/mwojciechowski653)

## License

This project is licensed under the **MIT** license.
The full license text can be found in the [LICENSE](LICENSE) file.

In short: you are free to use, copy, modify, and distribute this code under the MIT terms. The software is provided “as is”, without any warranty.

---

# File Encryption and Decryption Application wersja po polsku

## Opis projektu

Projekt z zakresu **kryptografii**, którego celem jest stworzenie aplikacji do szyfrowania i deszyfrowania plików (także całych folderów, rekursywnie) przy użyciu algorytmów symetrycznych (**AES**) oraz asymetrycznych (**RSA**). Rozszerzona wersja aplikacji wprowadza zarządzanie certyfikatami oraz rolę administratora, wydającego i podpisującego certyfikaty użytkowników.

Projekt posiada **dwie wersje**:

- **MVP – `basic-keys-version`**: pierwsza, uproszczona wersja aplikacji. Obsługuje generowanie par kluczy (publicznego i prywatnego), szyfrowanie oraz deszyfrowanie plików z wykorzystaniem AES i RSA. Do tego prosty interfejs z wykorzystaniem Tkinter;
- **Wersja rozszerzona – `certs-admin-keys-version`**: wprowadza **certyfikaty X.509** i rolę **administratora (authority)**. Administrator wystawia i podpisuje certyfikaty użytkowników, a podczas szyfrowania tworzony jest **nagłówek** zawierający osobno zaszyfrowany klucz AES dla każdego odbiorcy (multi‑recipient). Przy deszyfrowaniu weryfikowana jest ważność certyfikatu (okres ważności + podpis wystawcy).

Wykorzystane biblioteki: **PyCryptodome** (algorytmy AES/RSA) oraz **cryptography** (X.509, weryfikacja podpisów, serializacja kluczy). Interfejs użytkownika oparty jest o **Tkinter** (standardowa biblioteka Pythona). Do uruchomienia projektu potrzebny jest **Python 3.9+**.

## Uruchomienie projektu

1. Sklonuj repozytorium:

```bash
git clone https://github.com/mwojciechowski653/cryptography-enc-dec-app.git
cd cryptography-enc-dec-app
```

2. Zainstaluj zależności:

```bash
pip install -r requirements.txt
```

3. Uruchomienie aplikacji

#### Wersja podstawowa (MVP – `basic-keys-version`):

```bash
cd basic-keys-version
python encrypt.py
```

Przed szyfrowaniem należy wybrać opcję wygenerowania kluczy. Później proces szyfrowania/deszyfrowania krok po kroku, tak jak prowadzi GUI.

#### Wersja rozszerzona (`certs-admin-keys-version`):

```bash
cd certs-admin-keys-version
python main_app.py
```

Schemat działania wersji rozszerzonej znajduje się w pliku `Scheme for certs-admin-keys version.png`. Dane admina to: imie — **authority**, hasło — **crypto**

> Przykładowe pliki do testów znajdują się w katalogu `example/` (także w podkatalogach).

## Struktura katalogu

```
cryptography-enc-dec-app/
├── basic-keys-version/                         # Pierwsza wersja aplikacji
│   ├── crypto/                                 # Implementacje AES, RSA
│   ├── example/                                # Przykładowe pliki do szyfrowania
│   ├── utils/                                  # Funkcje pomocnicze
│   └── encrypt.py                              # Aplikacja + Gui
│
├── certs-admin-keys-version/                   # Rozszerzona wersja
│   ├── certificate/                            # Folder, w którym przechowywane będą certyfikaty użytkowników
│   ├── crypto/                                 # Algorytmy kryptograficzne i certyfikaty
│   ├── example/                                # Przykładowe pliki do szyfrowania
│   ├── KeyFolder/                              # Folder, w którym przechowywane będą klucze admina
│   ├── utils/                                  # Funkcje pomocnicze
│   ├── coding.py                               # Obsługa wczytywania, szyfrowania i deszyfrowania folderów
│   ├── constants.py                            # Stałe aplikacji
│   └── main_app.py                             # Aplikacja + Gui
│
│── LICENSE                                     # Licencja projektu
│── README.md                                   # Opis projektu
│── requirements.txt                            # Wymagania i zależności potrzebne do uruchomienia projektu
└── Scheme for certs-admin-keys version.png     # Schemat działania wersji rozszerzonej
```

> Foldery `KeyFolder/` oraz `certificates/` w wersji rozszerzonej mogą zostać utworzone automatycznie podczas pierwszego użycia.

## Autorzy

Projekt stworzony w ramach przedmiotu **Theory of Codes and Cryptography** na Uniwersytecie w Almerii w 2024r.

- **Antoni Gąsior**\
  [GitHub](https://github.com/Terrokz)
- **Paulina Korus**\
  [GitHub](https://github.com/paulinakorus)
- **Monika Szur**\
  [GitHub](https://github.com/m-szur)
- **Marcin Wojciechowski**\
  [GitHub](https://github.com/mwojciechowski653)

## Licencja

Projekt jest udostępniany na licencji **MIT**.  
Pełny tekst licencji znajdziesz w pliku [LICENSE](LICENSE).

W skrócie: możesz używać, kopiować, modyfikować i rozpowszechniać ten kod na warunkach MIT. Oprogramowanie dostarczane jest „tak jak jest”, bez żadnych gwarancji.
