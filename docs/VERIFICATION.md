# Weryfikacja — 23 listopada 2026

Aktualna wersja używa SQLite, kont e-mail i opcjonalnej weryfikacji adresu. Testowano na Windows, Rust 1.100.0, Node 24.13.1. To weryfikacja konkretnych mechanizmów, nie formalny audyt całego systemu.

| Kontrola | Wynik |
|---|---|
| cargo test --all-targets --locked | 4 testy jednostkowe i 3 integracyjne: PASS |
| cargo fmt --all --check | PASS |
| cargo clippy --all-targets --locked -- -D warnings | PASS |
| npm test | 3 testy modułu Web Crypto: PASS |
| attacks.mjs z włączoną weryfikacją i lokalną pocztą | 11 scenariuszy HTTP: PASS |
| expiry.mjs z włączoną weryfikacją | Odczyt przed TTL 200; po 62 sekundach 404, lista pusta: PASS |
| Przeglądarka: rejestracja e-mailem i próba logowania przed potwierdzeniem | Logowanie odrzucone, widoczny komunikat i ponowne wysłanie linku |
| Przeglądarka: link z poczty lokalnej i potwierdzenie | Adres potwierdzony; potem logowanie poprawne |
| Przeglądarka: wiadomość i XSS w podglądzie | Odszyfrowano lokalnie, ładunek pozostał tekstem, 0 elementów HTML w podglądzie |
| Przeglądarka: podział wysłane/odebrane | Własna wiadomość tylko w wysłanych; wiadomość innego konta tylko w odebranych, z e-mailem nadawcy |
| Przeglądarka: klucz | Wygenerowanie, zapis chronionej kopii, zablokowanie, ponowne wczytanie hasłem i usunięcie kopii: PASS |
| Przeglądarka: teksty | Nowy nagłówek, numeracja 1/2/3 i stopka bez laboratorium; zrzut interface.jpg |
| Faktyczna wysyłka SMTP do zewnętrznej skrzynki | Nie wykonano: brak konfiguracji rzeczywistego konta SMTP |
| Docker / Render | Nie wykonywano w tej iteracji; konfigurację zaktualizowano |

## Nowy test weryfikacji adresu

`cargo test --test email_verification --locked` uruchamia rzeczywisty lokalny HTTP, SQLite w pamięci i własną tymczasową skrzynkę plikową. Sprawdza:

- brak tokenu potwierdzenia w odpowiedzi rejestracji i przechowywanie jego skrótu w bazie;
- odmowę logowania przed potwierdzeniem i odrzucenie fałszywego tokenu;
- ponowne wysłanie, unieważnienie wcześniejszego linku i wygaśnięcie tokenu (czas ustawiony bezpośrednio w testowej bazie);
- dwie równoległe próby potwierdzenia: dokładnie jeden sukces, drugi token już zużyty;
- poprawne logowanie po potwierdzeniu i odmowę użycia sesji, jeśli wymagany stan potwierdzenia nie jest spełniony;
- brak możliwości wyłączenia flagi przez pola żądania i brak dostępu HTTP do skrzynki lokalnej;
- poprawne logowanie niepotwierdzonego konta w trybie z wyłączoną weryfikacją;
- błąd dostarczenia: 503 i brak aktywacji konta, a następnie 403 przy logowaniu;
- zatrzymanie startu przy próbie użycia lokalnej skrzynki dla publicznego originu oraz przy niepoprawnej wartości flagi.

Testy fail_closed i sqlite nadal sprawdzają odmowę dostępu przy zamkniętej puli, klucze obce oraz brak ponownego przydzielania usuniętych identyfikatorów.

## Scenariusze ataków

Brak/fałszywa sesja, IDOR, SQLi, błędny klucz i zmieniony szyfrogram, zaszyfrowany plik z nazwą sugerującą ścieżkę, payload XSS i nagłówki, równoległy jednorazowy odczyt, błędne i za duże dane, obcy Origin, unieważnienie sesji po wylogowaniu i brute force ze zmienianymi nagłówkami IP. Z 8 równoległych odczytów jednorazowych nadal wygrywa dokładnie jeden.

Pomocniczy moduł local-mail.mjs jest częścią niezależnych skryptów testowych. Odczytuje plik z lokalnego środowiska testera; aplikacja nie ujawnia tokenu przez publiczne API. SMTP nie jest wymagane do tych testów. TEST_MAIL_DIR musi wskazywać ten sam katalog, co MAIL_OUTBOX_DIR serwera.

## Zakres i ograniczenia wykonania

W przeglądarce wykryto i poprawiono obsługę linku otwieranego w już istniejącej karcie (hashchange). Kontrola po przebudowaniu potwierdziła odczyt linku, wyczyszczenie fragmentu i przejście całego procesu. Pomocnicze przygotowanie odebranej wiadomości wymagało wskazania właściwego katalogu poczty testowej; po poprawieniu ustawienia podział list potwierdzono w DOM.

Nie testowano zewnętrznego dostarczenia SMTP, realnego upływu pełnych 30 minut tokenu e-mail, godziny sesji, publicznego DDoS ani wszystkich rozmiarów ekranu. Token e-mail wygaszono przez kontrolowaną zmianę czasu w bazie testowej. Nie utworzono płatnych zasobów ani usług w koncie użytkownika.

Kopie znalezionych starych baz zachowano w ignorowanym .tools/backups/ i zweryfikowano ich zgodność SHA-256. Starego schematu z nazwami użytkowników aplikacja nie nadpisuje automatycznie. Dane i poczta testowa oraz toolchain pozostają w .tools/, poza kontekstem Docker i repozytorium. Zrzut interfejsu: [interface.jpg](interface.jpg).

Proces serwera uruchomiony do testów został zatrzymany. Końcowe poprawki komunikatów crypto.js zmieniają wyłącznie nazwy wyświetlane użytkownikowi; algorytmy i format szyfrowania pozostały te same.
