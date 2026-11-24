# Weryfikacja — 24 listopada 2026

Sprawdzono lokalny kod po poprawieniu niespójności API. Środowisko: Windows, Rust 1.100.0, Node 24.13.1. To testy konkretnych mechanizmów, nie formalny audyt ani dowód braku wszystkich podatności.

| Kontrola | Wynik |
|---|---|
| cargo test --all-targets --locked | 4 testy jednostkowe i 4 integracyjne: PASS |
| cargo fmt --all --check | PASS |
| cargo clippy --all-targets --locked -- -D warnings | PASS |
| cargo build --locked | PASS |
| npm test | 3 testy rzeczywistego modułu Web Crypto: PASS |
| Obsługa zdarzeń app.js z uproszczonym DOM | Logowanie, blokada podwójnego wysłania, szyfrowanie i zgodność JSON, eksport/czyszczenie klucza oraz walidacja formularza: PASS; bez renderowania w przeglądarce |
| docker compose config --quiet | Poprawność lokalnej konfiguracji Compose: PASS; bez budowania i uruchamiania kontenera |
| attacks.mjs, weryfikacja wyłączona | 11 scenariuszy HTTP: PASS |
| attacks.mjs, weryfikacja włączona i poczta lokalna | 11 scenariuszy HTTP: PASS |
| expiry.mjs, weryfikacja włączona | Odczyt przed TTL: 200; po 62 sekundach: 404 i brak rekordu na liście: PASS |
| Przeglądarka i rzeczywiste wykonanie DOM/XSS | Nie powtarzano w tej iteracji; procedura ręczna w DEMO.md |
| Zewnętrzne dostarczenie SMTP | Nie testowano; brak konfiguracji prawdziwej skrzynki |
| Budowanie i uruchamianie kontenera Docker | Nie powtarzano w tej iteracji |
| Publiczna instancja Render | Panel i logi przekazane przez użytkownika pokazały Live dla wcześniejszego commitu 1f6b382; te lokalne poprawki wymagają osobnego wdrożenia |

## Poprawione niespójności

- Backend oczekiwał encoded_text, additional_encryption, expiration_time_sec i single_use, a frontend wysyłał ciphertext, nonce, ttl_seconds i one_time. Wysyłanie zwracało 422. Przywrócono jeden kontrakt zgodny z frontendem i skryptami testowymi.
- Lista odczytywała kolumnę one_time do pola single_use bez aliasu, więc dla niepustej bazy zwracała 503. Pole odpowiedzi ponownie nazywa się one_time.
- Komentarz przy rezerwacji limitu rekordów błędnie mówił o ataku czasowym. Transakcja chroni tutaj przed wyścigiem równoległych żądań.
- Domyślna flaga weryfikacji w dokumentacji i przykładowym środowisku nie zgadzała się z false w kodzie. Opis i przykład są teraz zgodne; włączenie lokalne wymaga true.
- Walidacja APP_ORIGIN sprawdza pełną strukturę originu zamiast samego prefiksu. Odrzuca ścieżki, poświadczenia, query, fragmenty i niepoprawny port; dopuszcza też lokalny IPv6.
- Długość hasła konta była liczona w bajtach, inaczej niż w formularzu. Backend liczy teraz jednostki UTF-16 tak jak HTML/JavaScript, również dla polskich znaków i emoji.
- Formularze nie blokowały ponownych akcji podczas operacji asynchronicznej. Interfejs serializuje akcje i czasowo wyłącza kontrolki; walidacja odbywa się przed ich wyłączeniem. Żądanie API ma limit 90 sekund, aby blokada nie pozostała na czas nieokreślony.
- Oba skrypty HTTP sprawdzają lokalny adres bez poświadczeń, query i fragmentu, nie podążają za przekierowaniami i pokazują także tekstowe odpowiedzi błędów Axum.

## Testy regresji i bezpieczeństwa

Nowy tests/messages.rs uruchamia prawdziwy lokalny HTTP i SQLite w pamięci. Sprawdza publiczny JSON: zapis, niepustą listę właściciela i odbiorcy, pole one_time i metadane bez szyfrogramu. Sprawdza także odmowę odczytu obcemu kontu, odmowę usunięcia przez odbiorcę, dwa równoległe odczyty jednorazowe z jednym zwycięzcą, wyczyszczenie szyfrogramu, powtarzalny odczyt zwykłej wiadomości, wygaśnięcie oraz odrzucenie nieznanych pól. Test używa koperty poprawnej strukturalnie; rzeczywiste szyfrowanie jest sprawdzane przez testy Node i scenariusze HTTP importujące frontend/crypto.js.

Test email_verification obejmuje oba tryby flagi, brak jawnego tokenu w API, skrót w bazie, odmowę logowania przed potwierdzeniem, resend i unieważnienie starego linku, wygasły i fałszywy token, jednorazowe potwierdzenie przy równoległych żądaniach oraz fail-closed przy błędzie dostarczenia i konfiguracji. Wygaśnięcie tokenu e-mail symuluje zmianą czasu w testowej bazie.

Test fail_closed sprawdza brak dostępu przy zamkniętej puli SQLite i jawnie wyłącza weryfikację, niezależnie od ustawień środowiska testera. Test sqlite sprawdza klucze obce i brak ponownego użycia usuniętego ID. Testy jednostkowe obejmują limiter, równoległe próby, walidację originu oraz długość haseł Unicode.

Skrypty ataków sprawdzają brak i fałszywą sesję, IDOR, SQLi, błędny klucz i zmieniony szyfrogram, zaszyfrowany plik z nazwą sugerującą ścieżkę, przeniesienie payloadu XSS i nagłówki ochronne, jednorazowy odczyt przy 8 równoległych żądaniach, limity rozmiaru i TTL, obcy Origin, wylogowanie oraz brute force ze zmienianymi nagłówkami IP. Test HTTP nie wykonuje DOM i nie zastępuje ręcznej próby XSS w przeglądarce.

## Zakres wykonania

Scenariusze HTTP wykonano na dwóch osobnych, tymczasowych instancjach loopback ze świeżą bazą w pamięci, bez dotykania danych lokalnej aplikacji ani hostingu. Procesy testowe zatrzymano po zakończeniu. Logi przebiegu są w ignorowanym katalogu .tools/audit-*.log; lokalna poczta testowa również pozostaje poza repozytorium i kontekstem Docker.

Nie sprawdzano w tej iteracji pełnej godziny sesji, rzeczywistych 30 minut ważności linku e-mail, zewnętrznego SMTP, publicznego DDoS ani interfejsu w prawdziwej przeglądarce. Przed prezentacją wykonaj [scenariusz ręczny](DEMO.md), szczególnie dla XSS, importu/eksportu klucza i lokalnego sejfu. Zrzut [interface.jpg](interface.jpg) pochodzi z wcześniejszej kontroli interfejsu z 23 listopada; nie jest dowodem aktualnych testów.

Status /health sprawdza SELECT 1, a nie cały przepływ aplikacji. Niepusta lista i przesłanie wiadomości wymagają osobnych testów — właśnie dlatego dodano test regresji API.
