# IncogniFile

Mała aplikacja do przesyłania zaszyfrowanych wiadomości i plików. Notatki, tymczasowe wiadomości i pliki do 512 KiB są szyfrowane w przeglądarce przed wysłaniem. Jeden proces aplikacji, baza SQLite w pliku, bez usług płatnych i osobnego serwera bazy.

## Uruchomienie

Z zainstalowanym Rust i narzędziami kompilacji:

```powershell
cargo run --locked
```

Otwórz [http://localhost:8080](http://localhost:8080). Aplikacja sama tworzy `incognifile.db` i tabele. Nie instalujesz SQLite, nie zakładasz konta bazy, nie ustawiasz hasła ani `.env`.

Alternatywnie, jeśli masz Docker z Compose:

```powershell
docker compose up --build
```

Compose uruchamia **wyłącznie aplikację**. Baza jest w tymczasowym katalogu kontenera i znika po jego zatrzymaniu. Przy uruchomieniu natywnym plik pozostaje na dysku; do resetu zatrzymaj aplikację i usuń jej testowy `incognifile.db`.

Domyślny adres to `http://localhost:8080`. Frontend jest osadzany w programie podczas kompilacji, więc jego zmiany wymagają przebudowania i ponownego uruchomienia serwera. Jeśli otwierasz stronę przez `127.0.0.1` lub wdrażasz ją pod innym adresem, ustaw dokładny `APP_ORIGIN`, bez końcowego ukośnika. Opcjonalne ustawienia:

```powershell
$env:APP_ORIGIN = 'http://127.0.0.1:8080'
$env:PORT = '8080'
$env:DATABASE_URL = 'sqlite:incognifile.db'
cargo run --locked
```

Rust nie wczytuje `.env` automatycznie; Compose korzysta z niego opcjonalnie. Zmienna DATABASE_URL wybiera plik, nie usługę sieciową. Katalog nadrzędny musi istnieć i być zapisywalny. Niepoprawna konfiguracja lub błąd bazy zatrzymuje start. Stare bazy innych silników nie są migrowane.

## Weryfikacja e-mail: flaga i lokalne testowanie

Domyślnie potwierdzenie adresu jest wyłączone, również w konfiguracji Render. Flaga w kodzie jest w **src/config.rs**:

```rust
pub const REQUIRE_EMAIL_VERIFICATION: bool = false;
```

Zmień na `true`, aby włączyć weryfikację do demonstracji lokalnej. Po zmianie zatrzymaj i ponownie uruchom aplikację. Alternatywnie bez edycji kodu:

```powershell
$env:REQUIRE_EMAIL_VERIFICATION = 'true'
cargo run --locked
```

Zmienna środowiskowa ma pierwszeństwo przed stałą. Ustaw `true` lub `false`; brak albo pusta wartość oznacza domyślną stałą z kodu. To ustawienie backendu; użytkownik nie może wyłączyć go parametrem żądania. Konto utworzone przy wyłączonej fladze pozostaje niepotwierdzone i po ponownym włączeniu weryfikacji musi potwierdzić adres.

**Lokalnie nie trzeba podłączać poczty.** Po włączeniu weryfikacji, przy domyślnym `MAIL_DELIVERY=local`, po rejestracji aplikacja zapisuje wiadomość w pliku `.mail/ID_KONTA.eml`. Otwórz ten plik jako tekst w edytorze, skopiuj link do przeglądarki i naciśnij „Potwierdź adres e-mail”. Następnie zaloguj się. Pliki nie są udostępniane przez HTTP. Ten tryb jest symulacją dostarczenia poczty, nie dowodem posiadania prawdziwej skrzynki; wolno go używać tylko z originem localhost.

W Dockerze poczta lokalna jest w `/app/data/.mail` wewnątrz kontenera. Do testów HTTP z hosta najprościej wyłączyć weryfikację przez zmienną środowiskową przed `docker compose up`. Przy natywnym uruchomieniu skrypty ataków automatycznie odczytują lokalne pliki weryfikacyjne; jeśli ustawisz inny MAIL_OUTBOX_DIR, podaj tę samą ścieżkę skryptom przez TEST_MAIL_DIR.

Link jest jednorazowy i ważny 30 minut. Przycisk „Wyślij ponownie link” wymaga e-maila i hasła konta, tworzy nowy link i unieważnia poprzedni. Błąd dostarczenia nie potwierdza konta. Skrót tokenu jest zapisany w bazie; jawny token trafia tylko do wiadomości. Link używa fragmentu `#verify=...`; przeglądarka usuwa go z paska i wysyła token POST dopiero po kliknięciu potwierdzenia.

**Rzeczywista wysyłka:** ustaw MAIL_DELIVERY=smtp, SMTP_HOST, SMTP_PORT (domyślnie 587), SMTP_USER, SMTP_PASSWORD i MAIL_FROM (adres nadawcy). Użyj istniejącej skrzynki/serwera SMTP; nie jest wymagany konkretny płatny dostawca. Biblioteka wymaga STARTTLS i sprawdza certyfikat. Bez prawdziwego SMTP nie obiecujemy dostarczenia do skrzynki. Nie dodano resetowania hasła ani zmiany adresu.

Adres e-mail zastępuje nazwę użytkownika także przy wskazywaniu odbiorcy. Obsługujemy typowe adresy ASCII do 254 znaków; porównujemy je bez rozróżniania wielkości liter, bez usuwania plusów i kropek. Dotychczasowe konta z nazwami użytkowników wymagają nowej bazy. Stary plik zachowaj jako kopię; możesz wybrać nowy przez DATABASE_URL=sqlite:incognifile-email.db. Aplikacja wykrywa stary schemat i nie kasuje go automatycznie.

## Funkcje

- Konto na adres e-mail, opcjonalna weryfikacja adresu i sesja ważna godzinę; wylogowanie unieważnia sesję na serwerze.
- Notatka albo plik, właściciel oraz opcjonalnie jedno konto odbiorcy.
- AES-256-GCM przez Web Crypto; treść, rodzaj i nazwa pliku wewnątrz szyfrogramu.
- Ważność od minuty do 7 dni i opcjonalny jednorazowy odczyt.
- Klucz w pamięci karty; import/eksport pliku `.key`; opcjonalny zaszyfrowany sejf w przeglądarce i przycisk jego usunięcia.
- Limity prób logowania i rejestracji, rozmiaru żądań oraz pojemności demonstracyjnej.

Klucz przekaż odbiorcy **osobnym, bezpiecznym kanałem**. Sam dostęp do konta nie wystarcza do odszyfrowania. Nie ma ról administratora, znajomych ani zewnętrznego storage. SMTP jest opcjonalne i służy tylko do potwierdzania adresu konta; wiadomości użytkowników nadal są przekazywane wewnątrz aplikacji.

## Architektura

`Przeglądarka (HTML/CSS/JS + Web Crypto) → Rust/Axum + SQLite`

Jeden proces obsługuje API, osadzone pliki statyczne i lokalną bazę przez sqlx. SQLite przechowuje konta, skróty losowych tokenów sesji, szyfrogramy i metadane uprawnień. Brak bundlera i zależności npm. Node jest potrzebny tylko do skryptów testowych.

Jedno połączenie z bazą wystarcza dla demonstracji. Odczyt jednorazowy i kontrola pojemności korzystają z transakcji `BEGIN IMMEDIATE`: blokada zapisu jest zajmowana przed sprawdzeniem danych, a odpowiedź wysyłana dopiero po zatwierdzeniu zużycia sekretu. Zachowano parametryzowane SQL, Argon2 i szyfrowanie klienta.

## Testy

Uruchamiaj skrypty HTTP na lokalnej instancji z testowymi danymi. Odrzucają hosty inne niż loopback i nie podążają za przekierowaniami. Node 22+; nie potrzeba `npm install`.

```powershell
cargo test --all-targets --locked
npm test
# W drugim terminalu, gdy aplikacja już działa:
node security-tests/attacks.mjs http://127.0.0.1:8080
node security-tests/expiry.mjs http://127.0.0.1:8080
```

Skrypty pokazują żądanie, kod i skróconą odpowiedź oraz PASS/FAIL. Tokeny i hasła są maskowane. Kod wyjścia 1 oznacza błąd. Test TTL trwa około 62 sekund. Testy Rust nie wymagają zewnętrznej bazy; sprawdzają też odmowę dostępu po zamknięciu puli SQLite oraz działanie kluczy obcych.

Testy kryptografii importują dokładnie moduł używany przez frontend. Test HTTP sam nie dowodzi niewykonania XSS — procedurę DOM opisuje [scenariusz prezentacji](docs/DEMO.md). Aktualne wyniki: [weryfikacja](docs/VERIFICATION.md).

## Świadome ograniczenia

- **Dane demonstracyjne mogą zniknąć.** Na darmowym Render baza zostanie utracona po restarcie, ponownym wdrożeniu lub uśpieniu usługi. To akceptowany warunek projektu; nie dokładamy płatnego dysku ani zewnętrznej bazy.
- Jednorazowość oznacza jedno pobranie szyfrogramu, nie potwierdzone przeczytanie. Właściciel też zużywa sekret. Zły klucz lub utrata odpowiedzi nie przywraca odczytu. Lista nie zużywa sekretów.
- Wspólny klucz otwiera wszystkie zaszyfrowane nim dane. Wyciek klucza i bazy pozwoli odczytać pasujące szyfrogramy. Nowy klucz nie zmienia wcześniejszych danych; zachowuj kopie starych kluczy.
- Klucz i sesja znikają po przeładowaniu karty. Plik klucza jest jawny. Sejf chroni zapisaną kopię, nie odblokowany klucz podczas XSS.
- Serwer widzi konta, rozmiary, relację właściciel–odbiorca i TTL. Złośliwy serwer może dostarczyć JS przechwytujący klucz. Nie jest to pełny model zero-knowledge.
- Brak skanowania zaszyfrowanych plików. Frontend ich nie renderuje ani nie uruchamia, ale pobrany plik może być złośliwy.
- Jedna instancja. Limiter pamięciowy resetuje się po restarcie: 5 prób/konto i 100 globalnie na 15 minut, także poprawnych. Rejestracja: 20/15 minut. Możliwe czasowe blokowanie kont przez napastnika.
- Maksymalnie 20 rekordów na właściciela, 200 globalnie. Zużyte rekordy nie zawierają szyfrogramu, ale liczą się do limitu aż do usunięcia lub wygaśnięcia. Wygasłe dane są od razu niedostępne, usuwane z tabeli przy następnym tworzeniu wiadomości.

Szczegóły: [model bezpieczeństwa](SECURITY_REPORT.md), [darmowy hosting](docs/HOSTING.md).
