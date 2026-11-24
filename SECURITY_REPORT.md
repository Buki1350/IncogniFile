# Model bezpieczeństwa IncogniFile

## Granice zaufania i decyzje

Chronimy przed innym użytkownikiem, przypadkowym wyciekiem zawartości bazy, wstrzyknięciami oraz powtarzalnymi próbami logowania. Przeglądarka i dostarczony kod aplikacji muszą być zaufane. Zainfekowany komputer, rozszerzenia przeglądarki, administrator hostingu zmieniający JS i przejęcie odblokowanej karty są poza tą gwarancją. TLS chroni transport; szyfrowanie klienta nie zastępuje HTTPS.

Nie dodano kont administratora mających dostęp do cudzych danych. Nie ma trybu niezabezpieczonego ani opcjonalnego szyfrowania. API przyjmuje wyłącznie ograniczone rozmiarem koperty Base64. Nie może udowodnić, że klient rzeczywiście je zaszyfrował: bezpośredni klient API może przesłać dowolne bajty poprawnego formatu.

## Klucz i lokalne przechowywanie

| Opcja | Korzyść | Ryzyko / koszt | Decyzja |
|---|---|---|---|
| Pamięć karty | Brak trwałej kopii; mało kodu | Utrata po przeładowaniu; XSS ma dostęp podczas użycia | Domyślnie |
| Jawny plik klucza | Przenośna kopia, działa bez przeglądarkowego magazynu | Kradzież pliku daje klucz; użytkownik musi zabezpieczyć kopię | Import / eksport |
| Cookie | Automatyczna dostępność na żądaniach | Klucz trafiałby na serwer; HttpOnly uniemożliwia Web Crypto w JS; nie-HttpOnly dostępne dla XSS | Odrzucono |
| sessionStorage z jawnym kluczem | Przetrwanie odświeżenia | Dostępne dla XSS; niepotrzebnie dłuższa ekspozycja | Odrzucono |
| localStorage z zaszyfrowanym kluczem | Prosty sejf bez nowej zależności | Słabe hasło podlega atakowi offline; XSS może ukraść sejf, hasło i odblokowany klucz | Opcjonalnie |
| IndexedDB / CryptoKey | Ustrukturyzowane dane, klucz nieeksportowalny | Więcej kodu; XSS nadal może użyć klucza do odszyfrowania | Pominięto |

Sejf przechowuje tylko 32-bajtowy klucz zaszyfrowany AES-256-GCM; hasło sejfu nigdy nie trafia do API. PBKDF2-HMAC-SHA256: 600000 iteracji, losowa sól 16 bajtów, nowe IV 12 bajtów, osobne AAD sejfu. Hasło: 12–128 znaków, zalecana długa losowa fraza różna od hasła konta. Nie zapisujemy jawnego klucza, hasła ani sesji w local/sessionStorage. Format sejfu ma stałe parametry, aby podmienione dane nie wymusiły dowolnie kosztownego KDF.

Przycisk usunięcia kasuje wpis `incognifile.vault.v1`, aktywny bufor i podgląd. Nie usuwa plików z dysku, kopii przeglądarki ani synchronizowanych backupów. JavaScript i garbage collector nie zapewniają bezpiecznego wyzerowania wszystkich kopii pamięci. Sejf jest wspólny dla originu i profilu przeglądarki, a nie powiązany z kontem.

Treść: losowy 256-bitowy klucz, AES-GCM, IV 96 bitów losowane przy każdym szyfrowaniu, tag 128 bitów, AAD `IncogniFile:v1`. Biblioteką jest Web Crypto, nie własny algorytm. Błędny klucz, IV lub modyfikacja szyfrogramu kończy się błędem uwierzytelnienia. AAD rozdziela formaty, ale nie wiąże serwerowych metadanych właściciela i TTL — nie chronimy przed złośliwym administratorem bazy/serwera. Brak automatycznej dystrybucji kluczy, PKI i odzyskiwania klucza: oszczędność zakresu kosztem wygody i izolacji kluczy.

Podstawa parametrów: [MDN AES-GCM](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams), [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). PBKDF2 dotyczy wyłącznie lokalnego sejfu; hasła kont używają zachowanego Argon2id (domyślne parametry biblioteki: m=19456 KiB, t=2, p=1, losowa sól).

## Mechanizmy i ich weryfikacja

| Zagrożenie | Ochrona | Dowód i granica |
|---|---|---|
| SQL Injection | Stałe zapytania sqlx i `.bind()`, numeryczny ekstraktor ścieżki | HTTP: payload w adresie e-mail i odbiorcy, nieprawidłowe ID; przegląd wszystkich zapytań. Walidacja jest dodatkowa, parametryzacja pozostaje podstawą. |
| XSS | `textContent`, brak HTML z danych; brak podglądu plików; ścisła CSP, nosniff | Test przeniesienia payloadu i nagłówków + scenariusz DOM w przeglądarce. Sam test HTTP nie dowodzi niewykonania skryptu. |
| Brute force | Atomowa rezerwacja przed Argon2, 5 prób/konto, 100 globalnie/15 min; 20 rejestracji/15 min; 2 równoległe operacje Argon2 | Test HTTP zmienia X-Forwarded-For i X-Real-IP, nadal 429. Test równoległego limitera. Limit pamięciowy resetuje restart i nie nadaje się do wielu replik. |
| IDOR | Właściciel lub przypisany odbiorca w SQL odczytu/listy; usunięcie tylko właściciel | HTTP: trzecie konto nie widzi rekordu, odczyt i DELETE zwracają 404; odbiorca nie może kasować. |
| Sesje | 32 losowe bajty z OsRng; token Bearer tylko w pamięci; SHA-256 tokenu w DB; TTL 1h; usuwanie przy logout | HTTP: brak, fałszywy token, cookie i token po logout dają 401. Brak odświeżania sesji i resetu haseł. |
| Fail-closed | Błędy SQL ->503, brak sesji ->401; zatrzymanie startu bez bazy; brak fallback do roli/uprawnień | Test Rust uruchamia prawdziwy HTTP z niedostępną bazą; odpowiedź nie zawiera szyfrogramu. |
| Niebezpieczny upload | Maks. żądanie 1100000 B, szyfrogram 1000000 znaków Base64, frontend plik 512 KiB; brak ścieżek zapisu, dane w lokalnym SQLite | HTTP: błędny IV/Base64, zbyt duży payload ->400/413. Klient API może ominąć frontendowy limit pliku, nie serwerowy limit koperty. |
| Wykonanie pliku | Szyfrowana nazwa; po odszyfrowaniu Blob application/octet-stream + a.download; nazwa bez separatorów ścieżki | Pliki nie są publikowane jako URL z HTML ani wykonywane na serwerze. Brak AV jest świadomym ograniczeniem szyfrowania klienta. |
| CSRF | Brak cookie uwierzytelniającego i innego automatycznie dołączanego poświadczenia; wymagany Bearer; brak CORS; odrzucanie obcego Origin | HTTP: cookie bez Authorization ->401, obcy Origin nawet z tokenem ->403. Osobny token CSRF nie jest potrzebny dla tej architektury; XSS nadal może wykonać żądanie. |
| Jednorazowy odczyt | Transakcja BEGIN IMMEDIATE: blokada zapisu przed sprawdzeniem uprawnień i TTL, wyczyszczenie szyfrogramu i commit przed wydaniem | HTTP: 8 równoległych żądań ->1 sukces, 7 razy 404; wcześniejszy IDOR i listowanie nie zużywają sekretu. Szyfrogram w DB jest czyszczony. |
| Wygaśnięcie | Czas SQLite (unixepoch, UTC), sprawdzenie przy każdym odczycie i listowaniu | Osobny test TTL=60 sekund, później 404; usunięcie rekordu przy następnym tworzeniu. |
| Zużycie zasobów | Limity żądań, połączeń, Argon2 i rekordów; quota w transakcji BEGIN IMMEDIATE | Nie jest to ochrona przed DDoS. Limit globalny pozwala celowo odmówić innym dostępu; przy publicznym hostingu potrzebne limity na brzegu. |

## Co pozostaje poza zakresem

Brak MFA, automatycznej rotacji, audytu zewnętrznego, skanowania malware, anonimowych linków, logowania do zewnętrznego IdP, HA i rozproszonego limitera. Zmiana hasła konta i odzyskiwanie konta wymagałyby dodatkowych przepływów, których nie dodano. Jednorazowość nie powstrzyma odbiorcy przed skopiowaniem już pobranej treści. Czas ważności nie cofa dostępu do istniejących kopii.

Nie zapisujemy treści ani tokenów w logach aplikacji. Logujemy tylko rodzaj błędu bazy; platforma i reverse proxy wymagają osobnej konfiguracji. Backup może zawierać stare szyfrogramy i skróty haseł. Projekt nie jest poddany formalnemu audytowi i testy nie dowodzą braku wszystkich podatności.

## SQLite i reset danych

Baza jest lokalnym plikiem, bez osobnej usługi, hasła ani portu sieciowego. sqlx jawnie włącza klucze obce dla połączenia; identyfikatory AUTOINCREMENT nie są ponownie używane po usunięciu sekretu w tej samej bazie. Jedno połączenie i transakcje BEGIN IMMEDIATE upraszczają synchronizację. Błąd otwarcia, blokady lub zatwierdzenia bazy odmawia dostępu; nie wysyłamy szyfrogramu przed commit.

Na darmowym hostingu akceptujemy utratę całej bazy po resecie. Lokalny plik bazy i pliki pomocnicze są wykluczone z Git i kontekstu budowania Docker. Nie są dostępne przez routing HTTP. Dostęp systemowy do pliku daje dostęp do metadanych i skrótów haseł, a treść wymaga klucza klienta. Nie dodano płatnej infrastruktury dla trwałości danych.

## Konta e-mail i weryfikacja adresu

Weryfikacja jest domyślnie wyłączona (stała false w src/config.rs, nadpisywana zmienną REQUIRE_EMAIL_VERIFICATION). Aby zademonstrować potwierdzanie adresu lokalnie, ustaw true. Wyłączenie jest celowym wariantem demonstracyjnym: wtedy adres jest tylko deklarowanym identyfikatorem i można zarejestrować cudzy adres. Po włączeniu flagi sprawdzamy stan email_verified przy logowaniu i przy każdym uwierzytelnionym żądaniu, również dla sesji utworzonych wcześniej. Nie zapisujemy „zweryfikowany” tylko dlatego, że flaga była wyłączona.

Token: 32 losowe bajty OsRng, SHA-256 w tabeli email_verifications, TTL 30 minut. Potwierdzenie zużywa token i aktualizuje konto w transakcji BEGIN IMMEDIATE. Ponowne wysłanie wymaga hasła, podlega limiterowi logowania i unieważnia poprzedni token. Nie ma auto-logowania po kliknięciu linku. Niepowodzenie SMTP pozostawia konto niepotwierdzone; dostęp jest odmawiany. Nie dodano endpointu zwracającego jawny token ani publicznej skrzynki testowej.

Tryb local zapisuje pocztę w prywatnym, ignorowanym katalogu .mail, niewystawionym przez routing HTTP; na Unix katalog otrzymuje 0700. To wyłącznie symulacja dostarczenia do lokalnej demonstracji. Włączenie jej dla publicznego originu z wymaganą weryfikacją blokuje start. Prawdziwa weryfikacja własności skrzynki wymaga SMTP (STARTTLS z walidacją certyfikatu) i dostępu odbiorcy do rzeczywistej poczty. Hasło SMTP nie trafia do repo. Lokalnych plików .eml nie wolno publikować, ponieważ zawierają tokeny.

Link korzysta z fragmentu URL, który nie jest przesyłany w żądaniu strony. Interfejs usuwa fragment i wymaga kliknięcia przed POST, aby zwykłe pobranie strony przez skaner linków nie zużyło tokenu. Nie jest to gwarancja wobec skanerów wykonujących pełne interakcje. Parametry oparto o [OWASP Email Verification](https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html); konfiguracja TLS: [lettre STARTTLS](https://docs.rs/lettre/latest/lettre/transport/smtp/struct.AsyncSmtpTransport.html#method.starttls_relay).

Adresy są ograniczone do powszechnego formatu ASCII i porównywane bez rozróżniania wielkości liter, również w części lokalnej. To jawna polityka identyfikatorów tej aplikacji; nie obsługuje wszystkich poprawnych według RFC form skrzynek. Rejestracja zwraca konflikt dla zajętego adresu, więc nie zapewniamy ukrywania faktu istnienia konta. Brak odzyskiwania konta pozostaje ograniczeniem projektu.
