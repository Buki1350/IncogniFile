# Scenariusz prezentacji

1. Uruchom pustą lokalną instancję. Zarejestruj dwa konta na adresy e-mail w dwóch profilach przeglądarki; przy włączonej weryfikacji otwórz odpowiednie linki z plików .mail i potwierdź adresy; nie korzystaj z wylogowania w tej samej karcie podczas tworzenia danych.
2. Na pierwszym koncie wygeneruj klucz, zapisz do pliku i zaszyfruj wiadomość dla drugiego konta. W Network pokaż, że wysyłane są `ciphertext`, `nonce`, odbiorca, TTL i flaga jednorazowości. Klucz i treść jawna nie trafiają do API. W bazie nazwa pliku i treść też nie są jawne.
3. Na drugim koncie wygeneruj inny klucz: odczyt zwykłej wiadomości nie odszyfruje danych. Wczytaj właściwy plik klucza: treść pojawi się lokalnie. Wyjaśnij osobny kanał przekazania klucza.
4. XSS: wyślij `<img src=x onerror="document.body.dataset.xss='executed'">` i `<script>alert(1)</script>` jako notatkę. Odszyfruj; znaczniki mają być widocznym tekstem. W DevTools sprawdź brak utworzonego elementu img/script w podglądzie i brak `document.body.dataset.xss`. Zobacz CSP w Network. To krok przeglądarkowy, którego test samego HTTP nie zastępuje.
5. Prześlij mały plik HTML z podobnym payloadem. Odszyfrowanie pokazuje tylko nazwę i przycisk pobrania; aplikacja nie renderuje treści. Nie otwieraj ręcznie pobranego pliku jako części testu bezpieczeństwa aplikacji.
6. Stwórz wiadomość jednorazowy. Lista nie zużywa odczytu. Pierwsze odszyfrowanie zużywa; kolejne żądanie daje 404. Zły klucz również zużywa pierwsze pobranie. Wyjaśnij brak gwarancji dostarczenia i brak możliwości cofnięcia skopiowanej treści.
7. Zapisz klucz w lokalnym sejfie z osobnym hasłem, odśwież stronę, zaloguj się i odblokuj. W Application/Local Storage pokaż, że jest tam zaszyfrowana koperta, nie jawny klucz. Usuń lokalny klucz i sprawdź zniknięcie wpisu i podglądu.
8. Uruchom `node security-tests/attacks.mjs`: pokaż IDOR, sfałszowaną sesję, SQLi, limity, 8 równoległych odczytów i tylko jeden sukces. Skrypt tworzy własne konta, nie potrzebuje ręcznie zarejestrowanych.
9. Uruchom `node security-tests/expiry.mjs` i `cargo test --test fail_closed --locked` dla TTL i awarii autoryzacji. Omów granicę modelu: administrator zmieniający frontend może przechwycić klucz.

Zapisany sejf jest wspólny dla originu i profilu, dlatego do demonstracji dwóch użytkowników używaj oddzielnych profili. Nie pokazuj prawdziwych haseł/tokenów i nie testuj na danych osobistych.

Weryfikację można porównać w dwóch trybach: REQUIRE_EMAIL_VERIFICATION=true odmawia logowania przed potwierdzeniem, a false pozwala zalogować niepotwierdzone konto. Samo wyłączenie flagi nie potwierdza adresu na stałe. Kompletny test automatyczny: cargo test --test email_verification --locked.
