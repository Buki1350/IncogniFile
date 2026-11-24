# Darmowy hosting demonstracyjny

IncogniFile wymaga tylko **jednego darmowego Docker Web Service**. Baza SQLite jest lokalnym plikiem w kontenerze. Nie dodawaj zewnętrznej bazy, Redis, object storage ani płatnego dysku.

## Render

W repozytorium jest render.yaml definiujący dokładnie jedną usługę Free we Frankfurcie, bez dodatkowej bazy ani dysku. Możesz użyć opcji New → Blueprint i wybrać to repozytorium. Automatyczne wdrażanie kolejnych commitów jest wyłączone. Alternatywnie utwórz Web Service ręcznie:

1. Utwórz Web Service z tego kodu, wybierz runtime Docker i plan **Free**.
2. Wykorzystaj główny Dockerfile. Aplikacja automatycznie odczytuje swój adres z RENDER_EXTERNAL_URL. APP_ORIGIN możesz ustawić ręcznie dla własnej domeny; ma pierwszeństwo. Nie wpisuj adresu zewnętrznej bazy. Na Free ustaw REQUIRE_EMAIL_VERIFICATION=false dla demonstracji bez prawdziwej poczty.
3. Render ustawia `PORT`, aplikacja nasłuchuje na `0.0.0.0`. Dockerfile ustawia `DATABASE_URL=sqlite:/app/data/incognifile.db` i przygotowuje zapisywalny katalog dla użytkownika bez uprawnień root.
4. Health check: `/health`, sprawdzający także SQLite. Nie konfiguruj trwałego dysku ani dodatkowych usług.

Free Web Service ma tymczasowy filesystem. Baza, konta, sesje i sekrety mogą zniknąć po restarcie, wdrożeniu lub uśpieniu; przy następnym starcie aplikacja automatycznie utworzy pustą bazę. **To zaakceptowany sposób działania projektu studenckiego.** Klucz zapisany w przeglądarce nie przywróci usuniętych z serwera szyfrogramów.

Usługa Free usypia po bezczynności i może potrzebować czasu na wybudzenie. Przed prezentacją otwórz stronę i utwórz dane testowe. Obowiązują limity darmowego planu; nie włączaj płatnych zasobów. Aktualne zasady: [Render Free](https://render.com/docs/free), [tymczasowy filesystem](https://render.com/docs/disks). Rozpoznanie: 23 listopada 2026. Nie utworzono usług ani nie wykonano wdrożenia na koncie użytkownika.

## Minimalne zabezpieczenia hostingu

- HTTPS z poprawnym certyfikatem i przekierowaniem z HTTP. Aplikacja wystawia HSTS dla originu HTTPS.
- Dokładny APP_ORIGIN i ten sam adres dla frontendu oraz API; brak szerokiego CORS.
- Jedna instancja. Plik bazy należy wyłącznie do procesu aplikacji; nie publikuj go przez serwer plików ani nie montuj socketu Dockera.
- Kontener działa jako UID 10001, katalog bazy ma uprawnienia 0700. W lokalnym Compose pozostały filesystem jest tylko do odczytu, a baza leży w tymczasowym katalogu RAM z limitem 256 MiB.
- Nie loguj Authorization, treści żądań ani odpowiedzi. Zabezpiecz konto hostingowe MFA, aktualizuj zależności i obrazy.
- Limity żądań i pojemności pozostają w aplikacji. Nie są ochroną przed publicznym DDoS; demonstrację ataków wykonuj lokalnie.

Lokalne uruchomienie nie wymaga konta w chmurze ani jakiejkolwiek płatności. Docker i Rust są alternatywnymi sposobami uruchomienia; w żadnym nie trzeba instalować serwera bazy.

## Poczta a darmowy hosting

Publiczny origin z włączoną weryfikacją wymaga MAIL_DELIVERY=smtp i poprawnej konfiguracji SMTP. Lokalna skrzynka plikowa nie potwierdza posiadania prawdziwego adresu i jest na publicznym originie zabroniona. Render Free blokuje typowe porty SMTP 25/465/587 ([warunki](https://render.com/docs/free)); nie deklarujemy działania standardowego SMTP na tym planie. Bez dokładania usług najprościej prezentować weryfikację lokalnie i jawnie wyłączyć ją flagą na Free. Własny serwer dostępny na innym porcie musi obsługiwać wymagany STARTTLS; zgodność i dostępność trzeba sprawdzić osobno.
