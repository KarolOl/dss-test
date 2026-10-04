# Analiza podpisów z EU DSS 6.5

Backend Java 21, Spring Boot 4.0.8, Maven. Początkowy katalog zawierał wyłącznie `.git`: nie było kodu, `pom.xml`, konfiguracji DSS ani konwencji pakietów. Implementacja znajduje się w `pl.dss`; nie dodano frontendu.

Publiczne API usługi:

```java
CompositeValidationReport validate(MultipartFile file);
CompositeValidationReport validate(MultipartFile file, List<MultipartFile> detachedContents);
```

Endpoint: `POST /api/signatures/validate`, `multipart/form-data`, część `file` oraz opcjonalne, powtarzalne części `detachedContents`. Treści odłączone należy przekazywać z oryginalnymi nazwami wymaganymi przez referencje. Nazwa i MIME nie wybierają validatora. `SignedDocumentValidator.fromDocument(...)` rozpoznaje zawartość przez fabryki DSS.

Przykładowe wywołanie dla uruchomionej aplikacji:

```powershell
curl.exe -X POST http://localhost:8080/api/signatures/validate -F "file=@C:/documents/document.pdf"
curl.exe -X POST http://localhost:8080/api/signatures/validate -F "file=@C:/documents/signature.p7s" -F "detachedContents=@C:/documents/original.pdf"
```

Polecenie uruchomienia, do wykonania przez użytkownika: `mvn spring-boot:run`. Wymagane JDK 21+ i Maven 3.6.3+. Nie wykonano tego polecenia podczas implementacji.

## Konfiguracja

W `pom.xml` importowany jest `dss-bom:6.5`. Moduły obejmują XAdES, CAdES, PAdES z PDFBox oraz ASiC-S/ASiC-E z XAdES/CAdES. Konieczne implementacje SPI to `dss-policy-jaxb`, `dss-cms-object`, `dss-crl-parser-x509crl` i `dss-utils-apache-commons`. `dss-policy-jaxb` dostarcza fabrykę domyślnej i własnej polityki XML; samo `dss-validation` jej nie dostarcza. `dss-service` obsługuje AIA i OCSP/CRL. Nie dodano własnych repozytoriów Maven; DSS 6.5 jest publikowane w Maven Central.

BOM DSS dziedziczy zarządzanie zależnościami z `sd-dss`, w tym starszy Logback 1.3.x. Jawne wpisy `dependencyManagement` zachowują zgodne wersje `logback-classic/core` z właściwości rodzica Spring Boot. Właściwości HttpClient/HttpCore wyrównano do 5.6.4/5.4.3: DSS używa HttpClient 5.6.4, a [POM tej wersji Apache](https://github.com/apache/httpcomponents-client/blob/rel/v5.6.4/pom.xml) wskazuje HttpCore 5.4.3. Dzięki temu zarządzanie wersjami Spring Boot nie cofa samego HttpCore do 5.3.x.

`DssConfiguration` tworzy konfigurację wyłącznie wtedy, gdy nie dostarczono beanów `CertificateVerifier` lub `ValidationPolicy`. Istniejący verifier można więc wstrzyknąć wraz ze zweryfikowanymi źródłami TL/LOTL, OCSP/CRL i własnymi opcjami. Usługa używa go bez zmiany konfiguracji. Tak samo zachowuje dostarczoną politykę i ustawiony poziom walidacji.

Domyślna konfiguracja ładuje jawnie wskazane certyfikaty zaufania PEM/DER (również pakiet certyfikatów), włącza online AIA/OCSP/CRL i pozostawia domyślne mechanizmy DSS. Nie dodaje do źródeł zaufania certyfikatów z przesłanego dokumentu. Puste źródło zaufania jest zgłaszane w logu; uruchomienie bez kotwic zaufania nie zapewni pozytywnej walidacji niezaufanych łańcuchów.

```yaml
dss:
  validation:
    trusted-certificates:
      - file:C:/dss/config/trusted-root.pem
    policy: file:C:/dss/config/validation-policy.xml
    level: ARCHIVAL_DATA
    max-total-upload-bytes: 20971520
    network-timeout-millis: 10000
```

Nieprawidłowy plik polityki/certyfikatu powoduje błąd inicjalizacji; nie ma cichego przejścia na inną politykę. Bez własnej polityki ładowana jest polityka domyślna DSS. Statyczne kotwice zaufania nie zastępują list TL/LOTL potrzebnych do pełnej oceny kwalifikacji eIDAS. Integracja takich list powinna dostarczyć odpowiednio skonfigurowany `CertificateVerifier`.

Każdy przebieg dostaje nowy validator, nowy `DSSDocument` oraz nowe dokumenty odłączone. Wspólny verifier i polityka pozostają konfiguracją aplikacji. Wywołania DSS są synchronizowane na verifierze, ponieważ dostarczony verifier może zawierać pomocnicze obiekty przechowujące bieżący kontekst walidacji. Przebiegi w tej instancji aplikacji są przez to wykonywane kolejno. Nie należy zmieniać konfiguracji verifiera/polityki w trakcie obsługi żądań.

## Algorytm i znaczenie czasu

1. Odczyt ograniczonego rozmiarem wejścia do `InMemoryDocument`, automatyczny wybór validatora DSS i ustawienie wspólnej konfiguracji.
2. Walidacja całego dokumentu bez `setValidationTime`. Zachowanie oryginalnego `Reports` i czasu z `SimpleReport.getValidationTime()`.
3. Odczyt wszystkich identyfikatorów z raportu, w tym kontrasygnat. Sprawdzenie zgodności identyfikatorów SimpleReport i DiagnosticData; brak wyniku nie staje się wynikiem pozytywnym.
4. Podpis kwalifikuje się dokładnie wtedy, gdy `indication != TOTAL_PASSED`, `bestSignatureTime` jest równy zapamiętanemu czasowi pierwszej walidacji i dostępny jest deklarowany `signingTime`. Braki lub niespełnione warunki mają jawną przyczynę `SKIPPED`. `signingDate` oznacza tutaj to samo co `signingTime`; osobnego pola o tej nazwie nie ma.
5. Dla każdego zakwalifikowanego podpisu nowy validator ponownie waliduje **cały dokument**, ustawiając czas na jego `signingTime`. Z raportu wybierany jest tylko wynik o docelowym `signatureId`. Nie zakłada się zgodności kolejności. Nie ma rekursji ani dalszych prób. Każdy podpis ma własny dodatkowy przebieg, również przy wspólnym czasie podpisania.
6. Wynik dodatkowy zastępuje efektywny wpis zawsze po udanym technicznie odczycie wyniku, także dla `TOTAL_FAILED`/`INDETERMINATE`. Pozostałe wpisy zachowują wynik pierwszego przebiegu. Awaria techniczna pozostawia pierwotny wynik i `TECHNICAL_FAILURE`. Licznik poprawnych podpisów jest liczony od nowa wyłącznie z końcowych `TOTAL_PASSED`.

`bestSignatureTime` jest czasem istnienia podpisu przyjętym przez algorytm DSS. Kod procesu LTV inicjalizuje go czasem walidacji; odpowiednie zaakceptowane dowody istnienia mogą go przesunąć w przeszłość. Raport archiwalny uwzględnia dodatkowe dowody. Równość z czasem walidacji jest regułą kwalifikacji tego zadania, a nie ogólnym dowodem braku znacznika czasu. Wpis wskazuje osobno czas przebiegu i `bestSignatureTime`; ten drugi nie jest osobną datą uruchomienia validatora dla podpisu.

Weryfikacja tej interpretacji: [dokumentacja DSS 6.5](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html), sekcje 7.4 oraz 22.6; [kod procesu LTV w tagu 6.5](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/process/vpfltvd/ValidationProcessForSignaturesWithLongTermValidationData.java), [odczyt bestSignatureTime](https://github.com/esig/dss/blob/6.5/dss-detailed-report-jaxb/src/main/java/eu/europa/esig/dss/detailedreport/DetailedReport.java).

Daty są zamieniane bezpośrednio z `Date.getTime()` na `Instant.ofEpochMilli(...)`, a następnie porównywane przez `Instant.equals`. Zachowana jest precyzja milisekundowa obiektów DSS, bez tolerancji i bez obcinania do sekund. Ułamki sekund mogą być już niedostępne w niektórych źródłach podpisu; aplikacja nie dopisuje brakującej precyzji. Nie serializuje i nie odczytuje ponownie XML do porównań: adapter `DateParser` DSS 6.5 zapisuje daty w XML z precyzją sekundową, choć obiekty raportu mogą mieć milisekundy.

**Deklarowany `signingTime` nie jest zaufanym dowodem istnienia podpisu.** Wynik `SIGNING_TIME_REVALIDATION` jest oceną warunkową przy tym założeniu o czasie. Nawet `TOTAL_PASSED` z dodatkowego przebiegu nie dowodzi, że podpis rzeczywiście istniał w zadeklarowanym czasie, ani nie zastępuje pierwotnego raportu DSS do celów dowodowych. Historyczne OCSP/CRL mogą być niedostępne; dodatkowy przebieg może nadal zwrócić wynik negatywny lub nieokreślony.

## Raport i błędy

DTO zawiera dokładnie jeden `SignatureEntry` na identyfikator: `original`, `effective` i `revalidation`. Każdy snapshot zawiera źródło, faktyczny czas przebiegu, format/poziom, kwalifikację, oba czasy podpisu, statusy, błędy i ostrzeżenia AdES/kwalifikacji, certyfikat i jego łańcuch, diagnostyczne dane unieważnienia, znaczniki czasu i stan referencji. Relacja `parentSignatureId` pochodzi z `SignatureWrapper.getParent()`. Status znacznika pochodzi z raportu, a nie z faktu jego obecności. Informacja o kotwicy zaufania albo obecności danych unieważnienia sama w sobie nie jest oceną ważności certyfikatu.

`originalDssReports()` zachowuje obiekty `Reports` pierwszego przebiegu oraz mapę dodatkowych raportów po docelowym `signatureId`. Po błędzie mapowania dodatkowego wyniku zachowywany jest również raport, który DSS zdążył zwrócić. Nie modyfikuje się SimpleReport, DetailedReport, DiagnosticData ani ETSI. Obiekty należy traktować jako tylko do odczytu.

Surowe `Reports` są celowo oznaczone `@JsonIgnore`: są dostępne dla wywołującego usługę w Javie, nie są serializowane jako graf JAXB w odpowiedzi REST. Nie ma globalnego cache, trwałego archiwum ani udostępniania raportów innym żądaniom. Jeśli potrzebny jest trwały audyt, wywołujący może archiwizować oryginalne raporty poprzez dostępne `getXmlSimpleReport()`, `getXmlDetailedReport()`, `getXmlDiagnosticData()` i `getXmlValidationReport()`.

| Sytuacja | Wynik |
|---|---|
| Pusty plik / brak części `file` | HTTP 400 i kod aplikacyjny |
| Przekroczony limit | HTTP 413 |
| Brak fabryki rozpoznającej dokument | HTTP 415 `UNSUPPORTED_OR_UNRECOGNIZED_DOCUMENT` |
| Rozpoznany, ale uszkodzony dokument przy parsowaniu | HTTP 422 `MALFORMED_DOCUMENT` |
| Techniczny błąd pierwszej walidacji/raportu | HTTP 500 |
| Rozpoznany dokument bez podpisów | HTTP 200, `NO_SIGNATURES`, pusta lista, liczniki 0, oryginalny raport |
| Brak wymaganej treści podpisanej | HTTP 200, `MISSING_SIGNED_DATA`, szczegóły referencji i rzeczywisty wynik DSS |
| `TOTAL_FAILED` / `INDETERMINATE` | HTTP 200 z rzeczywistą oceną podpisu; nie jest to wyjątek techniczny |
| Błąd dodatkowego przebiegu | HTTP 200, pierwotny wpis oraz `TECHNICAL_FAILURE` |

Brak treści jest wykrywany na podstawie `SIGNED_DATA_NOT_FOUND` i diagnostycznych referencji danych z `dataFound=false`; obejmuje to podpisy odłączone i brakującą zawartość kontenera. Podanie błędnej treści może dać `dataFound=true`, `dataIntact=false` i wynik negatywny — nie oznacza to braku treści. Serwis nie pobiera oryginału na podstawie nazwy pliku i nie zakłada, że `.p7s` wystarcza. Dodatkowy przebieg nie odzyska brakujących danych.

DSS może nie rozpoznać bardzo uszkodzonego pliku. Wtedy nie ma wiarygodnego rozróżnienia od nieobsługiwanego formatu bez własnego parsera; kod błędu 415 jawnie uwzględnia oba przypadki. Dowolny nieobsługiwany plik bez podpisów również otrzyma 415; `NO_SIGNATURES` dotyczy dokumentów rozpoznanych przez DSS.

## Przykład i weryfikacja

[Przykład raportu](docs/example-composite-report.json) przedstawia trzy podpisy PAdES. Tylko `sig-2` ma niepozytywny wynik, czas odniesienia równy czasowi walidacji i zadeklarowany czas podpisania. Po jednym dodatkowym przebiegu jego wynik zostaje zastąpiony; `sig-1` i `sig-3` pozostają z pierwszego raportu. Licznik poprawnych rośnie z 1 do 2. Dane i skrócone identyfikatory są ilustracyjne, nie pochodzą z walidacji rzeczywistego dokumentu.

Wykonano przegląd statyczny implementacji, XML `pom.xml`, importów, sygnatur metod oraz kodu źródłowego i artefaktów **6.5**, w tym SPI i precyzji dat. Szczegóły: [weryfikacja API](docs/API-VERIFICATION.md). Zgodnie z poleceniem nie uruchomiono testów, kompilacji, serwera ani Mavenowego rozwiązywania pełnego grafu zależności. Nie można zatem traktować tej weryfikacji jako potwierdzenia wykonania całej aplikacji.

`SignatureValidationServiceTest` wywołuje publiczną metodę `validate(MultipartFile)` z rzeczywistym dokumentem CAdES zawierającym dwa podpisy różnych osób. Fixture `TwoSignatureDocument` generuje klucze RSA, certyfikaty, lokalny CA i osadzoną CRL; używa Bouncy Castle dostarczanego przez zależności DSS. Test nie wymaga sieci ani kontekstu Spring i nie mockuje validatora ani raportów DSS. Pierwszy przypadek sprawdza dwa wyniki `TOTAL_PASSED`, identyfikatory, certyfikaty, czasy, zachowanie oryginalnego raportu i pominięcie dodatkowej walidacji. Drugi zmienia osadzoną treść, pozostawiając oba podpisy, i oczekuje dwóch wyników `TOTAL_FAILED/HASH_FAILURE` oraz licznika poprawnych równego zero. Testy dodano bez ich uruchamiania; nie obejmują wszystkich formatów ani całego algorytmu dodatkowej walidacji.

Do weryfikacji wykonawczej po osobnym zleceniu: rzeczywiste dokumenty z wieloma podpisami i kontrasygnatami, ASiC-S/ASiC-E, podpis odłączony z poprawnym/błędnym/brakującym oryginałem, pliki uszkodzone i bez podpisów, dokładna równość/milisekundowa różnica czasów, pominięcie brakujących dat, niepozytywny wynik dodatkowy i awaria techniczna. Sprawdzić także wiarygodne źródła zaufania, historyczne dane OCSP/CRL oraz uruchomienie z wybranym poziomem i polityką.
