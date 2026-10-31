# Audyt raportu weryfikacji

PDF powstaje na końcu `SignatureValidationService.validate(...)`. Czytelne podsumowanie jest powiązane z danymi źródłowymi przez osadzone załączniki i manifest SHA-256. JSON dotychczasowego endpointu zachowuje dotychczasowe pola; oryginalne obiekty DSS i bajty PDF mają `@JsonIgnore`. Kod Java pobiera PDF przez `report.pdfReport()`.

`AuditPdfReportGenerator` tworzy treść i zapisuje PDF. Wstrzyknięty przez konstruktor `AuditPdfAttachmentService` przygotowuje XML/JSON i manifest, osadza załączniki, ustawia metadane audytu oraz domyślnie zamknięty panel załączników. Zwraca manifest i jego skrót do wykorzystania w treści raportu. Serwis załączników nie zapisuje ani nie zamyka dokumentu PDF; odpowiada za to generator. Refaktoryzacja tego podziału nie zmienia formatu pakietu. Po jej wykonaniu nie uruchamiano ponownie testów ani kompilacji; opis weryfikacji na końcu dotyczy poprzedniej wersji kodu.

## Wybór rozwiązania

Załączniki XML są właściwym miejscem na oryginalne raporty DSS. Są samodzielnymi plikami, można je wyodrębnić i przetwarzać zgodnie ze schematami DSS. XMP i pola informacji PDF nadają się do identyfikatora oraz skrótu manifestu, ale nie zastępują załączników z pełnymi danymi. [Dokumentacja DSS](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html) opisuje cztery raporty XML; [przykład Apache PDFBox 3.0.8](https://github.com/apache/pdfbox/blob/3.0.8/examples/src/main/java/org/apache/pdfbox/examples/pdmodel/EmbeddedFiles.java) pokazuje standardowe osadzanie plików.

Samo dołączenie XML-a zapewnia wgląd w wynik, lecz nie potwierdza jego pochodzenia. Manifest pozwala sprawdzić zgodność bajtów, powiązać dokument z raportami i wykryć zmianę względem znanego skrótu. Atakujący może jednak zmienić PDF, załączniki oraz wszystkie zapisane w nim skróty jednocześnie. Dlatego pakiet jawnie ma status `UNSEALED`, a data utworzenia pochodzi z zegara aplikacji.

Silniejszym rozwiązaniem jest podpis/pieczęć całego końcowego PDF obejmujący także załączniki, z zaufanym znacznikiem czasu, oraz przechowanie go w niezależnym repozytorium z kontrolą zmian. Nie dodano fikcyjnego podpisu ani certyfikatu testowego do produkcji: aplikacja nie ma skonfigurowanego klucza wystawcy, usługi podpisu/pieczęci ani TSA. Po wdrożeniu takiej usługi należy podpisać PDF po osadzeniu wszystkich danych, a skrót archiwizować po ostatniej modyfikacji/podpisie. Obecne skróty opisują bajty zwrócone przez obecną implementację.

Jeśli wymagane będzie wieloletnie archiwum, można rozważyć PDF/A-3 z walidacją zgodności oraz podpisem PAdES z danymi długoterminowymi albo osobny kontener ASiC z podpisanym pakietem dowodowym. Obecny plik jest zwykłym PDF z załącznikami; nie deklaruje zgodności PDF/A, PAdES ani kwalifikowanego charakteru raportu. Sam wybór formatu archiwalnego nie uwierzytelnia danych.

## Zawartość

Dla przebiegu pierwotnego i **każdego zwróconego** przebiegu dodatkowego osadzane są dwa raporty:

- `dss-<run>-detailed-report.xml`,
- `dss-<run>-diagnostic-data.xml`.

Diagnostic Data zachowuje dane wejściowe i ustalenia użyte przez walidację, a Detailed Report jej oryginalny wynik i przebieg oceny według polityki. Simple Report pozostaje używany do mapowania wyników w serwisie, ale jego XML nie jest osadzany, ponieważ podsumowanie jest już w PDF i JSON. ETSI Validation Report nie jest generowany ani osadzany; w tym zastosowaniu nie jest potrzebny dodatkowy standardowy format wymiany wyników.

PDF ma ustawiony `PageMode.USE_NONE`, więc nie żąda automatycznego otwarcia panelu załączników. Załączniki nadal można odczytać po ręcznym otwarciu panelu. To preferencja widoku, którą czytnik może nadpisać własnymi ustawieniami.

Pierwotny przebieg ma nazwę `default`, kolejne `revalidation-1`, `revalidation-2`, itd. Manifest mapuje nazwę przebiegu na docelowy `signatureId` i rzeczywisty czas walidacji. Dodatkowy raport nadal obejmuje cały dokument; tylko wybrany podpis może zmienić wynik aplikacji. Kolejność dodatkowych załączników jest ustalana po identyfikatorach podpisów. Identyfikatory podpisów i nazwy przesłanych dokumentów nie są używane jako ścieżki załączników.

XML pochodzi bezpośrednio z metod `Reports.getXml...()`, zapisany jako UTF-8; aplikacja go nie scala ani nie przepisuje. `TokenExtractionStrategy.EXTRACT_ALL` zachowuje dostępne binarne certyfikaty, dane unieważnienia, znaczniki czasu i evidence records w diagnostyce. Nie oznacza to, że brakujące dowody stają się dostępne. Zachowany zostaje także raport zwrócony przez przebieg zakończony później błędem mapowania lub niespójnym czasem. Jeśli przebieg rzuci wyjątek przed zwróceniem `Reports`, nie ma XML-a do osadzenia; próba i kod błędu pozostają w wyniku aplikacji.

Dodatkowe załączniki:

- `composite-report.json`: kompletny wynik aplikacji, pierwotne i efektywne wpisy, próby, przyczyny i błędy techniczne. Zachowuje precyzję `Instant` z obiektów Java; serializacja XML DSS może ograniczać daty do sekund. To rozróżnienie jest zapisane w manifeście.
- `validation-policy.xml`: dokładne bajty polityki domyślnej albo skonfigurowanej przez `dss.validation.policy`, odczytane **raz przy starcie**, z których utworzono faktycznie używaną politykę DSS. Zmiana pliku po starcie nie zmienia archiwum. Standardowa polityka XML korzysta z tej samej klasy bazowej DSS i tego samego unmarshallingu co fabryka DSS 6.5. Nie należy modyfikować obiektów polityki w działającej aplikacji.
- `audit-manifest.json`: wersja schematu, UUID raportu, czas utworzenia, wersje DSS/aplikacji (albo jawne `unknown`, jeśli metadane artefaktu są niedostępne), poziom walidacji, tożsamość i stan archiwizacji polityki, lista wejść oraz inwentarz wszystkich pozostałych załączników z rozmiarami i SHA-256.

Bean `ValidationPolicy` dostarczony z zewnątrz pozostaje obsługiwany. Jeżeli nie jest `ArchivedValidationPolicy`, manifest ma `policyEvidence=IDENTITY_ONLY` i nie podszywa się pod archiwum tej polityki. Jej efektywną konfigurację należy zachować osobno. Nie odczytujemy ponownie pliku wskazanego w konfiguracji, aby nie dołączyć innej wersji niż rzeczywiście użyta.

Dokument wejściowy i wszystkie przesłane treści odłączone są identyfikowane przez rolę, indeks, oryginalną nazwę po usunięciu części katalogowej, długość i SHA-256. Indeks rozróżnia również powtarzające się nazwy. Ich pełne bajty nie są automatycznie kopiowane do PDF; oryginały trzeba przechować osobno. Raporty diagnostyczne również mogą zawierać dane osobowe i wymagają odpowiedniej kontroli dostępu.

Manifest nie zawiera skrótu siebie ani PDF, żeby uniknąć zależności cyklicznej. Skrót manifestu jest widoczny w PDF i jego polach informacji. Skrót całego PDF jest obliczany po zapisie i dostępny przez `pdfReport().sha256()` oraz nagłówek odpowiedzi. Weryfikacja bajtów nie wymaga ponownej serializacji JSON/XML: należy hashować dokładne wyodrębnione załączniki.

Po wygenerowaniu aplikacja loguje UUID raportu, SHA-256 PDF oraz SHA-256 manifestu, bez nazw i treści dokumentów. Daje to punkt odniesienia poza PDF; logi trzeba skierować do chronionego repozytorium, jeśli mają służyć jako niezależny rejestr. Zwykły modyfikowalny log nie zastępuje podpisu ani repozytorium z kontrolą zmian.

Nie jest to pełne archiwum umożliwiające dowolne odtworzenie zaufania historycznego. Konfiguracja zaufania, historyczne listy TL/LOTL i źródła zewnętrzne wymagają niezależnej archiwizacji. Wynik na deklarowany czas podpisania pozostaje oceną warunkową, nie dowodem istnienia podpisu w tym czasie.

## Pobranie PDF

`POST /api/signatures/validate/pdf` przyjmuje te same części multipart co endpoint JSON: `file` i opcjonalne, powtarzalne `detachedContents`. Zwraca `application/pdf`, nazwę `validation-report.pdf`, `Cache-Control: no-store` oraz nagłówki `X-Report-SHA256` i `X-Audit-Manifest-SHA256`. Wywołanie wykonuje jedną operację serwisu; wygenerowanie PDF nie uruchamia ponownie DSS. Awaria serializacji któregokolwiek wymaganego raportu lub tworzenia PDF kończy żądanie kodem `REPORT_GENERATION_ERROR` / HTTP 500, zamiast zwrócić niepełny pakiet.

```powershell
curl.exe -X POST http://localhost:8080/api/signatures/validate/pdf -F "file=@C:/documents/document.pdf" -o validation-report.pdf
```

## Test generujący przykład

`SignatureValidationServiceTest.generatesPdfWithOriginalDssEvidenceAndVerifiableManifest` używa rzeczywistego dokumentu CAdES z dwoma podpisami, lokalnym CA i CRL. Wywołuje publiczny serwis, otwiera zwrócony PDF, wyodrębnia pięć załączników, porównuje dokładne bajty dwóch XML-i z oryginalnymi raportami i niezależnie przelicza skróty inwentarza oraz całego PDF. Sprawdza także metadane, obecność danych binarnych certyfikatów/CRL, precyzję wyniku JSON, brak zbędnych raportów i domyślnie zamknięty panel załączników. Po poprawnych asercjach zapisuje `target/test-reports/signature-validation-audit.pdf`.

Pozostałe przypadki sprawdzają podpis odłączony i polskie znaki, pakiet dla zmienionej treści i dokumentu bez podpisów, zachowanie raportu z technicznie nieudanej próby oraz odmowę wygenerowania niepełnego pakietu. W tym ostatnim teście obiekt oparty na rzeczywistych raportach DSS symuluje błąd serializacji przez nadpisanie metody eksportu; nie wymaga agenta Mockito. `ArchivedValidationPolicyTest` sprawdza zachowanie dokładnej polityki po zmianie pliku źródłowego.

Polecenie do osobnego uruchomienia wyłącznie testu generującego przykład:

```powershell
mvn "-Dtest=SignatureValidationServiceTest#generatesPdfWithOriginalDssEvidenceAndVerifiableManifest" test
```

Jeśli poprzedni PDF jest otwarty w czytniku blokującym nadpisywanie pliku, można ustawić inną ścieżkę parametrem `-Ddss.test.reportPath=target/test-reports/signature-validation-audit-minimal.pdf`.

31.10.2026, po ograniczeniu pakietu i zamknięciu panelu załączników, uruchomiono `mvn "-Dtest=SignatureValidationServiceTest" "-Ddss.test.reportPath=target/test-reports/signature-validation-audit-minimal.pdf" test`: **7 testów, 0 niepowodzeń, 0 błędów, BUILD SUCCESS**. Wygenerowano dwustronicowy PDF z pięcioma załącznikami. Obie strony wyrenderowano Popplerem i sprawdzono wizualnie. Niezależny odczyt przez pypdf potwierdził ustawienie `/PageMode /UseNone`, listę pięciu załączników oraz ich skróty z manifestu. Testu `ArchivedValidationPolicyTest` w tym przebiegu nie uruchomiono.
