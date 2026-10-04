# Weryfikacja API DSS 6.5

Weryfikację wykonano na lokalnych plikach `*-6.5-sources.jar` i `*-6.5.jar` z grupy `eu.europa.ec.joinup.sd-dss`, porównując dokumentację z kodem wydania `6.5`. Nie używano API z 6.3/6.4 ani gałęzi `master`. `javap -public` odczytał publiczne sygnatury 22 klas z artefaktów 6.5; narzędzie nie kompiluje projektu ani nie wykonuje walidacji. Pomocnicze, wyodrębnione źródła i odczyty API są w ignorowanym katalogu `.verification`.

Źródło dokumentacji: [DSS, wersja 6.5](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html).

| API używane przez implementację | Potwierdzenie w wydaniu 6.5 |
|---|---|
| `SignedDocumentValidator.fromDocument(DSSDocument)` | [SignedDocumentValidator](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/SignedDocumentValidator.java), `ServiceLoader<DocumentValidatorFactory>` |
| `setCertificateVerifier`, `setDetachedContents`, `setValidationLevel`, `setEnableEtsiValidationReport`, `setIncludeSemantics`, `setLocale`, `setValidationTime(Date)` | Ten sam kod validatora i odczyt publicznego API |
| `validateDocument(ValidationPolicy)` | Waliduje cały dokument; przyjmuje `eu.europa.esig.dss.model.policy.ValidationPolicy` |
| `getSignatureById(String)` validatora | Wyciąga obiekt podpisu; nie wykonuje selektywnej walidacji. Dlatego nie jest używane do zawężania przebiegu |
| `Reports.getSimpleReport()`, `getDiagnosticData()` | [Reports](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/reports/Reports.java), [AbstractReports](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/reports/AbstractReports.java) |
| `SimpleReport.getValidationTime()`, `getSignatureIdList()`, `getSignatureFormat(String)`, `getSigningTime(String)`, `getBestSignatureTime(String)`, `getIndication(String)`, `getSubIndication(String)` | [SimpleReport](https://github.com/esig/dss/blob/6.5/dss-simple-report-jaxb/src/main/java/eu/europa/esig/dss/simplereport/SimpleReport.java) i publiczne sygnatury 6.5 |
| `getSignatureQualification`, `getContainerType`, `getAdESValidationErrors/Warnings`, `getQualificationErrors/Warnings`, `getTimestampQualification` | Ten sam wrapper; błędy/ostrzeżenia mają typ `List<eu.europa.esig.dss.jaxb.object.Message>`, odczytywane przez `getKey()`/`getValue()` |
| `DiagnosticData.getSignatureIdList()`, `getSignatureById(String)`, `getTimestampList(String)` | [DiagnosticData](https://github.com/esig/dss/blob/6.5/dss-diagnostic-jaxb/src/main/java/eu/europa/esig/dss/diagnostic/DiagnosticData.java) |
| `SignatureWrapper.isCounterSignature()`, `getParent()`, `getDigestMatchers()`, odziedziczone `getSigningCertificate()`, `getCertificateChain()`, `isTrustedChain()` | [SignatureWrapper](https://github.com/esig/dss/blob/6.5/dss-diagnostic-jaxb/src/main/java/eu/europa/esig/dss/diagnostic/SignatureWrapper.java), `AbstractTokenProxy` |
| `TimestampWrapper.getId()`, `getType()`, `getProductionTime()`, `isMessageImprintDataFound/Intact()`, `getSigningCertificate()` | `dss-diagnostic-jaxb:6.5` — źródła i publiczne sygnatury |
| `CertificateWrapper.getCertificateDN()`, `getCertificateIssuerDN()`, `getSerialNumber()`, `getNotBefore/After()`, `isTrusted()`, `getCertificateRevocationData()` | `dss-diagnostic-jaxb:6.5` |
| `CertificateRevocationWrapper.getStatus/Reason/RevocationDate()`, odziedziczone `getId/RevocationType/ProductionDate/ThisUpdate/NextUpdate()` | `CertificateRevocationWrapper` i `RevocationWrapper` w `dss-diagnostic-jaxb:6.5` |
| `SignatureLevel.getSignatureForm()` | `dss-enumerations:6.5`; format/poziom nie są odgadywane z pliku |
| `InMemoryDocument(byte[], String, MimeType)` | `dss-model:6.5`; używany z MIME `null`, bez wnioskowania z rozszerzenia |
| `ValidationPolicyLoader.fromDefaultValidationPolicy().create()`, `fromValidationPolicy(InputStream).create()` | [ValidationPolicyLoader](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/policy/ValidationPolicyLoader.java) |
| `CommonCertificateVerifier()`, `setTrustedCertSources`, `setAIASource`, `setCrlSource`, `setOcspSource` | `eu.europa.esig.dss.spi.validation` w `dss-spi:6.5` |
| `CommonTrustedCertificateSource.addCertificate(CertificateToken)` | Metoda dziedziczona z `CommonCertificateSource`; `CertificateToken(X509Certificate)` z `dss-model:6.5` |
| `OnlineOCSPSource(DataLoader)`, `OnlineCRLSource(DataLoader)` | `eu.europa.esig.dss.service.ocsp/crl` w `dss-service:6.5` |
| `CommonsDataLoader.setTimeoutConnection/ConnectionRequest/Response/Socket(int)`, `OCSPDataLoader()` | `dss-service:6.5`; dedykowany OCSPDataLoader dziedziczy CommonsDataLoader |
| `DefaultAIASource(DataLoader)` | `eu.europa.esig.dss.spi.x509.aia` w `dss-spi:6.5` |

## Czas odniesienia i dokładność

Kod [ValidationProcessForSignaturesWithLongTermValidationData](https://github.com/esig/dss/blob/6.5/dss-validation/src/main/java/eu/europa/esig/dss/validation/process/vpfltvd/ValidationProcessForSignaturesWithLongTermValidationData.java) inicjalizuje dowód istnienia czasem bieżącego przebiegu (`getCurrentTime()`), a następnie może przyjąć wcześniejszy czas zaakceptowanego znacznika. [DetailedReport.getBestSignatureTime](https://github.com/esig/dss/blob/6.5/dss-detailed-report-jaxb/src/main/java/eu/europa/esig/dss/detailedreport/DetailedReport.java) korzysta z POE procesu archiwalnego, LTV lub podstawowego. `SimpleReportBuilder` kopiuje ten wynik do SimpleReport, a deklarowany czas kopiuje z `SignatureWrapper.getClaimedSigningTime()`.

`DefaultDocumentAnalyzer.getValidationTime()` inicjalizuje domyślny czas tylko raz jako `new Date()`. `SimpleReportBuilder` przypisuje ten obiekt do czasu raportu. Data odniesienia i czas walidacji są więc pobierane z tego samego przebiegu. Aplikacja nie wywołuje zegara systemowego do kwalifikacji.

Adapter [DateParser](https://github.com/esig/dss/blob/6.5/dss-jaxb-parsers/src/main/java/eu/europa/esig/dss/jaxb/parsers/DateParser.java) formatuje XML do sekund. DTO jest mapowany bezpośrednio z obiektów Java przed jakimkolwiek takim przekształceniem. Dokładność porównania odpowiada `Date.getTime()`; nie zastosowano tolerancji ani obcinania ułamków sekund.

Domyślny `OriginalIdentifierProvider` zwraca `object.getDSSId().asXmlId()`. Wpisy są łączone wyłącznie po identyfikatorze. Jeśli cel zniknie albo wystąpi więcej niż raz w dodatkowym raporcie, wynik pierwotny jest zachowywany jako rezultat nieudanej technicznie próby.

## Zależności i ograniczenie weryfikacji

Nazwy modułów i wersje sprawdzono w [dss-bom/pom.xml z tagu 6.5](https://github.com/esig/dss/blob/6.5/dss-bom/pom.xml) oraz POM-ach z lokalnego repozytorium. Uwzględniono implementacje ServiceLoader, w tym [dss-cms-object](https://github.com/esig/dss/blob/6.5/dss-cms-object/pom.xml); sam `dss-cms` jest interfejsem. Zakres ASiC obejmuje moduły `dss-asic-cades` i `dss-asic-xades`.

`dss-policy-jaxb:6.5` zawiera rejestrację `eu.europa.esig.dss.model.policy.ValidationPolicyFactory` wskazującą `eu.europa.esig.dss.policy.EtsiValidationPolicyFactory`. Jest wymagany w runtime: `dss-validation:6.5` deklaruje go jedynie do swoich testów, a `ValidationPolicyLoader.loadDefaultPolicy()` wprost wymaga implementacji fabryki. Nie dodawano osobnego modułu crypto XML/JSON, ponieważ konfiguracja nie ładuje oddzielnego pliku cryptographic suite.

Sprawdzono także dziedziczone zarządzanie zależnościami BOM-u DSS: HttpClient 5.6.4 oraz Logback 1.3.16. Wersję HttpCore 5.4.3 potwierdza [POM Apache HttpClient 5.6.4](https://github.com/apache/httpcomponents-client/blob/rel/v5.6.4/pom.xml). Zachowano Logback zarządzany przez Spring Boot i wyrównano HttpCore. [Wymagania Spring Boot 4.0](https://docs.spring.io/spring-boot/4.0/system-requirements.html) potwierdzają wersję 4.0.8 i zgodność z JDK 21.

Nie uruchomiono testów, kompilacji, serwera, Maven `validate`, `dependency:tree` ani `help:effective-pom`. Przegląd POM-ów i publicznych API nie potwierdza rozwiązania całego grafu zależności ani poprawności walidacji rzeczywistych dokumentów w uruchomionej aplikacji.
