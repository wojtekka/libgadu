Jak to działa
-------------

Program testuje zgodność z protokołem Gadu-Gadu za pomocą prostych regułek
opisujących akcje (wywołanie funkcji, otrzymanie pakiet od serwera)
i spodziewane reakcje (wysłanie pakietu do serwera, wywołanie zdarzenia).
Nie wymaga dostępu do prawdziwego serwera, ponieważ program symuluje serwer
(za pomocą regułek, sam jedynie potrafi analizować przychodzące pakiety)
na lokalnym porcie 17219.

Dostępne akcje:

1. login (parametr = wartość, ...)

   Logowanie do serwera z podanymi parametrami gg_login_params. Parametry
   podaje się w jednej linii oddzielone przecinkiem. Przykład:

   login (uin = 123456789, password = "qwerty")

2. logoff

   Rozłączenie z serwerem.

3. send (11 22 33 44 ...)

   Wysyła pakiet do biblioteki. Poszczególne liczby heksadecymalne (bez "0x")
   można oddzielać spacjami i/lub przecinkami dla czytelnego pogrupowania.
   Pakiet musi zawierać poprawny nagłówek. Docelowo trzeba będzie stworzyć
   mechanizm do łatwiejszego przekazywania liczb 32-bitowych, 16-bitowych
   i ciągów znaków. Przykład:

   send (03 00 00 00, 00 00 00 00)

4. call {
     // kod C
   }

   Wywołuje funkcje biblioteki. Kod C jest kopiowany dosłownie i ubierany
   w definicję funkcji, więc może zawierać dowolny kod języka C: deklaracje
   zmiennych, instrukcje warunkowe itd. Struktura sesji jest zdefioniowana
   jako parametr funkcji o nazwie session. Początkowy nawias klamrowy musi
   znajdować się na końcu linii z nazwą regułki, a końcowy na początku linii.
   Przykład:

   call {
     printf("Hello, world!\n");
     gg_change_status(session, GG_STATUS_BUSY);
   }

Dostępne reakcje:

1. expect connect

   Oczekuje na połączenie z serwerem. MUSI występować po akcji login.
   
2. expect disconnect

   Oczekuje na rozłączenie z serwerem. MUSI występować po akcji logout.

3. expect data (11 22 33 44 ...)

   Oczekuje na pakiet od biblioteki. Poszczególne liczby heksadecymalne
   (bez "0x") można oddzielać spacjami i/lub przecinkami dla czytelnego
   pogrupowania. Bajty, których wartość ma być ignorowana oznacza się jako
   "xx". Pakiet musi zawierać poprawny nagłówek. Przykład:

   expect data (20 00 00 00, 04 00 00 00, xx xx xx xx)

4. expect event GG_EVENT_...

   Oczekuje na zdarzenie od biblioteki. Pola zdarzenia nie grają roli.
   Przykład:

   expect event GG_EVENT_CONN_SUCCESS

5. expect event GG_EVENT_... (
     pole == wartość
     ...
   )

   Oczekuje na zdarzenie od biblioteki, którego pola są opisane regułami.
   Każda reguła znajduje się w osobnej linii, nawias otwierający w linii
   z reakcją, nawias zamykający na początku linii. Pola muszą zawierać
   nazwę pola zdarzenia z unii. Dostępne są wszystkie operatory porównań
   języka C. Porównywanie ciągów znaków zapisuje się tak samo jak liczb,
   tj. operatorami == i !=. Pola nieopisane regułami są ignorowane. Przykład:

   expect event GG_EVENT_MSG (
     msg.sender != 0
     msg.message == "Ala ma kota"
   )

6. expect event [GG_EVENT_...] {
     // kod C
   }

   Oczekuje na zdarzenie od biblioteki. Zasady dotyczące wklejania kodu C
   są identyczne jak dla akcji call. Typ zdarzenia jest przekazywany jako
   parametr type, unia zdarzenia jako wskaźnik event. Typ zdarzenia nie musi
   wystąpić. Kod musi zwrócić wartość prawdziwą jeśli zdarzenie jest poprawne.
   Przykład:

   expect event {
     if (type != GG_EVENT_CONN_SUCCESS && type != GG_EVENT_CONN_FAILED)
       return false;

     if (type == GG_EVENT_CONN_FALSE && event->failure == GG_FAILURE_INVALID)
       return false;

     return true;
   }

