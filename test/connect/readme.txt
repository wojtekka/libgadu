Jak to działa
-------------

Program testuje mechanizm łączenia się z serwerem podczas występowania
różnego rodzaju błędów -- od awarii serwera DNS, przez awarię łącza, po
awarię serwerów Gadu-Gadu.

Zasada działania programu polega na przejęciu funkcji systemowych i
symulacji serwera Gadu-Gadu na komputerze lokalnym -- zarówno huba, jak
i serwera właściwego. Serwery zwracają jedynie uproszczone odpowiedzi i
nie analizują otrzymanych danych. Alokowane są 4 porty począwszy od 17219,
dla symulacji huba, dla symulacji portu 8074, dla symulacji portu 443 i
jedno zamknięte gniazdo do symulacji awarii serwera. To ostatnie jest
przywiązane do portu, ale bez wywołania listen().

Podstawiona funkcja gethostbyname() dla appmsg.gadu-gadu.pl zwraca adres
lokalny (127.0.67.67) lub błąd, jeśli symulujemy awarię DNS. Przejęcie
funkcji connect() pozwala skierować ruch z portów 80, 8074 i 443 na jedno
z lokalnie otwartych gniazd. Do symulacji awarii łącza lub całkowitej
niedostępności serwera, połączenie jest przekierowywane na adres 192.0.2.1,
który zgodnie z RFC 3330 jest zarezerwowany dla dokumentacji i przykładów,
przez co mamy pewność, że jest niedostępny i że nie będziemy się łączyć
z żadnym istniejącym hostem.

Kolejne testy są uruchamiane dla różnych parametrów symulacji:
- rozwiązywanie nazw działa lub nie,
- port 80 działa lub nie,
- port 8074 działa lub nie,
- port 443 działa lub nie,
- podano ręcznie adres serwera lub nie.

Dla przyspieszenia testów, limit czasu połączenia przy operacjach 
asynchronicznych jest zmniejszany do 1 sekundy. Dla synchronicznych,
funkcje systemowe od razu zwracają błąd typu ETIMEDOUT.
