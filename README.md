# Router
### Ion Dragos - Cosmin

Am realizat protocolul ARP, procesul de dirijare, protocolul ICMP si task-ul bonus.

## ARP
 * Aici avem cazul cand un host intreaba router-ul ce adresa mac are pe o anumita interfata.
 * Prima data m-am asigurat ca pachetele sunt pentru noi(mac-ul destinatie coincide cu mac-ul interfetei pe care am primit pachetul sau daca mac-ul destinatie este de broadcast, adica pentru toata lumea).
 * Schimbarile pe care le-am facut la acest pachet au fost: 
    * sa actualizez campul sha in care am pus adresa mac corespunzatoare interfetei pe care a fost primit request-ul
    * op: codul pentru reply
    * tpa, tha: adresele destinatarului
    * spa: adresa sursei
 * la final modificam header-ul de ethernet


## Forwarding
* La aceasta cerinta am preluat in mare parte codul din laboratorul 4
* noutatea a venit cand a trebuit sa trimit arp_request pentru a afla mac-ul next_hop-ului
* cand am trimis acest arp_reply am creat un pachet nou, cu destinatia de broadcast ca toata lumea sa auda
* punem headerul de arp cu toate campurile completate corect
* trimit pachetul
* am o coada in care pastrez toate pachetele care inca nu au primit reply
* odata ce am detectat un reply adaug in tabela arp ip si mac
* parcurg coada de pachete netrimise pana cand il gasesc pe cel cu adresa ip buna. Daca nu e cel bun, il bag inapoi in coada, altfel, il trimit


## ICMP
* Aici sunt cazurile de esec(expira ttl-ul, nu am gasit next_hop)
* practic inseram headerul de icmp dupa cel de ip.
* de asemenea trebuie mutati 64 de octeti la dreapta 

## Bonus
* Am transpus formula care se afla in documentul trimis in tema