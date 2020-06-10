Macarie Razvan Cristian, 322CB

Algoritmul de cautare in tabela de routare are in cazul meu O(1). Am implementat o trie
binara (care seamana mai mult cu un BST) care are pe copilul din stanga 1 si pe cel
din dreapta 0. Folosesc dummy nodes in locuri in care nu am valori, iar daca nu gasesc
o valoare in tabela de routare intorc un dummy node cu adresa ip: 0.0.0.0. Inaltimea maxima
a arborelui este 32, deci worst case cand am masca 255.255.255.255 voi face 32 de pasi pentru
a gasi nodul.

Protocolul arp, a fost cel mai greu de implementat pentru ca eu am pornit de la o tabela 
statica si a trebui sa restructurez codul. Functionalitate este cea standard pentru protocolul arp
cu adaugarea ca atunci cand primesc un arp-reply, verific cat timp coada nu e goala daca pentru
vreun pachet din coada a venit mac-ul necesar forward-ului pe acel arp reply. 

Procesul de dirijare este pas cu pas cel mentionat in enunt, la fel si protocolul ICMP.

Calcularea checksum-ului dupa decrementarea ttl folosind algoritmul incremental din 
RFC 1624 este implementat in fuctia bonus_ip_checksum. Checksum-ul este verificat la ICMP si 
IP cu functia checksum din laborator (am citit pe forum ca o putem folosi).

Probleme la implementare:

Forward02 si Forward03 cand sunt rulate de checker nu functioneaza. Am testat mult timp de ce doar
aceste 2 teste nu vor sa mearga si m-am dat batut. UPDATE: am descoperit de ce nu mergeau : cand
puneam un packet in coada nu ii puneam continutul, ci ii puneam adresa si se rula inainte un 
test cu host unreacheble si nu mai mergea nimic. Am reusit pana la urma sa-l rezolv prin a da
memcpy intr-un packet nou inainte sa ii dau enqueue acelui packet.

Protocolul arp, nu are in structura default din linux in header informatii despre
sender/target ip/mac, lucru ce a implicat crearea unei strucuri in care sa-mi tin si sa modific mai usor
datele. In plus, datele din arp sunt organizare complet diferit fata de cele din ip sau imcp, lucru ce a 
implicat multe modificari si faptul ca nu am putut sa-mi refolosesc functii de la ip/icmp.

"Read[33]
Network is down"
Aparent era o eroare logica in checker, atunci cand foloseai o tabela arp statica checkerul crapa si nu
functiona sa rulezi tema chiar daca aveai lucruri care merg. Am pierdut foarte mult timp, undeva la o zi intreaga
de debugging, instalat masini virtuale si reinstal linux de pe dual boot de cateva ori. Am avut noroc ca si-au dat
seama responsabilii de tema care e problema pentru ca mai aveam putin si ma dadeam batut.
