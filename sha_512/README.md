
<p>Vaším úkolem je realizovat funkci (či sadu funkcí, ne celý program), které naleznou <strong>libovolnou</strong> zprávu, jejíž hash (<strong>SHA-512</strong>) začíná zleva na posloupnost nulových bitů.</p><p>Pořadí bitů je big-endian: Bajt 0 od MSB do LSB, Bajt 1 od MSB do LSB, …, poslední bajt od MSB do LSB.</p><p>Neboli, dva nulové bity odpovídají například bajtu <code>0010 0111</code> (<code>0x27</code>).</p><p>Funkce je požadována ve dvou variantách:</p><ul><li>základní řešení (funkce <code>findHash</code>). Implementace této funkce je povinná.</li><li>vylepšené řešení (funkce <code>findHashEx</code>). Implementace této funkce není povinná, bez dodané „dummy“ implementace se ale úloha nepodaří zkompilovat. Funkci implementujte, pokud se rozhodnete usilovat o bonus.</li></ul><p>Parametry Vámi implementovaných funkcí jsou:</p><pre>int findHash (int bits, char ** message, char ** hash)
</pre><ul><li><code>bits</code> - požadovaný počet nulových bitů v hashi zprávy.</li><li><code>message</code> - výstupní parametr. Tento parametr obsahuje data, pro která byl nalezen příslušný hash. Výsledek je uložen jako Vámi dynamicky alokovaný hexadecimální C řetězec (ukončený <code>\0</code>).</li><li><code>hash</code> - výstupní parametr. Jedná se o hash zprávy <code>message</code> z předchozího parametru, opět jde o Vámi dynamicky alokovaný hexadecimální C řetězec.</li><li>Návratovou hodnotou funkce je <code>1</code> v případě úspěchu, <code>0</code> v případě neúspěchu nebo nesprávných parametrů. Těmi je typicky požadovaný počet nulových bitů, který nedává smysl.</li></ul><pre>int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction)
</pre><ul><li>rozšíření funkce <code>findHash</code>. Všechny parametry i návratová hodnota zůstavají stejné jako v případě základní varianty.</li><li><code>hashFunction</code> - nový parametr, který udává, která hashovací funkce má být použita pro nalezení posloupnosti nulových bitů. Zadaný název hashovací funkce je kompatibilní s funkcí <code>EVP_get_digestbyname</code>.</li></ul><p>O uvolnění dynamicky alokovaných protředků (<code>message</code> a <code>hash</code>; pouze ale v případě úspěchu funkce) se nemusíte starat, testovací prostředí zajistí jejich korektní uvolnění. Veškerá ostatní práce s pamětí je ovšem ve Vaší režii.</p><p>Odevzdávejte zdrojový soubor, který obsahuje implementaci požadované funkce <code>findHash</code>, resp. <code>findHashEx</code>. Do zdrojového souboru si můžete přidat i další Vaše podpůrné funkce, které jsou z <code>findHash</code> (resp. <code>findHashEx</code>) volané. Funkce bude volána z testovacího prostředí, je proto důležité přesně dodržet zadané rozhraní funkce.</p><p>Za základ pro implementaci použijte kód z přiloženého archivu níže. Ukázka obsahuje testovací funkci <code>main</code>, uvedené hodnoty jsou použité při základním testu. Všimněte si, že vkládání hlavičkových souborů a funkce <code>main</code> jsou zabalené v bloku podmíněného překladu (<code>#ifdef/#endif</code>). Prosím, ponechte bloky podmíněného překladu i v odevzdávaném zdrojovém souboru. Podmíněný překlad Vám zjednoduší práci. Při kompilaci na Vašem počítači můžete program normálně spouštět a testovat. Při kompilaci na Progtestu funkce <code>main</code> a vkládání hlavičkových souborů „zmizí“, tedy nebude kolidovat s hlavičkovými soubory a funkcí <code>main</code> testovacího prostředí.</p><p>V ukázce se dále nachází funkce <code>checkHash</code>, kterou si budete (s nemalou pravděpodobností) muset implementovat pro své lokální testování. Funkce je zabalená v bloku podmíněného překladu (=nebude testována). Přesto je vhodné ji implementovat pro ověření správnosti Vašeho řešení.</p>