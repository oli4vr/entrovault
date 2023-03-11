# Entropy Vault command line tool
<p>Target use : Securely store and retrieve sensitive strings like passwords for command line use.<p>

<p>Entropy Vaults are cryptographically obscured files intended to store passwords and other sensitive short strings. Every entry is stored as an encrypted entry that contains payload+hash. To retrieve it the program must decript every possible entry per x nr of bytes with the provided keys.</p>

<p>For obscuring purposes a random amount of random byte blocks are added before and after each entry. And unused data in a payload is also randomized to avoid predictable data blocks.</p>

<p><u><b>"Entropy" on wikipedia :</b></u></p>
<blockquote>"Entropy is a scientific concept, as well as a measurable physical property, that is most commonly associated with a state of disorder, randomness, or uncertainty."</blockquote>

<h3>Command syntax</h3>
<pre>
entrovault -> Entropy vault
 by Olivier Van Rompuy

Syntax: entrovault [-a | -r | -e] [-q] [-f filename] [-% rounds] keystring

Options
 -a             Append entry
 -r             Replace entry
 -e             Erase entry
 -q             Password type payload entry
 -v             Vault name
 -%             Encryption rounds
 </pre>

 <h3>Build & Install</h3>
 <pre>git clone https://github.com/oli4vr/entrovault.git
 cd entrovault
 make
 make install
 </pre>
 <p>* Make sure ~/bin is in your $PATH</p>

