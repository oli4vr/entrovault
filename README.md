# Entropy Vault command line tool
<p>Target use : Securely store and retrieve sensitive strings like passwords for command line use.<p>

<p>Entropy Vaults are cryptographically obscured files intended to store passwords and other sensitive short strings. Every entry is stored as an encrypted entry that contains payload+hash. To retrieve it the program must decript every possible entry per x nr of bytes with the provided keys.</p>

<p>For obscuring purposes a random amount of random byte blocks are added before and after each entry. And unused data in a payload is also randomized to avoid predictable data blocks.</p>

<p>There is also no index or any method to list or know what entries are present in the file. The idea is that person A could store an entry after person B and be completely unaware that person A has any data in the vault and vise versa.</p>

<p><u><b>"Entropy" on wikipedia :</b></u></p>
<blockquote>"Entropy is a scientific concept, as well as a measurable physical property, that is most commonly associated with a state of disorder, randomness, or uncertainty."</blockquote>

<h3>Command syntax</h3>
<pre>$ entrovault
entrovault -> Entropy vault
 by Olivier Van Rompuy

Syntax: entrovault [-a | -r | -e] [-q] [-p vault_password] [-f filename] [-% rounds] keystring

Options
 -a             Append entry
 -r             Replace entry
 -e             Erase entry
 -p             Vault password
 -q             Password type payload entry
 -v             Vault name
 -%             Encryption rounds
 </pre>

<h3>Explain by example :</h3>
<p><b>Store a password in the vault and retrieve it</b><br/>
You are always required to enter a vault password. This password can be unique per entry, but does not have to be.
This is purely up to the user and the use case. When you append a new entry you are required to confirm the password a second time.
<br/>The -q option allows you to enter the payload via a password style input prompt.
</p>
<pre>$ entrovault -q -a MySecretPassword
Enter vault password for MySecretPassword - 1st : 
Enter vault password for MySecretPassword - 2nd : 
Payload 1st : 
Payload 2nd :
</pre>
<p>Retrieve your password</p>
<pre>$ entrovault MySecretPassword
Enter vault password for MySecretPassword :
PASSW0RD
</pre>
<p>Example interactive scripting use case :<br/>
The point here is that you only need to remember the vault password</p>
<pre>some_application -username=myuser -password=$(entrovault MySecretPassword) ...do some stuff</pre>

<p>Replace entry</p>
<pre>$ entrovault -q -r MySecretPassword
Enter vault password for MySecretPassword :
Payload 1st :
Payload 2nd :
</pre>

<p>Erase entry</p>
<pre>$ entrovault -e MySecretPassword
Enter vault password for MySecretPassword :
Payload 1st :
Payload 2nd :
</pre>

<p>By default stdin is used as the source for the payload/content unless -q is provided</p>
<p>You can use mixed complexities of encryption with the -% parameter you can choose a customer nr of encryption rounds.
Do note that encryption is done in 2 stages, so the current 3 round default actually results in 6 encryption rounds.
You can go up to 255, but beware that as the vault file grows it will require exponentially more cpu power to retrieve entries. 2-8 rounds is quite secure, anything above is for experimentation only.
<p>

<h3>Build & Install</h3>
<pre>$ git clone https://github.com/oli4vr/entrovault.git
$ cd entrovault
$ make
$ make install
</pre>
<p>* Make sure ~/bin is in your $PATH</p>

