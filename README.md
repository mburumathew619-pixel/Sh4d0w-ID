# Sh4d0w-ID
# What Sh4d0w-ID Actually Does
At its core, Sh4d0w-ID solves a deceptively simple problem: you have a hash, and you need to know what it is before you can do anything useful with it.
When you extract a hash from a database dump, a /etc/shadow file, an Active Directory export, or a CTF challenge, it rarely comes with a label. You're staring at a string of hex characters or a $-prefixed blob, and your entire next step depends on correctly identifying what produced it. Feed the wrong format into hashcat or John and you waste time, burn wordlist passes, or worse — convince yourself a hash is uncrackable when it never even ran correctly.
Sh4d0w-ID reads the hash and identifies it by matching its structure against a library of over 300 known patterns. Prefixed formats like $2b$, $6$, or $argon2id$ are matched with high confidence because their structure is unambiguous. Plain hex hashes are identified by length and character set, returning a ranked list of candidates — a 32-character hex string could be MD5, NTLM, or MD4, and the tool tells you all of them along with their probability. For every match, it returns the hashcat -m mode number and the John the Ripper --format= string, so you can go straight from identification to cracking without consulting documentation.
It also has a verification mode: if you already suspect a plaintext, you feed both the hash and the plaintext and Sh4d0w-ID tries all supported algorithms, confirming with certainty which one produced the match.

# Why People Actually Need It
The naive answer is "just Google the hash format." The real answer is that this breaks down fast in practice.
A penetration tester who dumps credentials from a compromised machine at 2am during a time-boxed engagement does not want to be cross-referencing documentation. They need to know in seconds whether they're looking at an NTLM hash they can pass-the-hash with directly, a bcrypt they shouldn't bother attacking with a wordlist, or a sha512crypt they can run on a GPU with a reasonable chance of success. The answer changes the entire attack path.
CTF players face a different version of the same problem. Challenges deliberately strip context. You get a hash file with no metadata, or a login form that returns a hash in the source, or a database with dozens of users and two different hash formats mixed together. Identifying them quickly is a prerequisite for any further work, and doing it wrong wastes the limited hours of a competition.
For security researchers and forensic analysts, hash identification shows up during code audits — finding places where a codebase stores passwords in MD5 or unsalted SHA-1 without the algorithm being documented anywhere in the code — and during incident response, where you need to determine whether recovered credentials use a format that indicates outdated security practices or an active risk.
The broader point is that hash identification is a bottleneck, not the interesting work. It sits between finding credentials and doing anything with them, and every minute spent on it is a minute not spent on the actual objective. A tool that makes it instantaneous and also hands you the cracking command has real, compounding value over the course of a long engagement or a 24-hour CTF.
Sh4d0w-ID covers the full realistic range — not just the obvious MD5/SHA-1 cases that anyone can eyeball, but Kerberos ticket formats, database-specific hash schemes, cryptocurrency wallet formats, FDE headers, and dozens of application-specific implementations that only appear in the wild occasionally but matter enormously when they do.
<img width="815" height="445" alt="Screenshot_2026-06-09_03-08-21" src="https://github.com/user-attachments/assets/3022b7c3-8e5a-4e60-8156-737068c90e58" />


********************Basic Installation & Usage Guide********************

 Step 1: 
 git clone <git url>

 Step 2:  
 cd Sh4d0w-ID

 Step 3:
 python sh4d0w.py 
