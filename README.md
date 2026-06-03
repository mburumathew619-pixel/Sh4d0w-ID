# Sh4d0w-ID
Sh4d0w-ID is a command-line hash identification tool written in Python. 

It analyzes a given hash string and identifies the algorithm used to produce it — whether it's a legacy format like MD5 or SHA-1, a modern memory-hard scheme like yescrypt, bcrypt, or Argon2, or a platform-specific format such as Drupal 7, WordPress, or Unix crypt variants.

Sh4d0w supports over 30 hash formats including hex-based digests, modular-crypt formats, and base64-encoded outputs. 

It operates in two modes — an interactive prompt where you can submit multiple hashes in sequence, and a single-shot command-line mode for scripting and quick lookups. When a plaintext value is known, Sh4d0w can verify it directly against the hash to confirm the algorithm with certainty.

Built for penetration testers, CTF players, and security researchers who need fast, reliable hash identification without leaving the terminal.

********************Basic Installation & Usage Guide********************

 Step 1: 
 git clone <git url>

 Step 2:  
 cd Sh4d0w

 Step 3:
 python sh4d0w.py 
