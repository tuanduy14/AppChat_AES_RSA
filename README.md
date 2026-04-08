"# AppChat_AES_RSA" 

# Terminal 1 - Server
python server/server.py

# Terminal 4 - Attacker
python attacker/attacker.py

# Terminal 2 - Alice  
python client/client.py alice mitm

# Terminal 3 - Bob
python client/client.py bob mitm

