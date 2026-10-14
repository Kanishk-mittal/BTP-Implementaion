## 🛠 Pre-Demo Setup (Before the Presentation)                                                                                     
                                                                                                                                    
  Open 2 or 3 terminal windows in /home/kanishk/data/BTP/Implementation/docker.                                                     
                                                                                                                                    
  ### Terminal Layout Recommendation:                                                                                               
                                                                                                                                    
  • Terminal 1: Running services and live log tailing (kme-a, kme-b, server)                                                        
  • Terminal 2: Redis Key Pool monitor (shows keys refilling in real-time)                                                          
  • Terminal 3: Client execution (your interactive presenter terminal)                                                              
  ──────                                                                                                                            
  ## 🎬 4-Phase Live Demonstration                                                                                                  
                                                                                                                                    
  ### Phase 1: Show the Architecture & Start the Infrastructure                                                                     
                                                                                                                                    
  In Terminal 1, start the background infrastructure:                                                                               
                                                                                                                                    
    cd /home/kanishk/data/BTP/Implementation/docker                                                                                 
    docker compose up -d ca && docker compose wait ca                                                                               
    docker compose up -d redis kme-a kme-b server                                                                                   
                                                                                                                                    
  👉 Explain to the panel:                                                                                                          
                                                                                                                                    
  1. The CA container generated the root certificate, server certificate, and SSH host key.                                         
  2. KME-A and KME-B are active, sharing state via Redis (simulating quantum key sync).                                             
  3. SSH Server is listening on port 2222.                                                                                          
  ──────                                                                                                                            
  ### Phase 2: Show the Real-Time Quantum Key Pool (ETSI GS QKD 014 Status)                                                         
                                                                                                                                    
  In Terminal 2, monitor the key pool filling up at 2 keys/sec up to 10 keys:                                                       
                                                                                                                                    
    watch -n 1 "docker compose exec redis redis-cli LLEN qkd:pool"                                                                  
                                                                                                                                    
  Or query KME-A's ETSI REST status endpoint directly:                                                                              
                                                                                                                                    
    docker compose exec kme-a curl -s http://localhost:8000/api/v1/keys/server-sae/status | python3 -m json.tool                    
                                                                                                                                    
  👉 Point out the ETSI parameters returned:                                                                                        
                                                                                                                                    
  • stored_key_count: Current count of keys available for delivery.                                                                 
  • key_size: 256 bits.                                                                                                             
  • max_key_count: 10.                                                                                                              
  • source_KME_ID: KME-A, target_KME_ID: KME-B.                                                                                     
  ──────                                                                                                                            
  ### Phase 3: The Main Event — QKD-Secured SSH Connection                                                                          
                                                                                                                                    
  In Terminal 3, run the client:                                                                                                    
                                                                                                                                    
    docker compose run --rm client                                                                                                  
                                                                                                                                    
  👉 What you and the panel will see on screen:                                                                                     
                                                                                                                                    
    ==================================================                                                                              
          Connecting via QKD-secured Paramiko SSH                                                                                   
     Target Host: server:2222                                                                                                       
     Master SAE ID (Username): client-sae                                                                                           
     Slave SAE ID (Target):   server-sae                                                                                            
     Client KME URL:          http://kme-a:8000                                                                                     
     Min Key Pool Threshold:  2                                                                                                     
    ==================================================                                                                              
    [INFO] Connected (version 2.0, client paramiko_5.0.0)                                                                           
    [INFO] Authentication (password) successful!                                                                                    
                                                                                                                                    
    [SUCCESS] Successfully connected!                                                                                               
    [SECURITY] Key Exchange Algorithm Negotiated: qkd-etsi014-sha256                                                                
    [STATUS] Connection is Quantum Key Distribution (QKD) SECURED! 🛡️                                                               
                                                                                                                                    
    --- Command Output ---                                                                                                          
    Linux ... x86_64 GNU/Linux                                                                                                      
    QKD SSH Session Verification OK                                                                                                 
                                                                                                                                    
  👉 Explain the flow that just happened:                                                                                           
                                                                                                                                    
  1. Master SAE (Client) queried KME-A for status and called POST /enc_keys.                                                        
  2. KME-A delivered a UUID key_ID and the 256-bit symmetric quantum key.                                                           
  3. The client sent key_ID, client-sae, and server-sae over the SSH handshake (SSH_MSG_KEX_QKD_INIT).                              
  4. Slave SAE (Server) received the packet, requested a challenge nonce from KME-B, signed it with its CA-certified private key,   
  and called POST /dec_keys.                                                                                                        
  5. KME-B verified the CA signature, released the identical quantum key, and consumed it (one-time-use).                           
  6. Both sides derived the session encryption keys using the quantum key material as the root shared secret K.                     
  ──────                                                                                                                            
  ### Phase 4: Fallback Mechanism (Examiners LOVE this!)                                                                            
                                                                                                                                    
  Examiners always ask: "What happens if the QKD link is jammed or the quantum key pool runs out?"                                  
                                                                                                                                    
  In Terminal 3, run the client with a threshold higher than the pool limit (e.g., requires 20 keys when maximum capacity is 10):   
                                                                                                                                    
    docker compose run --no-deps --rm -e QKD_MIN_AVAILABLE_KEYS=20 client                                                           
                                                                                                                                    
  👉 Show the output:                                                                                                               
                                                                                                                                    
    [WARNING] [QKD] Key pool has 10 key(s) (min threshold: 20) — falling back to classical key exchange                             
    [SUCCESS] Successfully connected!                                                                                               
    [SECURITY] Key Exchange Algorithm Negotiated: mlkem768x25519-sha256                                                             
    [STATUS] Connection fell back to classical key exchange.                                                                        
                                                                                                                                    
  👉 Explain:                                                                                                                       
                                                                                                                                    
  • The client detected that quantum key levels were insufficient.                                                                  
  • Rather than dropping the connection or failing, Paramiko logged a warning and gracefully negotiated the next best available     
  algorithm (mlkem768x25519-sha256 or classical curve25519).