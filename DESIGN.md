# Secure Messaging Platform: Low-Level System Design
<!-- secure-messaging-low-level-design.md -->

## 1. Software Architecture

### 1.1 Component Overview

```
┌─────────────────────────────────────────────────────┐
│                  Client Application                  │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐ │
│ │ UI Layer    │ │ Business    │ │ Local Storage   │ │
│ │             │ │ Logic Layer │ │ Layer           │ │
│ └─────────────┘ └─────────────┘ └─────────────────┘ │
│         │              │                │           │
│         └──────────────┼────────────────┘           │
│                        │                            │
│ ┌─────────────────────▼────────────────────────┐   │
│ │              Crypto Engine Layer              │   │
│ └─────────────────────┬────────────────────────┘   │
│                        │                            │
│ ┌─────────────────────▼────────────────────────┐   │
│ │            Network Communication Layer        │   │
│ └─────────────────────┬────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                Transport Layer                       │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                 Local Server                         │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐ │
│ │ API Layer   │ │ Service     │ │ Database Layer  │ │
│ │             │ │ Layer       │ │                 │ │
│ └─────────────┘ └─────────────┘ └─────────────────┘ │
│         │              │                │           │
│         └──────────────┼────────────────┘           │
│                        │                            │
│ ┌─────────────────────▼────────────────────────┐   │
│ │              Security Layer                   │   │
│ └─────────────────────┬────────────────────────┘   │
│                        │                            │
│ ┌─────────────────────▼────────────────────────┐   │
│ │            Message Broker & Router           │   │
│ └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### 1.2 Technology Stack

#### Client Application
- **Core Languages**: Rust (for cryptographic operations), Swift (iOS), Kotlin (Android), C++ (Desktop)
- **UI Frameworks**: Platform-native UI frameworks with minimal dependencies
- **Storage**: SQLCipher for encrypted local storage
- **Cryptographic Libraries**: libsodium, OpenSSL (with hardware acceleration when available)

#### Server (Local Deployment)
- **Core Languages**: Rust or Go
- **Framework**: Minimal HTTP/WebSocket server with custom handlers
- **Database**: SQLite with encryption extensions (SQLCipher)
- **Message Queue**: Custom implementation or lightweight solution like ZeroMQ
- **Containerization**: Docker for isolated environment

## 2. Detailed Component Design

### 2.1 Client-Side Components

#### 2.1.1 Crypto Engine

```rust
// Key management subsystem
struct KeyManager {
    identity_keypair: Ed25519KeyPair,  // Long-term identity
    prekeys: Vec<X25519KeyPair>,       // Pre-generated key material
    one_time_keys: Vec<X25519KeyPair>, // Single-use ephemeral keys
    session_keys: HashMap<SessionId, TripleRatchetState>
}

// Message encryption protocol
struct SecureMessage {
    header: EncryptedHeader,  // Metadata (encrypted separately)
    content: EncryptedPayload,
    auth_tag: AuthenticationTag,
    public_metadata: PublicMetadata  // Minimal routing information
}

// Triple Ratchet implementation (extension of Double Ratchet)
struct TripleRatchetState {
    root_chain: SymmetricRatchet,
    sending_chain: SymmetricRatchet,
    receiving_chain: SymmetricRatchet,
    dh_sending_keypair: X25519KeyPair,
    dh_receiving_public: X25519PublicKey,
    quantum_layer_keys: QuantumResistantKeyState
}
```

#### 2.1.2 Local Storage Layer

```rust
// Database schema (pseudo-code)
struct MessageStore {
    // Messages with total deniability
    fn store_message(&self, conversation_id: ConversationId, message: SecureMessage) -> Result<()>;
    fn get_messages(&self, conversation_id: ConversationId) -> Result<Vec<SecureMessage>>;
    
    // Encrypted indexes for search
    fn create_search_index(&self, message_id: MessageId, tokens: Vec<EncryptedToken>) -> Result<()>;
    fn search(&self, query: EncryptedQuery) -> Result<Vec<MessageId>>;
    
    // Contact management
    fn store_contact(&self, contact_id: ContactId, public_identity: IdentityPublicKey, metadata: EncryptedContactMetadata) -> Result<()>;
}

// All persistent data is encrypted at rest with unique keys
struct EncryptionManager {
    fn derive_database_key(&self, master_key: Key, database_id: DatabaseId) -> Result<DatabaseKey>;
    fn encrypt_payload(&self, data: &[u8], key: &DatabaseKey) -> Result<EncryptedData>;
    fn decrypt_payload(&self, encrypted: &EncryptedData, key: &DatabaseKey) -> Result<Vec<u8>>;
}
```

#### 2.1.3 Network Communication Layer

```go
// Network protocol handler (pseudo-code in Go)
type SecureTransport struct {
    // TLS 1.3 with custom cipher suite restrictions
    TLSConfig      *tls.Config
    
    // Connection obfuscation
    PaddingStrategy PaddingStrategy
    
    // Tor-like onion routing implementation
    RouteProvider   RouteProvider
}

func (t *SecureTransport) SendMessage(msg *EncryptedMessage) error {
    // 1. Apply traffic padding according to strategy
    paddedMsg := t.applyPadding(msg)
    
    // 2. Determine routing path (multiple hops if possible)
    route := t.RouteProvider.GetRoute()
    
    // 3. Apply onion encryption layers
    encryptedPacket := t.buildOnionPacket(paddedMsg, route)
    
    // 4. Send through secure channel with TLS 1.3
    return t.sendPacket(encryptedPacket, route[0])
}
```

### 2.2 Server-Side Components

#### 2.2.1 Message Handling Service

```go
// Server implementation (pseudo-code in Go)
type MessageServer struct {
    Router       *MessageRouter
    AuthService  *AuthenticationService
    Storage      *EncryptedStorage
    RateLimiter  *RateLimiter
}

func (s *MessageServer) HandleIncomingMessage(ctx context.Context, encryptedPacket []byte) error {
    // 1. Authenticate the request (zero-knowledge when possible)
    if err := s.AuthService.ValidateRequest(ctx); err != nil {
        return s.generateDeceptiveResponse(err) // Hide actual errors
    }
    
    // 2. Rate limit check
    if err := s.RateLimiter.CheckLimit(getClientIdentifier(ctx)); err != nil {
        return s.generateDeceptiveResponse(err) // Hide actual errors
    }
    
    // 3. Process the onion-routed message
    destinationID, message, err := s.Router.ProcessPacket(encryptedPacket)
    if err != nil {
        return s.generateDeceptiveResponse(err) // Hide actual errors
    }
    
    // 4. Store for recipient or route immediately if online
    if s.Router.IsRecipientOnline(destinationID) {
        return s.Router.DeliverMessage(destinationID, message)
    } else {
        return s.Storage.StoreMessage(destinationID, message)
    }
}
```

#### 2.2.2 Authentication & Authorization

```rust
// Authentication service (pseudo-code in Rust)
struct AuthenticationService {
    key_registry: HashMap<DeviceId, AuthenticationPublicKey>,
    device_attestations: HashMap<DeviceId, DeviceAttestation>,
    active_sessions: ConcurrentMap<SessionId, SessionState>,
}

impl AuthenticationService {
    // Zero-knowledge authentication
    fn authenticate_device(&self, 
                           auth_proof: AuthenticationProof, 
                           device_id: DeviceId) -> Result<SessionToken> {
        // 1. Verify the authentication proof without revealing the key
        if !self.verify_zero_knowledge_proof(auth_proof, device_id) {
            return Err(AuthError::InvalidProof);
        }
        
        // 2. Check device attestation (when available)
        if let Some(attestation) = self.device_attestations.get(&device_id) {
            if !self.verify_attestation(attestation) {
                return Err(AuthError::InvalidAttestation);
            }
        }
        
        // 3. Generate session token with short expiry
        let session_token = self.generate_session_token(device_id);
        
        // 4. Record session state with continuous auth requirements
        self.active_sessions.insert(session_token.id, SessionState::new(device_id));
        
        Ok(session_token)
    }
}
```

#### 2.2.3 Database Layer

```sql
-- SQLite schema with encryption through SQLCipher

-- Message queue table (minimized metadata)
CREATE TABLE pending_messages (
    message_id BLOB PRIMARY KEY, -- Random ID
    recipient_id BLOB NOT NULL,  -- Encrypted recipient ID
    message_blob BLOB NOT NULL,  -- Fully encrypted message
    timestamp INTEGER NOT NULL,  -- Timing information (for cleanup only)
    
    -- Indexes
    INDEX idx_recipient (recipient_id)
);

-- Device registration (minimal information)
CREATE TABLE registered_devices (
    device_id BLOB PRIMARY KEY,       -- Device identifier (hashed)
    public_key BLOB NOT NULL,         -- Verification key
    registration_timestamp INTEGER,   -- For key rotation policies
    last_active_timestamp INTEGER     -- For inactive device detection
);

-- Audit log (encrypted)
CREATE TABLE audit_log (
    event_id BLOB PRIMARY KEY,
    encrypted_event BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);
```

## 3. Security Protocol Specifications

### 3.1 End-to-End Encryption Protocol

```
┌──────────┐                                   ┌──────────┐
│          │                                   │          │
│  Alice   │                                   │   Bob    │
│          │                                   │          │
└────┬─────┘                                   └────┬─────┘
     │                                              │
     │ Generate:                                    │ Generate:
     │ - Identity Key Pair (IKa)                    │ - Identity Key Pair (IKb)
     │ - Signed Pre-Key (SPKa)                      │ - Signed Pre-Key (SPKb)
     │ - One-Time Pre-Keys (OPKa)                   │ - One-Time Pre-Keys (OPKb)
     │                                              │
     │                  Register Public Keys        │
     │ ─────────────────────────────────────────────▶
     │                                              │
     │                  Register Public Keys        │
     │ ◀─────────────────────────────────────────────
     │                                              │
     │ Request Bob's Keys                           │
     │ ─────────────────────────────────────────────▶
     │                                              │
     │ Receive:                                     │
     │ - IKb (public)                               │
     │ - SPKb (public)                              │
     │ - Signature of SPKb                          │
     │ - OPKb (public, one-time use)                │
     │                                              │
     │ Generate:                                    │
     │ - Ephemeral Key Pair (EKa)                   │
     │                                              │
     │ Calculate DH exchanges:                      │
     │ - DH1 = DH(IKa, SPKb)                        │
     │ - DH2 = DH(EKa, IKb)                         │
     │ - DH3 = DH(EKa, SPKb)                        │
     │ - DH4 = DH(EKa, OPKb)                        │
     │                                              │
     │ Combine: SK = KDF(DH1 || DH2 || DH3 || DH4)  │
     │                                              │
     │ Encrypt initial message:                     │
     │ - Header: IKa, EKa                           │
     │ - Ciphertext: AEAD(SK, message, header)      │
     │                                              │
     │                  Send Message                │
     │ ─────────────────────────────────────────────▶
     │                                              │
     │                                              │ Process Header:
     │                                              │ - Verify IKa
     │                                              │ - Calculate same DH exchanges
     │                                              │ - Derive SK
     │                                              │ - Decrypt message
     │                                              │
     │                  Triple Ratchet begins       │
     │                  for subsequent messages     │
     │                                              │
```

### 3.2 Triple Ratchet Protocol Flow

```
Triple Ratchet Protocol
-----------------------

1. Root Key Ratchet:
   SK = KDF(SK || DH(a_dh_private, b_dh_public))

2. Chain Keys:
   CKs, CKr = KDF(SK)
   
3. Message Keys:
   MK = KDF(CK)
   CK = KDF(CK)
   
4. Post-Quantum Layer:
   PQSK = PQ-KEM.Encapsulate(b_pq_public)
   
5. Final Message Key:
   FMK = KDF(MK || PQSK)
   
6. Message Encryption:
   CT = AEAD-Encrypt(FMK, message, associated_data)
   
7. After sending DH ratchet:
   a_dh_private, a_dh_public = DHKeyGen()
   SK = KDF(SK || DH(a_dh_private, b_dh_public))
   CKs, CKr = KDF(SK)

8. After receiving DH ratchet:
   SK = KDF(SK || DH(a_dh_private, b_dh_public))
   CKr, CKs = KDF(SK)
```

### 3.3 Local Authentication Protocol

```
User Authentication Flow
------------------------

1. Local Authentication:
   - Device biometric or PIN initializes secure enclave
   - Secure enclave unlocks local key store using device-bound key
   
2. Application Authentication:
   - Master application key derived from:
     MK = KDF(user_auth_material || device_key || app_salt)
   - All encryption keys derived from master key
   
3. Server Authentication:
   - Zero-knowledge proof:
     ZKP = Prove(knowledge of: user_key without revealing user_key)
   - Send ZKP to server for verification
   
4. Session Maintenance:
   - Session keys rotated every 15 minutes
   - Connection re-authentication for long sessions
   - Background revalidation of device integrity
```

## 4. Data Flow Lifecycle

### 4.1 Message Lifecycle

```
Message Creation and Delivery
----------------------------

1. User Composes Message:
   ┌─────────────┐
   │ UI Layer    │──► Add metadata (timestamps, etc.)
   └─────────────┘
          │
          ▼
   ┌─────────────┐
   │ Business    │──► Apply message rules and formatting
   │ Logic Layer │
   └─────────────┘
          │
          ▼
   ┌─────────────┐
   │ Crypto Layer│──► End-to-end encryption
   └─────────────┘    Triple ratchet protocol
          │
          ▼
   ┌─────────────┐
   │ Network     │──► Traffic obfuscation, padding
   │ Layer       │    Onion routing when possible
   └─────────────┘
          │
          ▼
   ┌─────────────┐
   │ Local       │──► Message queuing, delivery attempts
   │ Server      │    Store for offline recipients
   └─────────────┘
```

### 4.2 Key Management Lifecycle

```
Key Lifecycle Management
-----------------------

Identity Keys:
- Generated at account creation
- Backed up with secure recovery mechanism
- Never leave the device unencrypted
- Rotation: Manual with migration protocol

Session Keys:
- Generated for each new conversation
- Rotated with each message (Triple Ratchet)
- Deleted after session termination
- Perfect forward secrecy ensures

Pre-Keys:
- Generated in batches on device
- Uploaded to server with minimal metadata
- One-time use, replenished when running low
- Server cannot see or use actual key material
```

## 5. Security Implementation Details

### 5.1 Cryptographic Algorithm Implementation

```rust
// Simplified XChaCha20-Poly1305 encryption (pseudo-code)
fn encrypt_message(
    message: &[u8], 
    key: &[u8; 32], 
    nonce: &[u8; 24], 
    associated_data: &[u8]
) -> Result<Vec<u8>> {
    // XChaCha20-Poly1305 AEAD implementation
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.encrypt(nonce.into(), Payload {
        msg: message,
        aad: associated_data,
    })
}

// Post-quantum hybrid encryption
fn hybrid_encrypt(
    message: &[u8],
    ec_public_key: &X25519PublicKey,
    kyber_public_key: &KyberPublicKey,
    associated_data: &[u8]
) -> Result<HybridCiphertext> {
    // Generate ephemeral keys
    let ephemeral_x25519 = X25519KeyPair::generate();
    let shared_secret_x25519 = ephemeral_x25519.diffie_hellman(ec_public_key);
    
    // Kyber encapsulation
    let (kyber_ciphertext, kyber_shared_secret) = kyber_encapsulate(kyber_public_key);
    
    // Combine shared secrets
    let combined_secret = kdf_sha512(
        shared_secret_x25519.as_bytes(), 
        kyber_shared_secret.as_bytes()
    );
    
    // Create symmetric encryption key and nonce
    let (encryption_key, nonce) = split_into_key_and_nonce(&combined_secret);
    
    // Encrypt message with XChaCha20-Poly1305
    let ciphertext = encrypt_message(message, &encryption_key, &nonce, associated_data)?;
    
    Ok(HybridCiphertext {
        ephemeral_x25519_public: ephemeral_x25519.public_key(),
        kyber_ciphertext,
        encrypted_message: ciphertext,
    })
}
```

### 5.2 Memory Safety Practices

```rust
// Secure memory management for cryptographic keys
struct SecureKey<const N: usize> {
    bytes: secrecy::Secret<[u8; N]>
}

impl<const N: usize> Drop for SecureKey<N> {
    fn drop(&mut self) {
        // Secure zeroing of memory before deallocation
        secrecy::zeroize(self.bytes.expose_secret());
    }
}

// Memory locking to prevent swapping of sensitive data
fn initialize_secure_memory() {
    // Lock memory pages containing key material
    // to prevent them from being swapped to disk
    #[cfg(unix)]
    {
        use nix::sys::mman::{mlockall, MlockallFlags};
        mlockall(MlockallFlags::MCL_CURRENT | MlockallFlags::MCL_FUTURE)
            .expect("Failed to lock memory pages");
    }
    
    // Disable core dumps
    #[cfg(unix)]
    {
        use std::process::Command;
        Command::new("ulimit")
            .args(&["-c", "0"])
            .output()
            .expect("Failed to disable core dumps");
    }
}
```

### 5.3 Anti-Forensic Techniques

```rust
// Deniable storage implementation
struct DeniableStorage {
    // Hidden volume within ordinary-looking database
    outer_db: SqliteConnection,
    hidden_volume: Option<EncryptedVolume>,
}

impl DeniableStorage {
    // Creates plausible decoy data that appears normal
    fn populate_decoy_data(&mut self) -> Result<()> {
        let decoy_conversations = generate_realistic_conversations();
        for convo in decoy_conversations {
            self.outer_db.execute(
                "INSERT INTO conversations VALUES (?, ?, ?)",
                params![convo.id, convo.name, convo.timestamp]
            )?;
            
            for msg in convo.messages {
                self.outer_db.execute(
                    "INSERT INTO messages VALUES (?, ?, ?, ?)",
                    params![msg.id, convo.id, msg.content, msg.timestamp]
                )?;
            }
        }
        Ok(())
    }
    
    // Provides alternate "innocent" password that reveals decoy data
    fn open_with_duress_password(&mut self, password: &str) -> Result<()> {
        // Authenticate with decoy credentials, revealing only non-sensitive data
        self.outer_db = SqliteConnection::open_encrypted("database.db", password)?;
        self.hidden_volume = None; // Do not open hidden volume
        Ok(())
    }
    
    // Real password reveals hidden messages
    fn open_with_true_password(&mut self, password: &str) -> Result<()> {
        // Open outer DB with decoy view
        self.outer_db = SqliteConnection::open_encrypted("database.db", &derive_decoy_key(password))?;
        
        // Open hidden volume embedded in slack space or steganographically
        let hidden_key = derive_hidden_volume_key(password);
        self.hidden_volume = Some(EncryptedVolume::open("database.db", hidden_key)?);
        
        Ok(())
    }
}
```

## 6. Local Deployment Architecture

### 6.1 Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  messenger-server:
    build:
      context: ./server
      dockerfile: Dockerfile
    ports:
      - "127.0.0.1:8443:8443"  # Only expose locally
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      - RUST_LOG=info
      - SERVER_MODE=standalone
      - DATABASE_ENCRYPTION_KEY_FILE=/app/config/keys/db_key.enc
    restart: unless-stopped
    cap_drop:
      - ALL  # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE  # Minimum required
    security_opt:
      - no-new-privileges:true
      - seccomp=./seccomp_profile.json
    
  hardened-db:
    image: postgres:alpine
    volumes:
      - ./db_data:/var/lib/postgresql/data
      - ./db_init:/docker-entrypoint-initdb.d
    environment:
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
      - POSTGRES_INITDB_ARGS=--data-checksums
    secrets:
      - db_password
    restart: unless-stopped
    network_mode: "service:messenger-server"  # Use messenger-server network
    
secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### 6.2 Local Network Security

```shell
# Setup local firewall rules (simplified example for Linux)
iptables -A INPUT -p tcp --dport 8443 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# Create TLS certificate for local HTTPS
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout ./config/certs/server.key \
  -out ./config/certs/server.crt \
  -subj "/CN=localhost"

# Generate strong Diffie-Hellman parameters
openssl dhparam -out ./config/certs/dhparams.pem 4096
```

### 6.3 Secure Configuration

```json
// config.json
{
  "server": {
    "bind_address": "127.0.0.1",
    "port": 8443,
    "max_connections": 100,
    "connection_timeout_ms": 30000,
    "tls": {
      "cert_path": "/app/config/certs/server.crt",
      "key_path": "/app/config/certs/server.key",
      "min_version": "TLSv1.3",
      "cipher_suites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
      ],
      "prefer_server_cipher_suites": true,
      "session_ticket_lifetime": 3600
    }
  },
  "security": {
    "password_hashing": {
      "algorithm": "argon2id",
      "time_cost": 4,
      "memory_cost": 65536,
      "parallelism": 2
    },
    "rate_limiting": {
      "window_size_ms": 60000,
      "max_requests": 30
    },
    "audit_logging": {
      "enabled": true,
      "log_level": "INFO",
      "retention_days": 90
    }
  },
  "storage": {
    "database_type": "sqlite",
    "database_path": "/app/data/messenger.db",
    "encryption": {
      "enabled": true,
      "key_derivation": "pbkdf2",
      "iterations": 100000
    }
  }
}
```

## 7. Client-Server Interactions

### 7.1 Authentication Flow

```
┌──────────┐                           ┌──────────┐
│          │                           │          │
│  Client  │                           │  Server  │
│          │                           │          │
└────┬─────┘                           └────┬─────┘
     │                                      │
     │  1. Initial TLS 1.3 Handshake        │
     │ ─────────────────────────────────────▶
     │                                      │
     │ ◀─────────────────────────────────────
     │                                      │
     │  2. Client Hello with Auth Request   │
     │ ─────────────────────────────────────▶
     │    {                                 │
     │      device_id: [hashed_id],        │
     │      auth_method: "zero_knowledge",  │
     │      timestamp: [current_time],      │
     │      client_nonce: [random_bytes]    │
     │    }                                 │
     │                                      │
     │                                      │  3. Check device registration
     │                                      │     Generate server_nonce
     │                                      │
     │  4. Server Challenge                 │
     │ ◀─────────────────────────────────────
     │    {                                 │
     │      server_nonce: [random_bytes],   │
     │      challenge: [derived_challenge]  │
     │    }                                 │
     │                                      │
     │  5. Process challenge, create proof  │
     │     using device-bound private key   │
     │                                      │
     │  6. Client Proof                     │
     │ ─────────────────────────────────────▶
     │    {                                 │
     │      device_id: [hashed_id],         │
     │      proof: [zkp_authentication],     │
     │      client_nonce: [same_as_before]  │
     │    }                                 │
     │                                      │
     │                                      │  7. Verify ZKP proof
     │                                      │     Generate session token
     │                                      │     Start session monitoring
     │                                      │
     │  8. Authentication Result            │
     │ ◀─────────────────────────────────────
     │    {                                 │
     │      status: "success",              │
     │      session_token: [encrypted_token],│
     │      expires_at: [expiry_timestamp]  │
     │    }                                 │
     │                                      │
```

### 7.2 Message Delivery Protocol

```
┌──────────┐                           ┌──────────┐
│          │                           │          │
│  Sender  │                           │  Server  │
│          │                           │          │
└────┬─────┘                           └────┬─────┘
     │                                      │
     │  1. Prepare encrypted message        │
     │     with recipient's public key      │
     │                                      │
     │  2. Send Message Request             │
     │ ─────────────────────────────────────▶
     │    {                                 │
     │      session_token: [token],         │
     │      message: {                      │
     │        id: [random_id],              │
     │        recipient: [encrypted_id],    │
     │        content: [encrypted_content], │
     │        metadata: [minimal_metadata]  │
     │      }                               │
     │    }                                 │
     │                                      │
     │                                      │  3. Validate session token
     │                                      │     Check rate limits
     │                                      │     Process message routing
     │                                      │
     │  4. Delivery Receipt                 │
     │ ◀─────────────────────────────────────
     │    {                                 │
     │      status: "enqueued",             │
     │      message_id: [random_id],        │
     │      timestamp: [server_timestamp]   │
     │    }                                 │
     │                                      │
     │                                      │
     │                                      │         ┌────────────┐
     │                                      │         │            │
     │                                      │         │ Recipient  │
     │                                      │         │            │
     │                                      │         └─────┬──────┘
     │                                      │               │
     │                                      │  5. Notify if online
     │                                      │ ──────────────▶
     │                                      │               │
     │                                      │  6. Fetch Message Request
     │                                      │ ◀──────────────
     │                                      │               │
     │                                      │  7. Deliver encrypted message
     │                                      │ ──────────────▶
     │                                      │               │
     │                                      │  8. Decrypt with private key
     │                                      │    Verify authenticity
     │                                      │    Update local storage
     │                                      │               │
     │                                      │  9. Delivery confirmation
     │                                      │ ◀──────────────
     │                                      │
     │                                      │
```

## 8. Performance Optimizations

### 8.1 Resource Efficiency

```go
// Efficient message handling (Go pseudo-code)
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
    // Use connection pooling
    pool := s.getWorkerPool()
    
    // Submit task to worker pool
    pool.Submit(func() {
        defer conn.Close()
        
        // Set short read deadline to prevent slow loris attacks
        conn.SetReadDeadline(time.Now().Add(5 * time.Second))
        
        // Read with buffer limiting
        buf := bufferPool.Get().([]byte)
        defer bufferPool.Put(buf)
        
        n, err := conn.Read(buf)
        if err != nil {
            s.metrics.IncrementFailedConnections()
            return
        }
        
        // Process message with memory constraints
        s.processMessage(ctx, buf[:n])
    })
}

// Memory-efficient buffer pooling
var bufferPool = &sync.Pool{
    New: func() interface{} {
        return make([]byte, 32*1024) // 32KB buffers
    },
}
```

### 8.2 Compression for Low-Bandwidth Environments

```rust
// Adaptive compression based on content and network conditions
fn compress_message(
    content: &[u8], 
    network_quality: NetworkQuality,
    message_priority: Priority
) -> Vec<u8> {
    match (network_quality, message_priority) {
        (NetworkQuality::Good, _) => {
            // Use light compression for good networks
            compress_with_zstd(content, 1)
        },
        (NetworkQuality::Medium, Priority::High) => {
            // Medium compression for medium quality networks
            compress_with_zstd(content, 9)
        },
        (NetworkQuality::Poor, _) => {
            // Max compression for poor networks
            compress_with_zstd(content, 19)
        },
        _ => {
            // Default compression
            compress_with_zstd(content, 3)
        }
    }
}

// Apply compression before encryption
fn prepare_message_for_sending(
    message: &Message,
    recipient_keys: &RecipientKeys,
    network_monitor: &NetworkMonitor
) -> Result<EncryptedMessage> {
    // Check message size and network conditions
    let network_quality = network_monitor.get_current_quality();
    
    // Apply compression if beneficial
    let processed_content = if message.content.len() > 1024 {
        compress_message(&message.content, network_quality, message.priority)
    } else {
        message.content.clone() // Don't compress small messages
    };
    
    // Apply padding to standardize message sizes
    let padded_content = apply_padding(processed_content, network_quality);
    
    // Proceed with encryption
    encrypt_for_recipient(padded_content, recipient_keys)
}
```

## 9. Testing & Validation

### 9.1 Security Test Cases

```rust
// Test Triple Ratchet implementation (pseudo-code)
#[test]
fn test_triple_ratchet_forward_secrecy() {
    // Setup Alice and Bob's identity keys
    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    
    // Initialize session
    let mut alice_session = TripleRatchetSession::init_as_alice(&alice_identity, &bob_identity.public);
    let mut bob_session = TripleRatchetSession::init_as_bob(&bob_identity, &alice_identity.public);
    
    // Exchange initial messages
    let message1 = "First message";
    let encrypted1 = alice_session.encrypt(message1.as_bytes());
    let decrypted1 = bob_session.decrypt(&encrypted1).expect("Failed to decrypt");
    assert_eq!(message1.as_bytes(), decrypted1.as_slice());
    
    // Compromise a key
    let compromised_key = alice_session.current_sending_key().clone();
    
    // Continue communication after compromise
    let message2 = "Second message with forward secrecy";
    let encrypted2 = alice_session.encrypt(message2.as_bytes());
    
    // Verify an attacker with the compromised key cannot decrypt
    let mut attacker_session = bob_session.clone();
    attacker_session.inject_compromised_key(compromised_key);
    let attacker_attempt = attacker_session.decrypt(&encrypted2);
    assert!(attacker_attempt.is_err());
    
    // Verify legitimate recipient can decrypt
    let decrypted2 = bob_session.decrypt(&encrypted2).expect("Failed to decrypt");
    assert_eq!(message2.as_bytes(), decrypted2.as_slice());
}

// Cryptographic implementation validation
#[test]
fn test_against_known_test_vectors() {
    // XChaCha20-Poly1305 test vectors from RFC
    let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    
    let ciphertext = encrypt_xchacha20poly1305(
        plaintext, 
        &key, 
        &nonce, 
        &aad
    ).expect("Encryption failed");
    
    // Compare with expected output from test vectors
    let expected = hex::decode("...[expected test vector output]...").unwrap();
    assert_eq!(ciphertext, expected);
}
```

### 9.2 Penetration Testing Plan

```markdown
## Security Testing Plan

### 1. Static Analysis
- Run Rust analyzer and clippy with security lints
- Run semgrep with crypto rules
- Validate memory safety with MIRI
- Check dependencies with cargo-audit

### 2. Dynamic Analysis
- Fuzz protocol implementations with cargo-fuzz
- Memory safety testing with Valgrind/ASan

### 3. Cryptographic Validation
- Validate all crypto implementations against test vectors
- Verify forward secrecy properties
- Test for side-channel leakage using timing analysis

### 4. Penetration Testing Scenarios
- Attempt to perform MitM attacks during key exchange
- Test for replay attacks against the protocol
- Try to extract keys from memory 
- Attempt social engineering against authentication

### 5. Secure Code Review Checklist
- No hardcoded secrets or credentials
- Proper error handling without information leakage
- Constant-time comparisons for all sensitive operations
- Secure memory handling (zeroing after use)
- No debug or logging of sensitive data
```

## 10. Deployment Guidelines

### 10.1 Local Development Setup

```bash
#!/bin/bash
# Setup local development environment

# Create directories
mkdir -p ./config/certs ./config/keys ./data ./secrets

# Generate random keys for development
openssl rand -base64 32 > ./secrets/db_password.txt
openssl rand -base64 64 > ./config/keys/db_key.enc

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout ./config/certs/server.key \
  -out ./config/certs/server.crt \
  -subj "/CN=localhost"

# Set proper permissions
chmod 600 ./config/keys/db_key.enc ./secrets/db_password.txt
chmod 600 ./config/certs/server.key

# Build and start in development mode
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

### 10.2 Security Hardening

```bash
#!/bin/bash
# System hardening script for secure messenger deployment

# Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf

# Set secure permissions
chmod 700 /app/config /app/data
chmod 600 /app/config/keys/* /app/config/certs/*

# Configure kernel parameters for security
cat > /etc/sysctl.d/99-security.conf << EOF
# Restrict kernel pointers
kernel.kptr_restrict=2

# Restrict access to kernel logs
kernel.dmesg_restrict=1

# Enable ASLR
kernel.randomize_va_space=2

# Protect against time-of-check-time-of-use attacks
fs.protected_hardlinks=1
fs.protected_symlinks=1

# Disable ptrace for enhanced memory protection
kernel.yama.ptrace_scope=2
EOF

# Apply sysctl settings
sysctl --system

# Check for listening ports and running services
echo "Checking for unnecessary open ports..."
ss -tulpn

# Ensure messenger service runs as non-root
useradd -r -s /bin/false messenger
chown -R messenger:messenger /app/data
```