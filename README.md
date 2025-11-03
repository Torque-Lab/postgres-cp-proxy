
# PostgreSQL Control Plane Proxy

A high-performance TCP gateway for PostgreSQL Wire Protocol that handles SSL termination, SCRAM authentication, and connection management while acting as a secure proxy between clients and PostgreSQL servers.

## Documentation Reference
- https://www.postgresql.org/docs/current/protocol.html

## Features

- SSL/TLS termination 
- SCRAM-SHA-256 authentication
- Connection routing and load balancing
- TCP Relays

## Architecture

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Proxy
    participant S as PostgreSQL

    %% Phase 1: Client to Proxy Connection
    Note over C,P: 1. Connection Initialization
    C->>P: TCP SYN
    P->>C: TCP SYN-ACK
    C->>P: TCP ACK
    
    %% Phase 2: Startup Message and SSL Handshake
    Note over C,P: 2. PostgreSQL Startup
    C->>P: StartupMessage (SSLRequest)
    P-->>C: SSL Negotiation Response
    C->>P: SSL Handshake (if SSL enabled)
    C->>P: StartupMessage (with user/database)

    %% Phase 3: SCRAM Authentication
    Note over C,P: 3. SCRAM Authentication
    P-->>C: AuthenticationSASL (SCRAM-SHA-256)
    C->>P: SASLInitialResponse
    P-->>C: AuthenticationSASLContinue
    C->>P: SASLResponse (final client response)
    P-->>C: AuthenticationSASLFinal (final proxy response)


## Start of extra information
 Proxy → Client:
  R 10  SCRAM-SHA-256

Client → Proxy:
  p "SCRAM-SHA-256", client-first-message: n,,n=alice,r=fyko+d2lbbFgONRv9qkxdawL

Proxy → Client:
  R 11  server-first-message: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096

Client → Proxy:
  p client-final-message: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=base64(clientproof)

Proxy → Client:
  R 12  server-final-message: v=base64(serversignature)

Proxy → Client:
  R 0   Here Auth will be checked and if valid ,open connection to backend which directly reply to real client AuthenticationOK and take over the connection

## end of extra information


    %% Phase 4: Backend Connection (if auth valid in previous phase open connection to backend which directly reply to real client AuthenticationOK and take over the connection)
    Note over P,S: 4. Backend Connection
    P->>S: StartupMessage

    %% Think of Relay Phase starting...
    S<<-->>C: AuthenticationOK
    S<<-->>C: ParameterStatus
    S<<-->>C: ReadyForQuery

    %% Phase 5: Normal Operation
    Note over C,S: 5. Normal Operation
        C->>S: Query
        S<<-->>C: RowDescription
        S<<-->>C: DataRow
        S<<-->>C: CommandComplete
        S<<-->>C: ReadyForQuery