# Secuencia implementada

~~~mermaid
sequenceDiagram
    participant A as ESP32 A
    participant B as ESP32 B
    A->>B: HELLO: SID, QA, NA, MAC A, HMAC
    B->>B: Verificar HMAC, generar QB y NB
    B->>A: RESPONSE: QB, NB, MAC B, HMAC(T)
    A->>A: Verificar HMAC(T), validar QB, ECDH, HKDF
    B->>B: Validar QA, ECDH, HKDF
    A->>B: READY cifrado, SEQ 0, clave A->B
    B->>A: READY cifrado, SEQ 0, clave B->A
    A->>B: TEXT: cabecera AAD, ciphertext, tag, SEQ 1+
    B->>B: Verificar origen/SID/nonce/GCM, confirmar replay
    B->>A: ACK cifrado: referencia al SEQ del TEXT, SEQ propio
    A->>A: Verificar ACK y referencia; registrar RTT_TEXT
~~~

PROTOCOLO.md especifica todos los bytes y las excepciones de reintento.
