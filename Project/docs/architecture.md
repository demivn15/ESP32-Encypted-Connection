<!-- Mermaid code for the System Architecture diagram. -->

architecture-beta
group application_layer[Application Layer]
    service user[Serial CLI] in application_layer
    service plaintext[Plaintext] in application_layer
    service session_controller[Session Controller] in application_layer

group cryptographic_protocol_layer[Cryptographic Protocol Layer]
    service ecdh[ECDH Session Key Derivation] in cryptographic_protocol_layer
    service aes_gcm[AES_128_GCM] in cryptographic_protocol_layer
    service sequence_number[Replay Protection Tracker SEQ] in cryptographic_protocol_layer

group transmission_layer[Transmission Layer]
    service packet_formatting[Packet Serialization] in transmission_layer 

group physical_layer[Physical Layer]
    service esp_connection[Wireless Driver] in physical_layer

user:L --> R:plaintext
plaintext:B --> T:aes_gcm
session_controller:B --> T:ecdh
ecdh:R --> L:aes_gcm
sequence_number:L --> R:aes_gcm
aes_gcm:B --> T:packet_formatting
packet_formatting:B --> T:esp_connection