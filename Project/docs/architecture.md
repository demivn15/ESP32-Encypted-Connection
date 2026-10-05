# Arquitectura implementada

~~~mermaid
flowchart LR
    CA[Consola USB A] --> A[ESP32 A: Session]
    A <--> W[ESP-NOW canal 1: medio no confiable]
    W <--> B[ESP32 B: Session]
    B --> CB[Consola USB B]
    KA[Credencial privada de pareja] --> A
    KA --> B
    A --> CR[ECDH P-256 + HMAC + HKDF + AES-GCM]
    B --> CR
~~~

Cada computadora programa y monitorea su placa. No coordina ni descifra el
trafico entre placas. El callback de WiFi copia frames a una cola; loop()
comprueba el protocolo y presenta resultados. Los endpoints son quienes cifran.
