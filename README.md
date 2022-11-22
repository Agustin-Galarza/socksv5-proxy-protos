# SOCKSv5 Proxy

## Índice

- [SOCKSv5 Proxy](#socksv5-proxy)
  - [Índice](#índice)
    - [Ubicación de los archivos](#ubicación-de-los-archivos)
    - [Generación de ejecutables](#generación-de-ejecutables)
    - [Artefactos Generados](#artefactos-generados)
      - [Servidor](#servidor)
      - [Cliente](#cliente)

---

### Ubicación de los archivos
- Definición de protocolo de admin: `./YetAnotherProtocol.txt`
- Informe: `./Informe TPE.pdf`
- Archivos ejecutables: `./bin/`
- Archivo de construcción: `./Makefile` 

### Generación de ejecutables
`make server` para compilar el servidor
`make client` para compilar la aplicación cliente
`make all` para compilar ambos programas

### Artefactos Generados
#### Servidor
`./bin/socks5d`
#### Cliente
`./bin/socks5c`
