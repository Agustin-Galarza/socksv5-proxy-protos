# SOCKSv5 Proxy

## Índice

- [Ubicación de los archivos](#ubicación-de-los-archivos)
- [Generación de ejecutables](#generación-de-ejecutables)
- [Artefactos Generados](#artefactos-generados)

---

### Ubicación de los archivos
- Definición de protocolo de admin: `./YetAnotherProtocol.txt`
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
