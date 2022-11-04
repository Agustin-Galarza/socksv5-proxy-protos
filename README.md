# SOCKSv5 Proxy

## Índice

[Ubicación de los archivos](#ubicación-de-los-archivos)
[Generación de ejecutables](#generación-de-ejecutables)
[Artefactos Generados](#artefactos-generados)
[Checkeo estático](#checkeo-estático)

---

### Ubicación de los archivos

### Generación de ejecutables

make all

### Artefactos Generados

`./bin/socks_proxy`: correr con `./run.sh`

### Docker
también es posible correr todo con docker:
```bash
docker-compose build
docker-compose up
```

### Checkeo estático

Correr `static_analysis.sh`
El programa toma como primer argumento la dirección del ejecutable a testear seguido de sus argumentos, o por defecto a `./bin/socks_proxy`.
Los resultados se dejan en la carpeta `./static_analysis_results`
