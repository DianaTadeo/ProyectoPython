# Proyecto de Python - Port Scanner

El objetivo de este programa es indicar qué puertos TCP se encuentran abiertos en determinado host o grupo de hosts.

### Integrantes:

- Hernández González Ricardo O.
- Juárez Méndez Jesika
- Tadeo Guillen Diana G.

### Prerrequisitos

Utilizamos un módulo externo llamado _**ipcalc**_

- Para instalarlo:

```bash
pip install ipcalc
```

### Correr el programa

- Si se quiere escanear varios puertos en un solo host:

```
python Port_Scanner.py -s 84.19.176.42 -p 22,80,443,21
```

- Si se quiere escanear varios host con varios puertos:

```
python Port_Scanner.py -s 84.19.176.42,pablotadeo.com -p 22,80,443,21 
```

- Si se quiere escanear las ip's de un segmento de red con varios puertos:

```
python Port_Scanner.py -s 192.168.4.0/23 -p 22,80,443,21 
```

- Si se quiere modo verboso: 

```
python Port_Scanner.py -s 84.19.176.42,pablotadeo.com -p 22,80,443,21 -v 
```

- Por omisión el archivo donde generá el reporte se llama "reporte.txt", si se quiere indicar el nombre del archivo:

```
python Port_Scanner.py -s 84.19.176.42,pablotadeo.com -p 22,80,443,21 -v -o archivo.txt
```

- Para indicar el intervalo de tiempo:

```
python Port_Scanner.py -s 84.19.176.42,pablotadeo.com -p 22,80,443,21 -v -o f.txt -t 5
```

- Si se quiere ejecutar el código con un archivo de configuración:

```
python Port_Scanner.py -c conf.txt
```

Si se quiere indicar las opciones en un archivo deberá tener el siguiente formato:

- Las opciones deben estar por renglon
- Los valores deben estar separados por un espacio
- Pueden ir en el orden que se desee

Ejemplo:

```
-s 84.19.176.42,pablotadeo.com
-p 22,80,443,53
-v
-o archivo.txt
-t 5
```

- Si se quiere ejecutar el código con un archivo de configuración:

```
python Port_Scanner.py -c conf.txt
```