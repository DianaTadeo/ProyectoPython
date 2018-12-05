#!/usr/bin/python
# -*- coding: utf-8 -*-
#Proyecto de Curso Python: Port Scanner
#Autores:
#		Hernaandez Ginzalez Ricardo O.
#		Juarez Mendez Jesika.
#		Tadeo Guillen Diana G.
import sys
import optparse

def printError(msg, exit = False):
        sys.stderr.write('Error:\t%s\n' % msg)
        if exit:
            sys.exit(1)

def opciones():
	 '''
    Funcion que permite agregar las banderas correspondientes para el uso del
    programa ejecutado como script.
    '''
    parser = optparse.OptionParser()
    parser.add_option('-p','--ports', dest='ports', default='80', help='Puerto, lista de puertos rando de puertos o una combinacion de estas opciones.')
    parser.add_option('-s','--servers', dest='servers', default=None, help='Host, lista de hosts o segmento.')
    parser.add_option('-t','--time', action='store_true', dest='tiempo', default=1, help='Retardo entre paquetes.')
    parser.add_option('-v','--verbose', action='store_true', dest='verbose', default=False, help='Modo verboso.')
    parser.add_option('-o','--reporte', dest='reporte', default=None, help='Archivo en donde se escribir[a el reporte. De no esar, se mostrara en la salida standard.')
    parser.add_option('-c', '--configure', dest='configuracion', default=None, help='Archivo de configuracion')
    opts,args = parser.parse_args()
    return opts

def checaOpciones(opciones):
	'''
    Funcion que valida que todas las opciones obligatorias se hayan agregado
    '''
    if opciones.ports is None:
        printError('Se debe especificar al menos un puerto, lista de puertos o un rango.', True)
    if opciones.servers is None:
        printError('Se debe especificar al menos un host, una lista de hosts o un segmento.', True)
	
def leeConfiguracion(archivo):
	'''
	Funcion que lee un archivo de configuracion para poder realizar el escaneo
	con la informacion que en ese archivo se encuentre
	'''
	try:
		if v:
			print 'Se itentan leer el archivo de configuracion'
	except Exception as e:
		printError('El archivo de configuracion contiene errores. Por favor revisalo.')
		printError(e, True)
		
def leePuertos(puertos,v): #Ya que van a ser uno o varios convendria tomarla como lista
	'''
	Funcion que revisa si se paso un solo puerto, una lista de puertos o un rango
	de puertos.
	puertos: puerto, lista de puertos o rango de puertos
	v: Indica si se requiere el modo verboso
	'''
	try:
		if v:
			print 'Se revisan los puertos'
	except Exception as e:
		printError('La entrada de los puertos fue incorrecta')
		printError(e, True)
				

def leeHosts(hosts,v): #Ya que van a ser uno o varios convendria tomarla como lista
	'''
	Funcion que revisa si se paso un solo host, una lista de hosts o un segmento de
	red.
	hosts: Host, lista de host o segmento
	v: Indica el modo verboso
	'''
	try:
		if v:
			print 'Se revisan los hosts'
	except Exception as e:
		printError('La engtrada de los hosts fue incorrecta')
		printError(e, True)
		

def validaPuertos(puertos):
	'''
	Funcion que devuelve una lista de puertos para cualquier entrada de tipo
	puerto, rango de puertos o lista de ambos
	'''
	lista=r'(.+,.+)+'
	rango=r'[0-9]{1,4}-[0-9]{1,4}'
	if re.match(lista,puertos):#Si es una lista de puertos o rangos
		lista_p= (puertos.replace(' ', '')).split(',')
		lista_puertos=[]
		for elemento in lista_p:#Se revisa si hay o no rangos en la lista
			if re.match(rango,elemento):
				lista_puertos=lista_puertos+guardaRangoPuertos(elemento)
			else:
				lista_puertos.append(int(elemento))
		return lista_puertos
	elif re.match(rango,puertos): #si es solo un rango de puertos
		return guardaRangoPuertos(puertos)
	else: #Se asume que solo es uno si no entro en las otras, se regresa como una lista de un elemento
		return [int(puertos)] 

def guardaRangoPuertos(rango):
	'''
	Funcion auxiliar que genera una lista de puertos a partir
	de un rango en forma de cadena de la forma '23-466'
	'''
	inicio=int(rango[:rango.find('-'):])
	fin=int(rango[rango.find('-')+1::])
	return [port for port in range(inicio,fin+1)]		
		
def buildURL(v,server,protocol = 'http'):
    '''
    funcion que construye una url de acuerdo a los valores que se le pasan
    v: Indica el modo verboso
    server: la ip del servidor (host)
	protocol: indica el protocolo de conexi[on
    '''
    url = '%s://%s' % (protocol,server)
    if v:
		print 'Se obtuvo la URL: '+url+'\n'
    return url
    
def generaReporte(opciones):
	'''
	Funcion que se encarga de generar el reporte a partir de los resultados
	'''
	if opciones.verbose:
		print 'Se genera el reporte'
	datos='Hora: '+str(datetime.now())
	banderas='Las banderas que se usaron: '
	if opciones.ports is not None:
		banderas+='\t -p  --ports\n'
	if opciones.servers is not None:
		banderas+='\t -s  --servers\n'
	if opciones.time is not None:
		banderas+='\t -t  --time\n'
	if opciones.verbose is not None:
		banderas+='\t -v  --verbose\n'
	if opciones.reporte is not None:
		banderas+='/t -o  --reporte\n'
	if opciones.configuracion is not None:
		banderas+='/t -c  --configure\n'	
	
	
