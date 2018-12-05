#!/usr/bin/python
# -*- coding: utf-8 -*-
#Proyecto de Curso Python: Port Scanner
#Autores:
#		Hernández González Ricardo O.
#		Juarez Mendez Jesika.
#		Tadeo Guillen Diana G.
import sys
import optparse
import re
from socket import *
from time import sleep
from datetime import datetime

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
    parser.add_option('-o','--reporte', dest='reporte', default='reporte.txt', help='Archivo en donde se escribir[a el reporte. De no esar, se mostrara en la salida standard.')
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
		
def escanea(hosts,puertos,retraso,v): 	
	'''
	Funcion que realiza el escaneo de la lista de hosts en los puertos indicados
	con un tiempo de retraso definido.
	hosts: Es una lista de hosts (puede contener solo 1 elemento)
	puertos: Es una lista de puertos (puede contener solo 1 elemento)
	retraso: El tiempo de retraso del envio de paquetes
	v: Identifica si se aplicara la funcion verbose
	'''
	try:
		salida=''
		if v:
			print 'Se revisan los hosts'
		for host in hosts:
			ip_host= gethostbyname(host)
			salida+= 'Host:  %s \n' %(host) 
			for puerto in puertos:
				cliente = socket(AF_INET, SOCK_STREAM)
				resultado = cliente.connect_ex((ip_host, puerto))
				print host, puerto, resultado
				if (resultado == 0):
					salida+= 'puerto %d: Abierto\n' %(puerto)
				cliente.close()
				sleep(retraso)
		print salida
	except Exception as e:
		printError('Ocurrio un error inesperado')
		printError(e, True)
		
    
def generaReporte(opciones):
	'''
	Funcion que se encarga de generar el reporte a partir de los resultados
	'''
	if opciones.verbose:
		print 'Se genera el reporte'
	with open(opciones.reporte,"w") as file:
		file.write(str(datetime.now()) + '\n\n')
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
		file.write(banderas)	
	
	
if __name__ == '__main__':
	
	escanea(['84.19.176.42'],[22,80,443],2,True)
	
	
