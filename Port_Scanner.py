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
import ipcalc #instalar ipcalc


def printError(msg, exit = False):
    '''
		Función para imprimir en la salida estandar de error y terminar ejecución
	'''
    sys.stderr.write('Error:\t%s\n' % msg)
    if exit:
        sys.exit(1)


def opciones():
    '''
	    Función que permite agregar las banderas correspondientes para el uso del
	    programa ejecutado como script.
    '''
    parser = optparse.OptionParser()
    parser.add_option('-p','--ports', dest='ports', default='80', help='Puerto, lista de puertos rando de puertos o una combinacion de estas opciones.')
    parser.add_option('-s','--servers', dest='servers', default=None, help='Host, lista de hosts o segmento.')
    parser.add_option('-t','--time', dest='time', default=1, help='Retardo entre paquetes.')
    parser.add_option('-v','--verbose', action='store_true', dest='verbose', default=False, help='Modo verboso.')
    parser.add_option('-o','--report', dest='report', default='reporte.txt', help='Archivo en donde se escribira el reporte. De no esar, se mostrara en el archivo "reporte.txt".')
    parser.add_option('-c', '--configure', dest='configure', default=None, help='Archivo de configuracion')
    opts,args = parser.parse_args()
    return opts


def checaOpciones(opciones):
    '''
    	Función que valida que todas las opciones obligatorias se hayan agregado
    '''
    if opciones.ports is None:
        printError('Se debe especificar al menos un puerto, lista de puertos o un rango.', True)
    if opciones.servers is None:
        printError('Se debe especificar al menos un host, una lista de hosts o un segmento.', True)
	
		
def validahosts(hosts):
	'''
		Función para validar si es un solo host, una lista de host, un segmento de host o un rango de host
	'''
	segmento = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}'
	lista = r'(.+,.+)+'
	if re.match(segmento,hosts):
		lista_hosts=ipcalc.Network(hosts)
		return [str(x) for x in lista_hosts]
	elif re.match(lista,hosts):
		lista_hosts = hosts.replace(' ', ' ')
		return lista_hosts.split(',')
	else:
		return [hosts]


def validaPuertos(puertos):
	'''
		Función que devuelve una lista de puertos para cualquier entrada de tipo
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
		Función auxiliar que genera una lista de puertos a partir
		de un rango en forma de cadena de la forma '23-466'
	'''
	inicio=int(rango[:rango.find('-'):])
	fin=int(rango[rango.find('-')+1::])
	return [port for port in range(inicio,fin+1)]		
		
		
def escanea(hosts,puertos,retraso,v): 	
	'''
		Función que realiza el escaneo de la lista de hosts en los puertos indicados
		con un tiempo de retraso definido.
		hosts: Es una lista de hosts (puede contener solo 1 elemento)
		puertos: Es una lista de puertos (puede contener solo 1 elemento)
		retraso: El tiempo de retraso del envio de paquetes
		v: Identifica si se aplicara la funcion verbose
	'''
	# print hosts,puertos,retraso,v
	try:
		salida=''
		if v:
			print 'Se revisan los hosts...'
		for host in hosts:
			ip_host= gethostbyname(host)
			salida+= '\nHost:  %s \n' %(host) 
			for puerto in puertos:
				cliente = socket(AF_INET, SOCK_STREAM)
				resultado = cliente.connect_ex((ip_host, int(puerto)))
				# print host, puerto, resultado
				if (resultado == 0):
					salida+= 'puerto %d: Abierto\n' % int(puerto)
				else:
					salida+= 'puerto %d: Cerrado\n' % int(puerto)
				cliente.close()
				sleep(retraso)
		return salida
	except Exception as e:
		printError('Ocurrio un error inesperado')
		printError(e, True)
		
    
def generaReporte(opciones,salida):
	'''
		Función que se encarga de generar el reporte a partir de los resultados
	'''
	if opciones.verbose:
		print 'Se genera el reporte...'
	with open(opciones.report,"w") as file:
		file.write(str(datetime.now()) + '\n\n')
		banderas='Las banderas que se usaron: \n'
		if opciones.ports is not None:
			banderas+='\t -p  %s\n' % opciones.ports
		if opciones.servers is not None:
			banderas+='\t -s  %s\n' % opciones.servers
		if opciones.time is not None:
			banderas+='\t -t  %d\n' % opciones.time
		if opciones.verbose is not None:
			banderas+='\t -v  %s\n' % opciones.verbose
		if opciones.report is not None:
			banderas+='\t -o  %s\n' % opciones.report
		if opciones.configure is not None:
			banderas+='\t -c  %s\n' % opciones.configure
		file.write(banderas+'\n')
		file.write(salida)	
	

def leer_opciones_archivo(opciones):
	'''
		Función para extraer las opciones del archivo, el formato del archivo deberá 
		ser una bandera por renglón y los valores separados por un espacio
	'''
	try:
		with open(opciones.configure) as file:
			for line in file:
				lis = line.split()
				if lis[0] == '-p':
					opciones.ports = lis[1]
				if lis[0] == '-s':
					opciones.servers = lis[1]
				if lis[0] == '-o':
					opciones.report = lis[1]
				if lis[0] == '-t':
					opciones.time = int(lis[1])
				if lis[0] == '-v':
					opciones.verbose = True
		return opciones	
	except IOError as io:
		printError('Ocurrio un error inesperado')
		printError(io, True)



if __name__ == '__main__':

	opts = opciones()
	if opts.configure:
		opts = leer_opciones_archivo(opts)
	salida = escanea(validahosts(opts.servers),validaPuertos(opts.ports),opts.time,opts.verbose)
	generaReporte(opts, salida)
