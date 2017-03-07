#!/usr/bin/python3
# rhme2 - Insecure Filesystem - crypto
# Angel Suarez-B. Martin (n0w)

import serial
import argparse
import signal
import time
import binascii
import sys
import hashpumpy

hashes = {}
hashes['cat.txt'] =                       "96103df3b928d9edc5a103d690639c94628824f5"
hashes['joke.txt'] =                      "715b21027dca61235e2663e59a9bdfb387ca7997"
hashes['finances.csv'] =                  "0b939251f4c781f43efef804ee8faec0212f1144"
hashes['finances.csv:joke.txt'] =         "4b0972ec7282ad9e991414d1845ceee546eac7a1"
hashes['cat.txt:joke.txt'] =              "ba2e8af09b57080549180a32ac1ff1dde4d30b14"
hashes['cat.txt:finances.csv'] =          "933d86ae930c9a5d6d3a334297d9e72852f05c57"
hashes['cat.txt:finances.csv:joke.txt'] = "83f86c0ba1d2d5d60d055064256cd95a5ae6bb7d"

#echo -e "96103df3b928d9edc5a103d690639c94628824f5#cat.txt\r\n" >> /dev/ttyUSB0

def buildPayload(hash, payload):
    return (hash + '#').encode('utf-8') + payload + '\r\n'.encode('utf-8')

def waitForPrompt():
    requestReceived = False
    buf = ""

    while not requestReceived:
        bytesToRead = ser.inWaiting()

        if bytesToRead > 0:
            try:
                raw = ser.readline(bytesToRead)
                line = raw.decode('utf-8')
                buf = buf + line
                #print (raw)

                if line == expectedRequestString:
                    requestReceived = True
                    print (buf)
            except:
                print("EEE")


def signalHandler(signal, frame):
    print ("[+] Bye!")
    ser.close()
    sys.exit(0)

expectedRequestString =  ">> "
expectedRequestString_file = " Request?"

catRequest = "96103df3b928d9edc5a103d690639c94628824f5#cat.txt\r\n"

parser = argparse.ArgumentParser(description='Solves rhme2 secure filesystem challenge.')
parser.add_argument('port', help='rhme2 challenge board serial port')
args = parser.parse_args()

signal.signal(signal.SIGINT, signalHandler)

ser = serial.Serial()
ser.baudrate = 19200
ser.bytesize = serial.EIGHTBITS
ser.parity = serial.PARITY_NONE
ser.port = args.port

ser.open()
waitForPrompt()

testRequest = 'cat.txt'

for i in range (0, 20):
    hash, payload = (hashpumpy.hashpump(hashes[testRequest], testRequest, ':passwd', i))

    currentPayload = payload

    print ("-----------> i = %d" % i)
    print ("-----------> Sending: {}".format(currentPayload))

    time.sleep(0.2)

    ser.write(buildPayload(hash, payload))
    waitForPrompt()

ser.close()
sys.exit(0)

for i in range (0, 25):
    print (hashpumpy.hashpump(hashes['cat.txt'], 'cat.txt', ':joke.txt', i))

