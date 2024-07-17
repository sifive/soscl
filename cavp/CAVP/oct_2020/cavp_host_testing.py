#CAVP host tool
#this tool sends test vectors to a target over the UART
#this tool is for the real CAVP testing, not the pre-testing
#receives the computation results and stores them (no verification)

#program structure
# -1 reading the parameters: filename, serial port
# -2 setting the serial port up and creating result file 
# -3 waiting for the target readiness
# -4 opening the test vectors file
# -5 for each file line, parsing the fields
# -6                     sending the data to the target
# -7                     receiving the results and comparing them

version="1.0.1"
#1.0.0 working for all modes
#1.0.1 mct corrected for iv processing
#for serial port handling
import serial
#for time handling
import time
import os
#for argc argv handling
import sys
#for regular expression search
import re

def format_str( str ):
    msg = str.lstrip("b")
    msg = msg.strip("'")
    msg = msg.rstrip("\\n")
    return msg;

debug=0
verbose=0
nb_of_retries=0
# -1
nbargs=len(sys.argv)
print(nbargs)
if nbargs < 3 or nbargs > 3:
    print("ERROR: command format is: >cavp_host.py <serial-port> <vectors-file-name>\n")
    sys.exit(1)
serial_port=str(sys.argv[1])
input_filename=str(sys.argv[2])
output_filename=input_filename+".result"
print("CAVP vectors files tool ",version)
print("serial port is <",serial_port,">")
print("file name is <",input_filename,">")
print("result file name is <",output_filename,">")

# -2
ser = serial.Serial(serial_port, 115200) #Tried with and without the last 3 parameters, and also at 1Mbps, same happens.
ser.flushInput()
ser.flushOutput()
if ser.isOpen():
    ser.close()
ser.open()
ser.isOpen()
sleep_time=0.05
print("the serial port ",serial_port," is open and ready")
print("h:waiting for the target to be ready...")
# -3
msg=str("")
while(msg != "target-ready"):
    msg = format_str(str(ser.readline()))
    print("t:",msg)
print("h:the target is ready")
print("h:sending host-ready\n")
ser.write("Hello\n".encode())
time.sleep(sleep_time)
while(msg != "t-ack"):
    msg = format_str(str(ser.readline()))
    if verbose == 1:
        print("t: ",msg)
print("h:the target has acknowledged")

# -4
infile=open(input_filename,"rt")
outwfile = open(output_filename,"at+")
#the input file is made of lines, each line being a test vector
#each line is made of fields (name:<value>) separated by spaces
#the first field is the algorithm, the other fields depend on the algorithm
#e.g. if the algorithm is the AES, other fields are key, input, output, ...
#if the algorithm is SHA256, other fields are input and digest

st="CAVP test tool "+version+"\n"
outwfile.write(st)
outwfile.write(input_filename)
outwfile.write("\n")

#reading each line
line_nb=0
for vector_line in infile:
# -5
    #processing each line
    #    vector_line=str.lower(infile.readline())
    #count the number of lines in the file, i.e. the number of test vectors
    line_nb += 1
    # lower-case the line
    vector_line = str.lower(vector_line)
    #display the line
#    if verbose == 1:
#        print("line #",line_nb," is <",vector_line,">")
    #splitting the line into fields, separated with spaces
    vector = vector_line.split()
    #search for algorithm field; should be the first one, but not mandatory
    algolist = [i for i in vector if "algo" in i]
    algorithm = algolist[0].split(":")[1]
    if verbose == 1:
        print("algo =",end='')
    print(" ",algorithm,end='')
    #search for test number field; should be the second one, but not mandatory
    testlist = [i for i in vector if "test" in i]
    test = testlist[0].split(":")[1]
    if verbose == 1:
        print("test:",end='')
    print("#",test,end='')
    #grep if the test has already been processed and been OK
    outrfile = open(output_filename,"rt")
    testpattern="TEST VECTOR "+test+" OK"
    found=0
    for line in outrfile:
        if re.search(testpattern,line):
            found=1
            break
    #skip it
    if found == 1:
        continue
    #if the first character of the line is a #, skip it (consider the line as a comment)
    if vector_line[0]=='#':
        continue
    outrfile.close()
    if algorithm == "aes":
        time
        sleep_time=0.05
        types = [i for i in vector if "type" in i]
        type = types[0].split(":")[1]
        if verbose == 1:
            print("type is ",end='')
        print(" ",type,end='')
        modeofopl = [i for i in vector if "mode" in i]
        modeofoperation = modeofopl[0].split(":")[1]
        if verbose == 1:
            print("mode of operation is",end='')
        print(" ",modeofoperation,end='')

        keylenl = [i for i in vector if "keylen" in i]
        keylength = keylenl[0].split(":")[1]
        if verbose == 1:
            print("key length is",end='')
        print(" ",keylength,end='')
        keyl = [i for i in vector if "key:" in i]
        key = keyl[0].split(":")[1]
        if verbose == 1:
            print("key is",end='')
            print(" ",key,end='')

        ivlist = [i for i in vector if "iv:" in i]
        if len(ivlist) !=0:
            ivnotpresent = 0
            iv = ivlist[0].split(":")[1]
            if verbose == 1:
                print("iv is",end='')
                print(" ",iv,end='')
        else:
            ivnotpresent = 1
            
        ivlist = [i for i in vector if "ivlen" in i]
        if len(ivlist) !=0:
            ivlnotpresent = 0
            ivlength = ivlist[0].split(":")[1]
            if verbose == 1:
                print("ivlength is",end='')
                print(" ",ivlength,end='')
        else:
            ivlnotpresent = 1
        #getting the aadlen
        aadlist = [i for i in vector if "aadlen" in i]
        if len(aadlist) != 0:
            aadlnotpresent = 0
            aadlength = aadlist[0].split(":")[1]
            if verbose == 1:
                print("aadlength is",end='')
                print(" ",aadlength,end='')
            else:
                print("(",aadlength,")",end='')
        else:
            aadlnotpresent = 1
        #getting the aad
        aadlist = [i for i in vector if "aad:" in i]
        if len(aadlist) != 0:
            aadnotpresent = 0
            aad = aadlist[0].split(":")[1]
            if verbose == 1:
                print("aad is",end='')
                print(" ",aad,end='')
        else:
            aadnotpresent = 1

        #getting the taglen
        taglist = [i for i in vector if "taglen" in i]
        if len(taglist) != 0:
            taglnotpresent = 0
            taglength = taglist[0].split(":")[1]
            if verbose == 1:
                print("taglength is",end='')
                print(" ",taglength,end='')
        else:
            taglnotpresent = 1
        #getting the tag
        taglist = [i for i in vector if "tag:" in i]
        if len(taglist) != 0:
            tagnotpresent = 0
            tag = taglist[0].split(":")[1]
            if verbose == 1:
                print("tag is",end='')
                print(" ",tag,end='')
        else:
            tagnotpresent = 1
        #getting the inputlen
        inputllist = [i for i in vector if "inputlen" in i]
        if len(inputllist) != 0:
            inputlnotpresent = 0
            inputlength = inputllist[0].split(":")[1]
            if verbose == 1:
                print("inputlength is",end='')
                print(" ",inputlength,end='')
            else:
                print("(",inputlength,")",end='')
        else:
            inputlnotpresent = 1
        #getting the input
        inputl = [i for i in vector if "input:" in i]
        input = inputl[0].split(":")[1]
        if verbose == 1:
            print("input is")
            print(" ",input,end='')
        #no output

        opl = [i for i in vector if "operation" in i]
        operation = opl[0].split(":")[1]
        if verbose == 1:
            print("operation is")
        print(" ",operation)
        #tell the target data will be sent
        # -6
        #sequence is
        #algorithm
        #type of test
        #mode of operation
        #keylen
        #direction
        #key
        #ivlen (optional, even with iv)
        #iv (optional)
        #aadlen (optional)
        #aad (optional)
        #taglen (optional)
        #tag (optional, even with taglen)
        #inputlen
        #input
        if verbose == 1:
            print("h:sending host-ready\n")
        ser.write("loop\n".encode())
        time.sleep(sleep_time)
        while(msg != "t-start-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #algorithm, so aes
        ser.write(algorithm.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:algo")
        while(msg != "t-algo-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #type, so AFT, MCT or CTR
        ser.write(type.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:type")
        while(msg != "t-type-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #mode of operation: ECB, CBC, ...
        ser.write(modeofoperation.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:modop")
        while(msg != "t-modop-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #key length, in bits
        ser.write(keylength.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:kylen");
        while(msg != "t-kl-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #operation, encrypt or decrypt
        ser.write(operation.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:op")
        while(msg != "t-op-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #key value in hexadecimal
        keylen=int(int(keylength)/8)
        if verbose == 1:
            print(keylen)
        ser.write(key.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        while(msg != "t-key-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #sending the ivlen (optional)
        #ivlength, in bits
        if ivlnotpresent == 0:
            ivlen=int(ivlength)
            ivlens=f"{ivlen:04n}"
            ser.write(ivlens.encode())
            ser.write("\n".encode());
            time.sleep(sleep_time)
            if verbose == 1:
                print("h:ivlen");
            while(msg != "t-ivl-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)
            ivlen = ivlen / 8
        else:
            ivlen=16
        #sending the iv (optional)
        if ivnotpresent == 0:
            #iv value in hexadecimal
            ser.write(iv.encode())
            ser.write("\n".encode());
            while(msg != "t-iv-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)
        #sending the aadlen (optional)
        #aadlength, in bits ->aadlen in bytes
        if aadlnotpresent == 0:
            aadlen=int(aadlength)
            aadlens=f"{aadlen:05n}"
            ser.write(aadlens.encode())
            ser.write("\n".encode());
            time.sleep(sleep_time)
            if verbose == 1:
                print("h:aadlen");
            while(msg != "t-aadl-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)
            aadlen = int(aadlen / 8)
        #sending the aad (optional)
        if aadnotpresent == 0:
            #aad value in hexadecimal
            i=0
            increment=16*4
            while(i < aadlen):
                if (i + increment) > aadlen:
                    blocksize = aadlen % increment
                else:
                    blocksize = increment
                ser.write(aad[2*i:2*i+2*blocksize].encode())
                ser.write("\n".encode());
                time.sleep(sleep_time)
                i = i + increment
            while(msg != "t-aad-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)
        #sending the taglen (optional)
        #taglength, in bits
        if taglnotpresent == 0:
            taglen=int(taglength)
            taglens=f"{taglen:04n}"
            ser.write(taglens.encode())
            ser.write("\n".encode());
            time.sleep(sleep_time)
            if verbose == 1:
                print("h:taglen");
            while(msg != "t-tagl-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)
            taglen = int(taglen / 8)
        #sending the tag (optional)
        if operation != "encrypt" and tagnotpresent == 0:
            #tag value in hexadecimal
            ser.write(tag.encode())
            ser.write("\n".encode());
            while(msg != "t-tag-ack"):
                msg = format_str(str(ser.readline()))
                if verbose == 1:
                    print("t: ",msg)

        #sending the input length (in bytes)
        if inputlnotpresent == 0:
            inputlen=int(int(inputlength)/8)
        else:
            inputlen=len(input)/2
        inputlens=f"{inputlen:05n}"
        if verbose == 1:
            print(inputlens)
        ser.write(inputlens.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        while(msg != "t-il-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #sending input value in hexadecimal
        i=0
        increment=16*4
        while i < inputlen:
            if (i + increment) > inputlen:
                blocksize = int(inputlen % increment)
            else:
                blocksize = increment
            ser.write(input[2*i:2*(i+blocksize)].encode())
            ser.write("\n".encode());
            time.sleep(sleep_time)
            i = i + increment
        while(msg != "t-input-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        msg=str("")
        while("response" not in msg):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        if("response-end" in msg):
            received=msg[14:]
        else:
            received=msg[10:]

        while("response-end" not in msg):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
            if("response-end" in msg):
                received=received+msg[14:]
            else:
                received=received+msg[10:]
                
        # -7
        received = str.upper(received)
        st = "{"
        outwfile.write(st+"\n")
        st = '"tcId"' + ": " + test + ","
        outwfile.write(st+"\n")
        if type == "aft" or type == "ctr":
            if modeofoperation == "gcm":
                if operation == "encrypt":
                    cta = received[:inputlen*2]
                    taga = received[inputlen*2:]
                    st = '"ct": "' + cta + '"'
                    outwfile.write(st+"\n")
                    st = '"tag": "' + taga + '"'
                    outwfile.write(st+"\n")
                if operation == "decrypt":
#                    print("received:",received)
                    pta = received[:inputlen*2]
                    taga = received[inputlen*2:]
#                    print("taga=",taga)
                    if taga == "FALSE":
                        st = '"testPassed": false'
                        outwfile.write(st+"\n")
                    else:
                        st = '"pt": "' + pta + '"'
                        outwfile.write(st+"\n")
            else:
                if modeofoperation == "ccm":
                    if operation == "encrypt":
#                        cta = received[:inputlen*2]
#                        taga = received[inputlen*2:]
                        st = '"ct": "' + received + '"'
                        outwfile.write(st+"\n")
#                        st = '"tag": "' + taga + '"'
#                        outwfile.write(st+"\n")
                    if operation == "decrypt":
#                        print("received:",received)
                        pta = received[:inputlen*2]
                        taga = received[inputlen*2:]
#                        print("taga=",taga)
                        if taga == "FALSE":
                            st = '"testPassed": false'
                            outwfile.write(st+"\n")
                            st = '"pt": "' + pta + '"'
                            outwfile.write(st+"\n")
                        else:
                            st = '"pt": "' + pta + '"'
                            outwfile.write(st+"\n")
                else:
                    if operation == "encrypt":
                        st = '"ct": "' + received + '"'
                    if operation == "decrypt":
                        st = '"pt": "' + received + '"'
                    outwfile.write(st+"\n")
            st = "},"
            outwfile.write(st+"\n")
        if type == "mct":
            st = '"' + "resultsArray" + '"' + ": ["
            outwfile.write(st+"\n")
            md_total_len = len(received)
            md_len = int(md_total_len / 100)
            print("total len=",md_total_len," len=",md_len," keylen=",keylen)
            i = 0
            while i < 100:
                st = "{"
                outwfile.write(st+"\n")
                payload = received[i*md_len:(i+1)*md_len]
                if operation == "encrypt":
                    keylen=int(keylen)
                    keya=payload[0:keylen*2]
                    st='"key": '+'"'+keya+'",'
                    outwfile.write(st+"\n")
                    #if iv to be displayed
                    if modeofoperation != "ecb":
                        iva=payload[keylen*2:keylen*2+32]
                        st='"iv": '+'"'+iva+'",'
                        outwfile.write(st+"\n")
                        pta=payload[keylen*2+32:keylen*2+64]
                        st='"pt": '+'"'+pta+'",'
                        outwfile.write(st+"\n")
                        cta=payload[keylen*2+64:]
                        st='"ct": '+'"'+cta+'" '
                        outwfile.write(st+"\n")
                    else:
                        pta=payload[keylen*2:keylen*2+32]
                        st='"pt": '+'"'+pta+'",'
                        outwfile.write(st+"\n")
                        cta=payload[keylen*2+32:]
                        st='"ct": '+'"'+cta+'" '
                        outwfile.write(st+"\n")
                if operation == "decrypt":
                    keya=payload[0:keylen*2]
                    st='"key": '+'"'+keya+'",'
                    outwfile.write(st+"\n")
                    #if iv to be displayed
                    if modeofoperation != "ecb":
                        iva=payload[keylen*2:keylen*2+32]
                        st='"iv": '+'"'+iva+'",'
                        outwfile.write(st+"\n")
                        pta=payload[keylen*2+64:]
                        st='"pt": '+'"'+pta+'",'
                        outwfile.write(st+"\n")
                        cta=payload[keylen*2+32:keylen*2+64]
                        st='"ct": '+'"'+cta+'" '
                        outwfile.write(st+"\n")
                    else:
                        pta=payload[keylen*2+32:]
                        st='"pt": '+'"'+pta+'",'
                        outwfile.write(st+"\n")
                        cta=payload[keylen*2:keylen*2+32]
                        st='"ct": '+'"'+cta+'" '
                        outwfile.write(st+"\n")
                st = "},"
                outwfile.write(st+"\n")
                i = i +1
            st = "]"
            outwfile.write(st+"\n")
        st = "\n"
        outwfile.write(st)
#            quit()
    if algorithm == "sha":
#        print("algo is ",algorithm)
        #mode: 256, 384 or 512
        modeofopl = [i for i in vector if "mode" in i]
        modeofoperation = modeofopl[0].split(":")[1]
        if verbose == 1:
            print("mode of operation is",end='')
        print(" ",modeofoperation,end='')
        types = [i for i in vector if "type" in i]
        type = types[0].split(":")[1]
        if verbose == 1:
            print("type is ",end='')
        print(" ",type,end='')
        inputlenl = [i for i in vector if "length" in i]
        inputlength = inputlenl[0].split(":")[1]
        if verbose == 1:
            print("input length is",end='')
        print(" ",inputlength,end='')
        inputl = [i for i in vector if "input" in i]
        input = inputl[0].split(":")[1]
        if len(input) > 128:
            print(" input is ",end='')
            for i in range(0,16):
                print(input[i],end='')
            print("...")
        else:
            print(" input is ",input)
        #sending sequence
        #algo
        #type
        #mode
        #input len
        #input
        if verbose == 1:
            print("h:sending host-ready\n")
        ser.write("loop\n".encode())
        time.sleep(sleep_time)
        while(msg != "t-start-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #algorithm, so sha
        ser.write(algorithm.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:algo")
        while(msg != "t-algo-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #type, so AFT, MCT
        ser.write(type.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:type")
        while(msg != "t-type-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #mode: 256, 384 or 512
        ser.write(modeofoperation.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:modop")
        while(msg != "t-modop-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #input length, in bits
        inputlen=int(inputlength)
        inputlens=f"{inputlen:08n}"
        ser.write(inputlens.encode())
        ser.write("\n".encode());
        time.sleep(sleep_time)
        if verbose == 1:
            print("h:ilen");
        while(msg != "t-il-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        #input
        inputlen=int(inputlength)/8
        if verbose == 1:
            print(inputlen)
        #sending input value in hexadecimal
        i=0
        increment=64
        while i < inputlen:
            if (i + increment) > inputlen:
                blocksize = int(inputlen % increment)
            else:
                blocksize = increment
            ser.write(input[2*i:2*(i+blocksize)].encode())
            ser.write("\n".encode());
            time.sleep(sleep_time)
            i = i + increment
#       i=0
#       while i < inputlen:
#           ser.write(input[2*i].encode())
#           time.sleep(sleep_time)
#           ser.write(input[2*i+1].encode())
#           time.sleep(sleep_time)
#           ser.write("\n".encode());
#           time.sleep(sleep_time)
#           i = i +1
        while(msg != "t-input-ack"):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        if verbose == 1:
            print("input-ack acknowledged\n")
        msg=str("")
        while("response" not in msg):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
        if("response-end" in msg):
            received=msg[14:]
        else:
            received=msg[10:]
        while("response-end" not in msg):
            msg = format_str(str(ser.readline()))
            if verbose == 1:
                print("t: ",msg)
            if("response-end" in msg):
                received=received+msg[14:]
            else:
                received=received+msg[10:]
        if verbose == 1:
            print("response-end acknowledged\n")
        # -7        
        #st="test #"+test+" "+received+"\n"
        received = str.upper(received)
        st = "{"
        outwfile.write(st+"\n")
        st = '"tcId"' + ": " + test + ","
        outwfile.write(st+"\n")
        if type == "aft":
            st = '"md"' + ": " + '"' + received + '"'
            outwfile.write(st+"\n")
            st = "},"
            outwfile.write(st+"\n")
        if type == "mct":
            st = '"' + "resultsArray" + '"' + ": ["
            outwfile.write(st+"\n")
            md_total_len = len(received)
            md_len = int(md_total_len / 100)
            print("total len=",md_total_len,"len=",md_len)
            i = 0
            while i < 100:
                st = "{"
                outwfile.write(st+"\n")
                st = '"' + "md" + '"' + ": " + '"' + received[i*md_len:(i+1)*md_len] + '"'
                outwfile.write(st+"\n")
                st = "},"
                outwfile.write(st+"\n")
                i = i +1
            st = "]"
            outwfile.write(st+"\n")
        st = "\n"
        outwfile.write(st)

#no more lines to send, the notification is sent to the target
ser.write("-end\n".encode());
#while(msg != "t-end-ack"):
#    msg = format_str(str(ser.readline()))
#    if verbose == 1:
#        print("t: ",msg)
infile.close()
outwfile.close()
sys.exit("quit\n");

