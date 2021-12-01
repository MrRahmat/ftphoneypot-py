import argparse
import copy
import math
import os
import random
import re
import socket
import socketserver
import string
import sys
import time

import ftp_db

# class to handle incoming connections

class FTPHandler ( socketserver.BaseRequestHandler ) :
    def handle ( self ) :
        client_ip = self.client_address[ 0 ]
        
        #  If user supplied an argument for the FTP banner to be used, use this banner. If not, pick a random banner
        if args[ 'banner' ] and ftp_db.banners[ args[ 'banner' ] ] :
            ftp_info = ftp_db.banners[ args [ 'banner' ] ]
            ftp_banner = ftp_info [ 'banner' ]
            ftp_name = args[ 'banner' ]
        else :
            ftp_name, ftp_info = random.choice( ftp_db.banners.items() )
            ftp_banner = ftp_info[ 'banner' ]

        # If the dir for this banner does not exist, create it.
        if not os.path.isdir( args[ 'flows_dir' ] + ftp_name ) :
            os.mkdir( args [ 'flows_dir' ] + ftp_name )

        # Set up basic stuff, create flow dir
        path = "/"
        flow_nr = 0
        flow_dir = args [ 'flows_dir' ] + ftp_name + "/" + client_ip + "_" + str(time.time())
        os.mkdir( flow_dir )
        
        # Send back initial  banner to the client
        #print 'Connection from ' + client_ip + ' ,serving banner for ' + ftp_name
        logfile.write( 'Connection from ' + client_ip + ' ,serving banner for ' + ftp_name + '\n' )
        logfile.flush()
        self.send_response( flow_dir, flow_nr, ftp_banner + '\r \n' )
        flow_nr += 1

        while 1:
            found_exploit = ''
            found_signature = ''

            # Try to grab all the data from the client in one go, so the data does not get split over multiple flows.
            #if there is no data, client aborted the connection
            self.data = self.request.recv( 9218 ).strip()
            if not self.data:
                break

            # Due to non-pritable characters in exploit traffic, all signatures are saved using hex encoding. Client requests are also present in hex to match the signatures
            for name, signature in ftp_info[ 'signatures' ].items():
                if self.data.encode( 'hex' ).find( signature ) != -1:
                    if not found_exploit or len( signature ) > len( ftp_info[ 'signatures' ][ found_exploit ]):
                        found_exploit = name
                        found_signature = signature
                    if found_exploit and found_signature:
                        logfile.write('Found exploit ' + found_exploit + ' : ' + found_signature + '\n')
                        logfile.flush()

            # All data should only contain 7-bit ASCII data. If this is not the case, most likely exploit traffic => mark as suspicious.
            if all( ord( c ) < 127 and c in string.printable for c in self.data ):
                flow = open( flow_dir + '/req_' + str( flow_nr ) + '.flow', 'w')
            else:
                flow = open (flow_dir + '/req_' + str(flow_nr ) + 'flow_suspicious', 'w')
            flow.write( self.data )
            flow.close()

            # extract the FTP command issued by the client, and tru to give it the response it expects
            cmd = self.data.split( ' ' )[ 0 ].upper()
            if re.match( 'USER', cmd ):
                user = self.data.split( ' ' )[ -1]
                self.send_response( flow_dir, flow_nr, '331 Password required for ' + user + '\r \n' )
            elif re.match( 'PASS', cmd ):
                self.send_response( flow_dir, flow_nr, '230 User ' + user + ' logged in \r \n' )
            elif re.match( 'HELP', cmd ):
                self.send_response( flow_dir, flow_nr, '214 Help. \r \n' )
            elif re.match( 'QUIT', cmd ):
                self.send_response( flow_dir, flow_nr, '221 Goodbye \r \n' )
                self.request.close()
                return
            elif re.match( 'SYSTEM', cmd ):
                self.send_response( flow_dir, flow_nr, '215 UNIX type: L* \r \n')
            elif re.match( 'X?MKD', cmd ):
                self.send_response( flow_dir, flow_nr, '257' + self.data.split( ' ' )[ 1 ] + ' directory created. \r \n')
            elif re.match( 'PWD', cmd ):
                self.send_response( flow_dir, flow_nr, '257 \'' + path + '\' is the current directory. \r \n')
            elif re.match( "CWD", cmd ):
                # Allow the client to change dirs, but no escaping the non-existing root dir 
                cwd_dir = self.data.split( ' ' )[ 1 ]
                if cwd_dir == '..':
                    if path == '/':
                        path = '/'
                    else:
                        ( path, tail ) = os.path.split( path )
                else:
                    path = os.path.join( path, cwd_dir )
                    self.send_response( flow_dir, flow_nr, '250 CWD command successful \r \n' )
            elif re.match( 'SITE EXEC', self.data.upper() ):
                # Emulate a SITE EXEC command, simply print back everything after SITE EXEC with a 200 status code.
                exec_cmd = " ".join( self.data.split(" ")[ 2: ] )
                self.send_response( flow_dir, flow_nr, '200 ' + exec_cmd + '\r \n' )
            elif re.match( 'DELE', cmd ):
                self.send_response( flow_dir, flow_nr, '250 File deleted. \r \n' )
            elif re.match( 'RMD', cmd ):
                self.send_response( flow_dir, flow_nr, '250 Directory deleted. \r \n' )
            elif re.match( 'TYPE', cmd ):
                self.send_response( flow_dir, flow_nr, '200 type set to ' + self.data.split( " " )[ 1 ].upper() + '\r \n' )
            else:
                self.send_response( flow_dir, flow_nr, '502 Command not implemented \r \n' )
            flow_nr += 1

    def send_response( self, flow_dir, flow_nr, msg ):
        flow = open( flow_dir + '/resp_' + str( flow_nr ) + '.flow', 'w' )
        flow.write( msg )
        flow.close()
        self.request.sendall( msg )

def parseArgs( argv ):
    parser = argparse.ArgumentParser( description = 'FTP Honeypot.' )
    parser.add_argument( '--logfile', default = 'honeypot.log', help = 'Log file to write messages to.' )
    parser.add_argument( '--port', default = '21', help = 'TCP port number to bind to.' )
    parser.add_argument( '--flows_dir', default = 'flows/', help = 'Directory in which to save flows.' )
    parser.add_argument( '--banner', default = ' ', help = 'FTP banner to server to clients If left empty, random banner will be served.' )
    parser.add_argument( '--list-banner', action = 'store_true', help = 'List all banners to use with the --banner.' )
    args = parser.parse_args( argv )
    return [ vars( args ), parser ]

def printBanners():
    print 'Banner Description'
    print '========================================================'
    for banner, banner_info in sorted( ftp_db.banners.items() ):
        print '{:<25}{}'.format( banner, banner_info[ 'name' ])
    print ''
    print 'Use value listed in the "Banner"'

if __name__ == '__main__':
    global parser, args, logfile
    args, parser = parseArgs( sys.argv[ 1: ] )
    if args[ 'list_banner' ] :
        printBanners()
        sys.exit( 0 )
    if args[ 'banner' ] and not args[ 'banner' ] in ftp_db.banners.keys():
        print 'Error: this banner does not exist.'
        print 'Specify a correct banner or use the --list-banner argument. '
        sys.exit( -1 )
    logfile = open( args[ 'logfile' ], 'w' )

    #Create the server, binding to all interfaces on port specified by args
    try:
        server = socketserver.TCPServer(( "", int(args[ 'port' ])), FTPHandler)
    except socket.error as msg:
        print 'Error: could not start the server ( ' + msg.strerror + ' ).'
        sys.exit( -1 )
    server.serve_forever()
